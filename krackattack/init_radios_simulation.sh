#!/bin/bash

# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

set -e

MACAP=02:00:00:00:00:00
MACCLIENT=02:00:00:00:01:00

function setibss {
	macchanger $1 -m $2
	iw $1 set type ibss
	ifconfig $1 up
	iw $1 ibss join $3 $4
}

# Create the virtual interfaces
rmmod mac80211_hwsim 2> /dev/null || true
modprobe mac80211_hwsim radios=5
rfkill unblock wifi
sleep 1

# Real AP is on channel 1
iw wlan2 set type monitor
ifconfig wlan2 up
iw wlan2 set channel 1

# Rogue AP is on channel 6
macchanger -m $MACAP wlan3
iw wlan3 interface add wlan3mon type monitor
sleep 1
iw wlan3mon set type monitor
ifconfig wlan3mon up
iw wlan3mon set channel 6
# sometimes hwsim doesn't immediately want to change channels..
ifconfig wlan3mon down
ifconfig wlan3mon up

# Extra interface so all frames sent by the real AP will get ACK'ed by mac80211_hwsim.
setibss wlan4 $MACCLIENT acknet1 2412	# Simulate wlan3 (client) on AP channel

