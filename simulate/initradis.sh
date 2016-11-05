#!/bin/bash
set -e

# Create the virtual interfaces
rmmod mac80211_hwsim 2> /dev/null || true
modprobe mac80211_hwsim radios=2
rfkill unblock wifi
