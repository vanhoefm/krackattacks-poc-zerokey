#!/bin/bash
set -e

cd wpa_supplicant
cp -n defconfig .config
make clean
make -j 6
cd ..

cd hostapd
cp -n defconfig .config
make clean
make -j 6
cd ..

