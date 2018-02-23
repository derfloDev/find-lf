#!/bin/bash

# Update
apt-get update
apt-get install -y htop vim python3 python3-requests bluetooth python-bluez git 
apt-get install pkg-config libboost-python-dev libboost-thread-dev libbluetooth-dev libglib2.0-dev python-dev mercurial 

# Install wireshark and other basics using all defaults
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" --force-yes -fuy install wireless-tools firmware-atheros usbutils wireshark tshark hostapd

hg clone https://bitbucket.org/OscarAcena/pygattlib
cd pygattlib
sudo python setup.py install

# Copy latest scan.py from the repo
wget https://raw.githubusercontent.com/derfloDev/find-lf/master/node/scan.py -O scan.py
sudo chown pi scan.py
sudo chgrp pi scan.py

git clone https://github.com/derfloDev/bluetooth-proximity.git
cd bluetooth-proximity
sudo python3 setup.py install

git clone https://github.com/derfloDev/pybluez.git
cd pybluez
sudo python3 setup.py install

# Generate SSH key
ssh-keygen -b 2048 -t rsa -f /home/pi/.ssh/id_rsa -q -N ""
