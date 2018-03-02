#!/usr/bin/python3

# Copyright 2015-2017 Zack Scholl. All rights reserved.
# Use of this source code is governed by a AGPL
# license that can be found in the LICENSE file.
import sys
import json
import socket
import time
import subprocess
import os
import glob
import argparse
import logging
import statistics
import atexit
import json
import bluetooth
from bluetooth.ble import DiscoveryService
#from bt_proximity import BluetoothRSSI
import datetime
import threading
logger = logging.getLogger('scan.py')
import requests

from bluepy.btle import Scanner, DefaultDelegate
import bluetooth._bluetooth as bt
import struct
import array
import fcntl

class BluetoothRSSI(object):
    """Object class for getting the RSSI value of a Bluetooth address.
    Reference: https://github.com/dagar/bluetooth-proximity
    """
    def __init__(self, addr):
        self.addr = addr
        self.hci_sock = bt.hci_open_dev(0)
        self.hci_fd = self.hci_sock.fileno()
        self.bt_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        self.bt_sock.settimeout(10)
        self.connected = False
        self.cmd_pkt = None

    def prep_cmd_pkt(self):
        """Prepares the command packet for requesting RSSI"""
        str2ba = bt.str2ba(self.addr)
        third =bytes("\0" * 17, 'utf-8')
        reqstr = struct.pack("6sB17s", str2ba, bt.ACL_LINK, third)        
        request = array.array("h", reqstr)        
        handle = fcntl.ioctl(self.hci_fd, bt.HCIGETCONNINFO, request, 1)
        handle = struct.unpack("8xH14x", request.tostring())[0]
        self.cmd_pkt = struct.pack('H', handle)
        
    def connect(self):
        """Connects to the Bluetooth address"""
        self.bt_sock.connect_ex((self.addr, 1))  # PSM 1 - Service Discovery
        self.connected = True

    def get_rssi(self):
        """Gets the current RSSI value.
        @return: The RSSI value (float) or None if the device connection fails
                 (i.e. the device is nowhere nearby).
        """
        try:
            # Only do connection if not already connected
            if not self.connected:
                self.connect()
            if self.cmd_pkt is None:
                self.prep_cmd_pkt()
            # Send command to request RSSI
            rssi = bt.hci_send_req(
                self.hci_sock, bt.OGF_STATUS_PARAM,
                bt.OCF_READ_RSSI, bt.EVT_CMD_COMPLETE, 4, self.cmd_pkt)
            
            retVal = None
            if rssi[3] > 0 and rssi[3] <= 256:
                retVal = -(256 - rssi[3])
            if rssi[3] == 0:
                retVal = rssi[3]
                
            print("rssi %d retval " % rssi[3],retVal)
            return retVal
        except IOError:
            # Happens if connection fails (e.g. device is not in range)
            self.connected = False
            return None

def restart_wifi(server):
    os.system("/sbin/ifdown --force wlan0")
    os.system("/sbin/ifup --force wlan0")
    os.system("iwconfig wlan0 mode managed")
    while True:
        ping_response = subprocess.Popen(
            ["/bin/ping", "-c1", "-w100", server], stdout=subprocess.PIPE).stdout.read()
        if '64 bytes' in ping_response.decode('utf-8'):
            break
        time.sleep(1)


def num_wifi_cards():
    cmd = 'iwconfig'
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    output = p.stdout.read().decode('utf-8')
    return output.count("wlan")


def process_scan(time_window):
    logger.debug("Reading files...")
    output = ""
    maxFileNumber = -1
    fileNameToRead = ""
    for filename in glob.glob("/tmp/tshark-temp*"):
        fileNumber = int(filename.split("_")[1])
        if fileNumber > maxFileNumber:
            maxFileNumber = fileNumber
            fileNameToRead = filename

    logger.debug("Reading from %s" % fileNameToRead)
    cmd = subprocess.Popen(("tshark -r "+fileNameToRead+" -T fields -e frame.time_epoch -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal").split(
    ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output += cmd.stdout.read().decode('utf-8')

    timestamp_threshold = float(time.time()) - float(time_window)
    fingerprints = {}
    relevant_lines = 0
    for line in output.splitlines():
        try:
            timestamp, mac, mac2, power_levels = line.split("\t")

            if mac == mac2 or float(timestamp) < timestamp_threshold or len(mac) == 0:
                continue
            
            relevant_lines+=1
            rssi = power_levels.split(',')[0]
            if len(rssi) == 0:
                continue

            if mac not in fingerprints:
                fingerprints[mac] = []
            fingerprints[mac].append(float(rssi))
        except:
            pass
    logger.debug("..done")

    # Compute medians
    fingerprints2 = []
    for mac in fingerprints:
        if len(fingerprints[mac]) == 0:
            continue
        fingerprints2.append(
            {"mac": mac, "rssi": int(statistics.median(fingerprints[mac]))})

    logger.debug("Processed %d lines, found %d fingerprints in %d relevant lines" %
                 (len(output.splitlines()), len(fingerprints2),relevant_lines))

    payload = {
        "node": socket.gethostname(),
        "signals": fingerprints2,
        "timestamp": int(
            time.time())}
    logger.debug(payload)
    return payload


def run_command(command):
    p = subprocess.Popen(
        command.split(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')


def tshark_is_running():
    ps_output = subprocess.Popen(
        "ps aux".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ps_stdout = ps_output.stdout.read().decode('utf-8')
    isRunning = 'tshark' in ps_stdout and '[tshark]' not in ps_stdout
    logger.debug("tshark is running: " + str(isRunning))
    return isRunning


def start_scan(wlan):
    if not tshark_is_running():
        # Remove previous files
        for filename in glob.glob("/tmp/tshark-temp*"):
            os.remove(filename)
        subprocess.Popen(("/usr/bin/tshark -I -i " + wlan + " -b files:4 -b filesize:1000 -w /tmp/tshark-temp").split(),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if tshark_is_running():
            logger.info("Starting scan")


def stop_scan():
    if tshark_is_running():
        os.system("pkill -9 tshark")
        if not tshark_is_running():
            logger.info("Stopped scan")
            
def start_bscan():
    logger.debug("Starting bluetooth scan")
    count = 0
    while count < 2:
        print(count)   
        nearby_devices = []
        try:
            nearby_devices = bluetooth.discover_devices(lookup_names=True)
        except Exception:
            logger.error("Fatal error in bluetooth_listen", exc_info=True)
        logger.debug("found %d bluetooth devices" % len(nearby_devices))
        
        nearby_le_devices = []
        try:
            scanner = Scanner()
            nearby_le_devices = scanner.scan()
        except Exception:
            logger.error("Fatal error in bluetooth_listen", exc_info=True)                        
        logger.debug("found %d bluetooth le devices" % len(nearby_le_devices))
        
        with open('bluetooth.json', '+r') as f:
            data = json.load(f)
            for device in nearby_devices:
                mac = device[0].lower()
                if mac not in data:
                      data[mac] = {"type":"bt","rssi":[]} 
                data[mac]["name"] = device[1]            
                
            for mac in data:
                if data[mac]["type"] == "bt":
                    try:
                        b = BluetoothRSSI(mac)
                        rssi = b.get_rssi()
                        if rssi is not None:
                            data[mac]["rssi"].append(rssi)
                    except Exception:
                        logger.error("Fatal error in bluetooth_listen", exc_info=True)
                            
            for device in nearby_le_devices:
                try:
                    rssi = device.rssi
                    mac = device.addr.lower()
                    if mac not in data:
                          data[mac] = {"type":"btle","rssi":[]}
                    data[mac]["addrType"] = device.addrType
                    data[mac]["getScanData"] =device.getScanData()
                    if rssi is not None:
                        data[mac]["rssi"].append(float(rssi))    
                except Exception:
                        logger.error("Fatal error in bluetooth_listen", exc_info=True)
            
            
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate() 
            
         
        count += 1
  
    

    
def stop_bscan():
    logger.debug("Stopping bluetooth scan")
    
def process_bscan(time_window):
    logger.debug("Processing bluetooth scan")
    
    timestamp_threshold = float(time.time()) - float(time_window)
    fingerprints = []
    relevant_lines = 0
    # Compute medians
    with open('bluetooth.json', '+r') as f:
        data = json.load(f)
        for mac in data:
            dataObj = data[mac]
            if len(dataObj["rssi"]) == 0:
                continue
            relevant_lines += 1
                        
            fingerprints.append(
            {"mac": mac, "rssi": int(statistics.median(dataObj["rssi"]))})
            
            data[mac]["rssi"] = []
            
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate() 

    logger.debug("found %d bluetooth fingerprints in %d relevant lines" %
                 ( len(fingerprints),relevant_lines))

    payload = {
        "node": socket.gethostname() +"-bt",
        "signals": fingerprints,
        "timestamp": int(
            time.time())}
    logger.debug(payload)
    return payload
    
def bluetooth_listen(sleep, group, server):
    # empty list of bluetooth rssi
    with open('bluetooth.json', '+r') as f:
        data = json.load(f)
        for mac in data:
            dataObj = data[mac]
            if len(dataObj["rssi"]) == 0:
                continue
            data[mac]["rssi"] = []            
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate() 
        
    while True:
      try:
            start_bscan()
      except Exception:
            logger.error("Fatal error in bluetooth_listen", exc_info=True)
      
      btpayload = process_bscan(sleep)
      btpayload['group'] = group
      if len(btpayload['signals']) > 0:
        r = requests.post(
          server + "/reversefingerprint",
          json=btpayload)
        logger.debug("Sent to server with status code: " + str(r.status_code))
      #time.sleep(sleep)

def main():
    # Check if SUDO
    # http://serverfault.com/questions/16767/check-admin-rights-inside-python-script
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    # Check which interface
    # Test if wlan0 / wlan1
    default_wlan = "wlan1"
    default_single_wifi = False
    if num_wifi_cards() == 1:
        default_single_wifi = True
        default_wlan = "wlan0"

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--group", default="", help="group name")
    parser.add_argument(
        "-i",
        "--interface",
        default=default_wlan,
        help="Interface to listen on - default %s" % default_wlan)
    parser.add_argument(
        "-t",
        "--time",
        default=10,
        help="scanning time in seconds (default 10)")
    parser.add_argument(
        "--single-wifi",
        default=default_single_wifi,
        action="store_true",
        help="Engage single-wifi card mode?")
    parser.add_argument(
        "-s",
        "--server",
        default="https://lf.internalpositioning.com",
        help="send payload to this server")
    parser.add_argument("-n", "--nodebug", action="store_true")
    parser.add_argument(
        "-b",
        "--bluetooth",
        default=False,
        help="Enables bluetooth scanning")
    args = parser.parse_args()

    # Check arguments for group
    if args.group == "":
        print("Must specify group with -g")
        sys.exit(-1)

    # Check arguments for logging
    loggingLevel = logging.DEBUG
    if args.nodebug:
        loggingLevel = logging.ERROR
    logger.setLevel(loggingLevel)
    fh = logging.FileHandler('scan.log')
    fh.setLevel(loggingLevel)
    ch = logging.StreamHandler()
    ch.setLevel(loggingLevel)
    formatter = logging.Formatter(
        '%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    # Startup scanning
    print("Using server " + args.server)
    logger.debug("Using server " + args.server)
    print("Using group " + args.group)
    logger.debug("Using group " + args.group)
    
    if args.bluetooth:
      thread = threading.Thread(
        target=bluetooth_listen, 
        args=(), 
        kwargs={
          'sleep': args.time,
          'group': args.group,
          'server': args.server
        }
      )
      # Daemonize
      thread.daemon = True
      # Start the thread
      thread.start()

    while True:
        try:
            if args.single_wifi:
                logger.debug("Stopping scan...")
                stop_scan()
                logger.debug("Stopping monitor mode...")
                restart_wifi(args.server)
                logger.debug("Restarting WiFi in managed mode...")
                        
            start_scan(args.interface)
            payload = process_scan(args.time)
            payload['group'] = args.group
            if len(payload['signals']) > 0:
                r = requests.post(
                    args.server +
                    "/reversefingerprint",
                    json=payload)
                logger.debug(
                    "Sent to server with status code: " + str(r.status_code))
            time.sleep(float(args.time))  # Wait before getting next window
        except Exception:
            logger.error("Fatal error in main loop", exc_info=True)
            time.sleep(float(args.time))


def exit_handler():
    print("Exiting...stopping scan..")
    os.system("pkill -9 tshark")

if __name__ == "__main__":
    atexit.register(exit_handler)
    main()
