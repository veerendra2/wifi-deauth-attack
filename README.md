# Automated script for Wifi Deauthentication Attack
### Intro
Written in Python, sends `deauth` packets to a wifi network which results network outage for connected devices. Uses `scapy` module to send `deauth` packets and sniffs wifi.
Know more about [Deauthentication Attack](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack)

### Required Tools
1. aircrack-ng (`apt-get install aircrack-ng`). I highly recommend to install latest version, from [source](https://www.aircrack-ng.org/downloads.html) to support more network drivers/cards. 
2. scapy (Python Module:`apt-get install python-scapy`)

### How to run?
We can run in 2 ways:
* `sudo python deauth.py` 
 
   It will automatically creates `mon0` with `airmon-ng start wlan0`(it wont create, if already exists) and sniffs the wifi  singal on that interface. After few seconds, it will displays the `SSID` and its `MAC` to choose.
* `sudo python deauth.py -m XX:YY:AA:XX:YY:AA` 
   
   MAC address as command line argument. In this case, there is no need to sniff wifi.

### What's new in version 3.0
* New command line
* Daemonize the attack i.e performs attack in background
* Compatable to new `airmon-ng` version

### Usage
```
root@ghost:/opt/scripts# python deauth.py -h
usage: deauth.py [-h] [-d] [-c COUNT] [-m MAC] [-v]

Sends deauthentication packets to a wifi network which results network outage
for connected devices. [Coded by VEERENDRA KAKUMANU]

optional arguments:
  -h, --help  show this help message and exit
  -d          Run as daemon
  -c COUNT    Stops the monitoring after this count reachs.By default it is
              2000
  -m MAC      Sends deauth packets to this network
  -v          show program's version number and exit
```

### FAQ
* ##### What is the option `-c` "COUNT"?
  
  It is a threshold value to stop the "monitoring". The access point or wifi hotspot trasmits [beacon frames](https://en.wikipedia.org/wiki/Beacon_frame) periodically to announce it's presence. The beacon frame contains all the information about the network. Now, the script looks for these beacons and makes count. If the count reachs the limit, it will stops the monitoring.
  * If you think, the monoring is taking to much time? then specify the count with less number(Default is 2000), but it may not get all wifi hotspots near to you. Because you are listening only few beacons

* ##### What is the option `-d` "Run as daemon"?
  
  Script runs in background while attacking. (Kill it by running `pkill -9 -f deauth.py`)

### Known Issues
* For some reasons, sometimes the script is not able to find all near wifi hotspots. 
* If you try to attack on a wifi hotspot which is by "Android" device, it won't work.(May be it has `802.11w`)

### Run it!
`wget -qO deauth.py https://goo.gl/bnsV9C && sudo python deauth.py`

#### How to avoid Deauthentication attack?
Use `802.11w` suppored routers. Know more about [802.11w](https://en.wikipedia.org/wiki/IEEE_802.11w-2009) and [read cisco document](http://www.cisco.com/c/en/us/td/docs/wireless/controller/technotes/5700/software/release/ios_xe_33/11rkw_DeploymentGuide/b_802point11rkw_deployment_guide_cisco_ios_xe_release33/b_802point11rkw_deployment_guide_cisco_ios_xe_release33_chapter_0100.pdf)

#### NOTE: 
Inorder to work deauthentication attack successful, you should near to the target network. The `deauth` packets should reach the connected devices of the target network(s)

#### Difficult to setup environment for this?? check out my other [repo](https://github.com/veerendra2/hacker-tools): docker image `veerendrav2/hacker-tools`.

#### Blog: [https://networkhop.wordpress.com/2016/12/30/automated-wifi-de-authentication-attack/](https://networkhop.wordpress.com/2016/12/30/automated-wifi-de-authentication-attack/)
