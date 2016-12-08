# Automated script for Wifi Deauthentication Attack
###Intro
Written in Python, sends `deauth` packets to a wifi network which results network outage for connected devices. Uses `scapy` module to send `deauth` packets and sniffs wifi.
Know more about [Deauthentication Attack](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack)

###Required Tools
1. aircrack-ng (`apt-get install aircrack-ng`)
2. scapy (Python Module:`apt-get install python-scapy`)

###How to run?
We can run in 3 ways:
* `sudo python deauth.py`. It will automatically creates `mon0` with `airmon-ng start wlan0`(it wont create, if already exists) and sniffs the wifi singal on that interface. After few seconds, it will displays the `SSID` and its `MAC` to choose.
* `sudo python deauth.py XX:YY:AA:XX:YY:AA`. MAC address as command line argument. In this case, there is no need to sniff wifi.
* `export DEAUTH=XX:YY:AA:XX:YY:AA && sudo python deauth.py`. MAC address as environmental variables.

####How to avoid Deauthentication attack?
Use `802.11w` suppored routers. Know more about [802.11w](https://en.wikipedia.org/wiki/IEEE_802.11w-2009) and [read cisco document](https://www.google.co.in/url?sa=t&rct=j&q=&esrc=s&source=web&cd=5&cad=rja&uact=8&sqi=2&ved=0ahUKEwii6qf3xeTQAhVKp48KHTLPBO0QFgg0MAQ&url=http%3A%2F%2Fwww.cisco.com%2Fc%2Fen%2Fus%2Ftd%2Fdocs%2Fwireless%2Fcontroller%2Ftechnotes%2F5700%2Fsoftware%2Frelease%2Fios_xe_33%2F11rkw_DeploymentGuide%2Fb_802point11rkw_deployment_guide_cisco_ios_xe_release33%2Fb_802point11rkw_deployment_guide_cisco_ios_xe_release33_chapter_0100.pdf&usg=AFQjCNEOoiBm3bVeusS0GYfrn5FNZiV-Kg&sig2=cjNnoD8ikMIKoQDMo5zM1g&bvm=bv.140915558,d.c2I)

####NOTE: 
Inorder to work deauthentication attack successful, you should near to the target network. The `deauth` packets should reach the connected devices of the target network(s)

####Difficult to setup environment for this?? check out my other [repo](https://github.com/veerendra2/wifi_sniffer): docker image `veerendrav2/wifi_sniffer`.
