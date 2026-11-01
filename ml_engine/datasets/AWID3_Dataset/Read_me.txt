Decryption keys are contained in 3 different files, namely "80211_keys_1-5", "80211_keys_6-8", and "80211_keys_9-13".

The range of numbers in each file name correspond to attacks, i.e., 1: Deauth, 2: Disass, 3: (Re)Assoc, 4: Rogue_AP,
5: Krack, 6: Kr00k, 7: Evil_Twin, 8: SQL_Injection, 9: SSH, 10: Malware, 11: SSDP, 12: Botnet, and 13: Website_spoofing.

So, for example, the keys to decrypt the "Disass" pcap file is in the "80211_keys_1-5" file.

To decrypt a pcap file,

1. Open Wireshark and navigate to Edit->Preferences->Protocols->IEEE 802.11.

2. Press the Edit button at Decryption keys option. A pop-up window will appear.
In this window, click on the hyperlink path of the relevant Wireshark file containing "decryption keys" (PMK) - For more details check: https://wiki.wireshark.org/HowToDecrypt802.11.

3. Copy paste (all) the contents of the relevant decryption file ("80211_keys_1-5", "80211_keys_6-8", or "80211_keys_9-13"), save, and restart Wireshark.
Follow the numbering format of each pcap file inside the pcaps folder, to match with the correct decryption file.


Note 1: Wireshark has a limit on how many PMKs (~50 to 70 keys) can contain in the "decryption keys" file. If this limit is excedeed, Wireshark will not decrypt the relevant pcap file. 
Therefore, it is recommended that you keep only the relevant PMKs, say, "80211_keys_6-8" in Wireshark "decryption keys" file.

Note 2: As stated in the manuscript, and due to an issue with the employed Wireshark version, the full decryption of pcap files for SSH (Att13), Website_spoofing (Att21) and Botnet (Att14), 
SSDP (Att18) was only possible in Wireshark Linux (v3.2.7) and Wireshark MS Windows (v3.4.0) versions, respectively. To avoid related issues with future Wireshark releases, 
always refer to the "Attack Frames" column in Table 3 for the correct amount of attacking frames contained in the respective pcap.

Note 3: "p1", "p2" in column "Frame #" of table 3 correspond (approximately) to the start and end frame of this phase (p) of the attack. 

Note 4: If you wish to receive our attack scripts, automation scripts, TLS keys for each machine, or the original encrypted RADIUS files, send us an email.

Proposed Wireshark filter per attack
To quickly discern among normal and attack traffic you can use the following Wireshark filters. 
Note that these filters will return the great mass (>95%) of attack frames per attack, and for some of the attacks almost all such frames.

Deauth
(wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12) && wlan.fc.protected==0 && (frame.number >=1088022 && frame.number <=1626254)

Disass
(wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12) && wlan.fc.protected==0 && (frame.number >=1404237 && frame.number <=2013346)

(Re)Assoc
(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2 || wlan.fc.type_subtype==8) && frame.number >= 1145178 && frame.number <= 1833964 && frame.len <= 301

Rogue_AP
wlan.fc.type_subtype==8 && frame.number >= 1198551 && frame.number <= 1973111 && frame.len < 264

Krack
wlan_radio.channel == 2

Kr00k
wlan.fc.type_subtype==10 && wlan.fc.protected==0 && frame.number >= 1555898

SSH
ip.addr == 192.168.2.248 && frame.number >= 1356015 && frame.number <= 2440390

Botnet
((ip.addr == 192.168.2.248) && (ip.addr==192.168.2.130 || ip.addr==192.168.2.1 || ip.addr==192.168.2.125 || ip.addr==192.168.2.42 || ip.addr==192.168.2.184 || ip.addr==192.168.2.73)) && frame.number >= 1135097 && frame.number <= 3325480

Malware
(ip.addr == 192.168.2.248 || ip.addr == 192.168.2.42 || ip.addr == 192.168.2.73 || ip.addr == 192.168.2.41 || ip.addr == 192.168.2.254 || ip.addr == 192.168.2.184 || ip.addr == 192.168.2.190) && ip.addr==192.168.2.130 && frame.number >= 1021326 && frame.number <= 2310931

SQL_Injection
ip.addr == 192.168.2.248 && frame.number >=1484773 && frame.number <= 2589043

SSDP
(ip.addr == 20.50.64.3 || ip.addr == 192.168.2.248) && ssdp && frame.number >= 1198154 && frame.number <= 8122583

Evil_Twin
((wlan.fc.type_subtype==8 && frame.len < 242) || ((wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12 || wlan.fc.type_subtype==40) && wlan.fc.protected==0)) && frame.number >= 1420038 && frame.number <= 3778728 && (ip.addr==192.168.30.1 || wlan.addr == 0c:9d:92:54:fe:35)

Website_spoofing
(wlan.sa == 04:ed:33:e0:24:82 || wlan.da == 04:ed:33:e0:24:82 || wlan.sa == 00:C0:CA:A8:29:56 || wlan.da == 00:C0:CA:A8:29:56 || wlan.sa == 24:F5:A2:EA:86:C3 || wlan.da == 24:F5:A2:EA:86:C3 || wlan.sa == 00:C0:CA:A8:26:3E || wlan.da == 00:C0:CA:A8:26:3E) && frame.number >= 16410 && frame.number <= 2668583
