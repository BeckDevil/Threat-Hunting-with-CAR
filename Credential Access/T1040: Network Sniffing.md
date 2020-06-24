# T1040 Network Sniffing 

Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (ex: IP addressing, hostnames, VLAN IDs) necessary for follow-on Lateral Movement and/or Defense Evasion activities.

## Detection
```
Event 1 
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = ["tshark.exe", "windump.exe", "logman.exe", "tcpdump.exe", "wprui.exe", "wpr.exe"]

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
(process_name = "netsh.exe" AND process_command_line = "*trace*start*capture=yes*") OR 
process_name = "tshark.exe" OR process_name = "wireshark.exe")\
```
