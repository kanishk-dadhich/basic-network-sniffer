Explanation
Imports: The script imports necessary functions from the scapy library and the datetime module to timestamp packets.

packet_callback: This function is called for each captured packet:

It retrieves the current timestamp.
It checks for the presence of IP, TCP, UDP, and ARP layers.
Depending on the protocol, it extracts and prints relevant information.
sniff: This function captures packets. The prn parameter specifies the callback function to process each packet, and store=0 means it won't store the packets in memory.

Running the Script
To run the script, you typically need superuser (root) privileges because capturing network packets requires elevated permissions:


Copy code
sudo python network_sniffer.py
Enhancements
You can enhance this script by adding more detailed analysis, saving captured packets to a file, and providing filtering options similar to Wireshark. For example, you could filter packets by specific protocols or IP addresses, and analyze additional protocols such as HTTP, DNS, and more.
