# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets

import socket, sys, time
from struct import *

def elapsed_time():
    print('Elapsed Time : ' + str(time.time()-start_time))

packet_counter = 0
tcp_counter = 0
start_time = time.time()
import atexit
atexit.register(elapsed_time)


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    # formatting each chunk to decimal addresses
    # and returns properly formatted mac address
    bytes_str = map('{:02x}'.format, a)
    return ':'.join(bytes_str).upper()


# create a AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL    0x0003          /* Every packet */
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error:
    print('Socket could not be created.')
    sys.exit()

# receive a packet
while True:
    # TCP/IP can handle packets of maximum legal size 65,565 bytes
    packet = s.recvfrom(65565)
    packet_counter = packet_counter+1
    # taking string form of packet from tuple
    packet = packet[0]

    # parse ethernet header
    eth_length = 14

    # Taking packet's first 14 character for ethernet header
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print('Destination MAC : ' + eth_addr(packet[0:6]) + ' || Source MAC : ' + eth_addr(packet[6:12]) + ' || Ethernet Protocol : ' + str(eth_protocol))

    # Parse IPv4 packets, Ethertype number = 0x0800
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # formatting the header we have with :
        # ! = big-endian
        # B = unsigned char
        # H = unsigned short
        # s = char array
        # 4s = char array of size 4
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        # takin first octet of ip header
        # ihl = Internet Header Length. (total ip header length)
        version_ihl = iph[0]

        # first 4 bit represents version. We shifted octet 4 bit to take just first 4 bit.
        version = version_ihl >> 4

        # second 4 bit represents ip header length. We used and operation for take just last 4 bit.
        # 0xF = 0000 0000 (....) 1111
        ihl = version_ihl & 0xF

        # ihl represents how many 32 bits words is in ip header. We multiply ihl with 4 to find size of ip header in bytes.
        ipheader_len = ihl * 4

        # assigned time to leave value. ( how many hops packet can make)
        ttl = iph[5]

        protocol = iph[6]
        source_addr = socket.inet_ntoa(iph[8]);
        destination_addr = socket.inet_ntoa(iph[9]);

        print('Version : ' + str(version) + ' || IP Header Length : ' + str(ihl) + ' || TTL : ' + str(ttl) + ' || Protocol : ' + str(protocol) + ' || Source Address : ' + str(source_addr) + ' || Destination Address : ' + str(destination_addr))

        # TCP protocol
        if protocol == 6:

            # another tcp packet captured
            tcp_counter = tcp_counter+1

            # after ip header , tcp header comes. we take packet's 20 characters from the begining of tcp header.
            t = ipheader_len + eth_length
            tcp_header = packet[t:t + 20]

            # Now its time o unpack the tcp header like we did before to ip header. But this time with diferent format.
            tcph = unpack('!HHLLBBHHH', tcp_header)

            # in tcp headers structure
            source_port = tcph[0]  # first element is source port
            dest_port = tcph[1]  # second element is destination port
            sequence = tcph[2]  # third element is Sequence number
            acknowledgement = tcph[3]  # fourth element is ack.
            tcph_length = tcph[4] >> 4

            print('Source Port : ' + str(source_port) + ' || Destination Port : ' + str(dest_port) + ' || Sequence Number : ' + str(sequence) + ' || Acknowledgement : ' + str(acknowledgement) + ' || TCP header length : ' + str(tcph_length))

            h_size = (eth_length + ipheader_len + tcph_length) * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            data = ''.join(map(chr, data))

            print('Data : ' + data)

        # some other IP packet like IGMP or ICMP or UDP ...
        else:
            print('Protocol other than TCP')

        print()
        print('Captured packets : ' + str(packet_counter) + '  TCP Packets : '+ str(tcp_counter))
        print()