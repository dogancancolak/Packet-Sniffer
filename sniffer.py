# Packet sniffer in python for Linux
# Sniffs only incoming TCP packet

import socket, sys, textwrap
from struct import *

# create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except (socket.error, msg):
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()


def format_multi_line(string, size=80):
    if isinstance(string, bytes):
        string = ''.join(map(chr, string))
        #string = ''.join(r'\x{:02}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([line for line in textwrap.wrap(string,size)])


# receive a packet
while True:
    # TCP/IP can handle packets of maximum legal size 65,565 bytes
    packet = s.recvfrom(65565)

    # taking string form of packet from tuple
    packet = packet[0]

    # take first 20 characters for the ip header
    ip_header = packet[0:20]

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
    str_protocol = "" + str(protocol)
    if protocol == 6:  # protocol 6 means TCP
        str_protocol = str_protocol + " (TCP)"

    source_addr = socket.inet_ntoa(iph[8])
    destination_addr = socket.inet_ntoa(iph[9])

    print('\nVersion : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str_protocol + '\nSource Address : ' + str(source_addr) + ' Destination Address : ' + str(destination_addr))

    # after ip header , tcp header comes. we take packets 20 characters from the begining of tcp header.
    tcp_header = packet[ipheader_len:ipheader_len + 20]

    # Now its time o unpack the tcp header like we did before to ip header. But this time with diferent format.
    tcph = unpack('!HHLLBBHHH', tcp_header)

    # in tcp headers structure
    source_port = tcph[0]      # first element is source port
    dest_port = tcph[1]        # second element is destination port
    sequence = tcph[2]         # third element is Sequence number
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + '\nSequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

    h_size = ipheader_len + tcph_length * 4

    # get data from the packet
    data = packet[h_size:]
    data = ''.join(map(chr, data))

    print('Data : ' + data)
    print()
