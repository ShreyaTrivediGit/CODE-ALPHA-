import socket
import struct
import textwrap
import scapy.all as scapy

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    try:
        scapy.sniff(prn=packet_handler, store=0)
    except PermissionError:
        print("Error: Please run this script with administrative privileges.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def packet_handler(packet):
    raw_data = bytes(packet)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, proto))

def format_multi_line(prefix, string, size=80):
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
    print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

def icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))

def tcp(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
    print(TAB_2 + "Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))

def udp(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    print(TAB_2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))

if __name__ == "__main__":
    main()