from TISnifferController import TISnifferController
from PcapBuilder import PcapBuilder
import time 

def big_endian_to_little_endian(big_endian):
    bytes_array = [big_endian[i:i+2] for i in range(0, len(big_endian), 2)]
    bytes_array.reverse()
    bytes_array = ''.join(bytes_array)
    return bytes_array

def on_packet_recieve(packet):
    # Convert package command data to bytes
    packet['command_data'] = bytes.fromhex(packet['command_data'])
    
    # Convert packet lenght to little endian and int
    packet['packet_length'] = big_endian_to_little_endian(packet['packet_length'])
    packet['packet_length'] = int(packet['packet_length'], 16)

    # Write packet to pcap file
    pcap.write_packet_header(packet)
    pcap.write_packet(packet)
    print('New packet written to pcap file.')
    pass









# Create sniffer controller
snfr = TISnifferController('COM5', debug=True)
# Connect to sniffer and get board info
snfr.connect()

# Create pcap file
pcap = PcapBuilder()
pcap.open_pcap('teste.pcap')
pcap.write_global_header()

# snfr.configure(868, 0x12)

# Start sniffer with packet callback to write packets to pcap file
snfr.start()
snfr.stream(on_packet_recieve, 30)

# Close pcap file
pcap.close_pcap()
# Stop sniffer
snfr.stop()
snfr.disconnect()
