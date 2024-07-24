from ti_sniffer_controller import TISnifferController
from pcap_builder import PcapBuilder


"""
Auxiliary method to convert big endian to little endian.
"""
def big_endian_to_little_endian(big_endian):
    bytes_array = [big_endian[i:i+2] for i in range(0, len(big_endian), 2)]
    bytes_array.reverse()
    bytes_array = ''.join(bytes_array)
    return bytes_array

"""
The IO is blocked when the streaming is enabled.
Because of that, the communication method for when a packet is recieved is a callback.
This callback is called whenever a new packet is received by the sniffer.
The callback necessarily takes the packet as a parameter.
"""
def on_packet_recieve(packet):
    # Convert package command data to bytes
    packet['command_data'] = bytes.fromhex(packet['command_data'])
    
    # Convert packet lenght to little endian and int
    packet['packet_length'] = big_endian_to_little_endian(packet['packet_length'])
    packet['packet_length'] = int(packet['packet_length'], 16)

    # Write packet to pcap file
    pcap.write_packet_header(packet)
    pcap.write_packet(packet)
    pass


"""
This is a example of how the sniffer controller can be used to stream packets to a pcap file using a file or a pipe.
Note: If PCAP is in pipe mode, the program will wait for the wireshark to be open to start the sniffer.
"""
# Create sniffer controller
# If debug is True, the sniffer controller will print debug messages
snfr = TISnifferController('/dev/ttyACM0', debug=True)
# Connect to sniffer and get board info
snfr.connect()

# Create pcap file
pcap = PcapBuilder()
# The pipe is created with the name 'wirehsark' in \\.\pipe\wireshark
# To start the wireshark using the pipe you must use the CLI command: wireshark -k -i \\.\pipe\wireshark
# If you want to output the pcap to a file, just use the file name as parameter
# pcap.open_pcap('wireshark.pcap') The is_pipe is False by default
print('[INFO] Waiting for wireshark to open...')
pcap.open_pcap('wireshark', is_pipe=True)
pcap.write_global_header()

# Start sniffer with packet callback to write packets to pcap file
snfr.start()
snfr.stream(on_packet_recieve, 30)

# Close pcap file
pcap.close_pcap()
# Stop sniffer
snfr.stop()
# Disconnect from sniffer
snfr.disconnect()
