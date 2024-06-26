# ////////////////////////////////////////////////////////////////////////////////////////////////////
# // Company:  Aceno Digital Tecnologia em Sistemas Ltda.
# // Homepage: http://www.aceno.com
# // Project:  Interface TI Packet Sniffer
# // Version:  1.0
# // Date:     2024
# //
# // Copyright (C) 2002-2024 Aceno Tecnologia.
# // Todos os direitos reservados.
# ////////////////////////////////////////////////////////////////////////////////////////////////////

import struct
import time
from datetime import datetime, timezone

from wireshark_pipe_factory import WiresharkPipeFactory

"""
This class is responsible for building a pcap file.

The .pcap file is organized as follows:
- Global Header
- Packet Header
- Packet Data
- Packet Header
- Packet Data
- [...]

"""
class PcapBuilder():
    """
    Pcap info can be found at: https://wiki.wireshark.org/Development/LibpcapOutFormat
    Defult timezone defined as GMT-3 (BRT) 
    Network type 228 is the value for Raw IPV4.
    """
    def __init__(self):
        self.is_pipe = False
        # File in which the pcap will be saved
        self.pcapOut = None

        # Initial time of the pcap file
        self.initial_time = 0
        # If its the first packet of the pcap file it takes the initial time
        # that was defined when the pcap file was created and
        # subtracts the timestamp of the packet from it.
        # This way the timestamp of the packet will be relative to the start time
        # of the sniffer
        self.is_first_packet = True

        # Calculate the time zone offset
        # Gets the currnt time in UTC and local time
        utc_now = datetime.now(timezone.utc)
        local_now = datetime.now()
        thiszone = int((local_now - utc_now.replace(tzinfo=None)).total_seconds())
        self.initial_time = thiszone

        self.global_header = {
            'magic_number': 0xa1b2c3d4, # 0xd4c3b2a1
            'version_major': 2,
            'version_minor': 4,
            'thiszone': thiszone,
            'sigfigs': 0,
            'snaplen': 262144,
            'network': 228
            # 228 is the value for Raw IPV4.
            # Apparently, TI uses this value for the sniffer interface.
            # The official sniffer software uses this because it opens a UDP connection
            # and sends the TI Radio Packet Info layer through it.
            # This software replicates it by writing a mockup for the IPV4 layer,
            # the UDP layer and the TI Radio Packet Info layer. 
            # For pure IEEE 802.15.4 the value would be 195 ou 215
            # Link to the list of values: https://www.tcpdump.org/linktypes.html
        }

        # IPV4 header hardcoded because the Zigbee dissector format
        self. ipv4_header = bytes([
            0x45, 0x00, 0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, 0xB7, 0x3B, 0xC0, 0xA8, 0x01, 0x03, 
            0xC0, 0xA8, 0x01, 0x03, 
        ])
        # UDP header hardcoded because the Zigbee dissector format
        self. udp_header = bytes([
            0x45, 0x60, 0x45, 0x60, 0x00, 0x47, 0x1D, 0x82, 
        ])

        # TI Radio Packet Info header
        self.ti_header =  bytes([0x00, 0x3c, 0x00, 0x00])
        # Used to separate TI Radio Packet Info
        self.separator = bytes([0x02])

        self.header_lengths  = {
            'ipv4_header_length': len(self.ipv4_header),
            'udp_header_length': len(self.udp_header),
            'ti_header_length': len(self.ti_header),
            'interface_length': 2,
            'separator_length': 1,
            'phy_length': 1,
            'frequency_length': 4,
            'channel_length': 2,
            'rssi_length': 1,
            'fcs_length': 1,
        }
        self.total_length = 0

    """
    Opens a file to write the pcap data.
    Returns True if the file/ pipe was opened successfully, False otherwise.
    """
    def open_pcap(self, output_name, is_pipe=False) -> bool:
        self.is_pipe = is_pipe
        if is_pipe:
            self.pcapOut = WiresharkPipeFactory.create_wireshark_pipe()
            self.pcapOut.open_pipe(output_name)
            self.pcapOut.connect()

        if not is_pipe:
            self.pcapOut = open(output_name, 'wb')

        current_time = int(time.time())
        # Mark initial time
        self.initial_time += current_time

        return False if self.pcapOut is None else True

    """
    Closes the PCAP file.

    """
    def close_pcap(self):
        if not self.is_pipe:
            self.pcapOut.close()
        self.pcapOut.close_pipe()
        pass

    """
    Writes the global header to the pcap file.
    The pcap header has the following structure:
    Magic Number: 4 bytes - Defined number to identify endianess
    Version Major: 2 bytes - Major version of the pcap file format (Commonly 2)
    Version Minor: 2 bytes - Minor version of the pcap file format (Commonly 4)
    Thiszone: 4 bytes - Time zone offset
    Sigfigs: 4 bytes - Accuracy of timestamps (0 for now)
    Snaplen: 4 bytes - Maximum length of captured packets
    Network: 4 bytes - Data link type (https://www.tcpdump.org/linktypes.html)
    """
    def write_global_header(self) -> None:
        # Write global header to a buffer
        global_header_buffer = bytearray()
        global_header_buffer.extend(struct.pack('I', self.global_header['magic_number']))   # guint32 -> 'I' em Python
        global_header_buffer.extend(struct.pack('H', self.global_header['version_major']))  # guint16 -> 'H' em Python
        global_header_buffer.extend(struct.pack('H', self.global_header['version_minor']))  # guint16 -> 'H' em Python
        global_header_buffer.extend(struct.pack('i', self.global_header['thiszone']))       # gint32 -> 'i' em Python
        global_header_buffer.extend(struct.pack('I', self.global_header['sigfigs']))        # guint32 -> 'I' em Python
        global_header_buffer.extend(struct.pack('I', self.global_header['snaplen']))        # guint32 -> 'I' em Python
        global_header_buffer.extend(struct.pack('I', self.global_header['network']))        # guint32 -> 'I' em Python

        # Write global header from buffer
        self.pcapOut.write(global_header_buffer)
        pass

    """
    Writes the packet header to the pcap file.
    The packet format should be:
    - sof: Start of Frame bytes.
    - packet_info: Packet Info byte.
    - packet_length: Packet Length bytes.
    - timestamp: Timestamp bytes.
    - rssi: RSSI bytes.
    - status: Status bytes.
    - command_data: Command Data bytes.
    - fcs: Frame Check Sequence bytes.
    - eof: End of Frame bytes.
    """
    def write_packet_header(self, packet) -> None:

        # Calculate total length of the packet
        self.header_lengths['command_data_lenght'] = len(packet['command_data'])
        self.total_length = int(sum(self.header_lengths.values()))
        # print(f'Total length: {self.total_length}')

        packet_time = packet['timestamp']
        packet_time = self._big_endian_to_little_endian(packet_time)
        packet_time = int(packet_time, 16)
        packet_time_seconds = packet_time // 1_000_000
        packet_time_milliseconds = (packet_time % 1_000_000) // 1_000
        # print(f'Packet time: {packet_time_seconds}.{packet_time_milliseconds}')

        if self.is_first_packet:
            self.is_first_packet = False
            self.initial_time -= packet_time_seconds

        # Write packet header to a buffer
        packet_header_buffer = bytearray()
        packet_header_buffer.extend(struct.pack('I', int(self.initial_time + packet_time_seconds)))     # guint32 -> 'I' em Python
        packet_header_buffer.extend(struct.pack('I', int(packet_time_milliseconds)))    # guint32 -> 'I' em Python
        packet_header_buffer.extend(struct.pack('I', int(self.total_length)))   # guint32 -> 'I' em Python
        packet_header_buffer.extend(struct.pack('I', int(self.total_length)))   # guint32 -> 'I' em Python

        # Write packet header from buffer
        self.pcapOut.write(packet_header_buffer)
        pass

    """
    Writes the packet data to the pcap file.
    The packet format should be:
    - sof: Start of Frame bytes.
    - packet_info: Packet Info byte.
    - packet_length: Packet Length bytes.
    - timestamp: Timestamp bytes.
    - rssi: RSSI bytes.
    - status: Status bytes.
    - command_data: Command Data bytes.
    - fcs: Frame Check Sequence bytes.
    - eof: End of Frame bytes.
    """
    def write_packet(self, packet):
        """
        Wireshark uses a dissector to interpret the data of a packet in the pcap file.
        The dissector is responsible for interpreting the data of the packet and showing it in a human-readable format by
        giving each field or byte group a name and showing it on the interface.
        The dissector being used was made by Texas Instruments and has the following layers:
        - Frame
            - IPV4
            - UDP
            - TI Packet Info
                - Command Data
        
        This interface does not have a pipe, therefore there's no need for using the IPV4 and UDP layers.
        So, those headers will be written as placeholders.
        """

        # Write ipv4 and udp header (placeholder)
        self.ipv4_header = self.ipv4_header[:2] + struct.pack('>H', self.total_length) + self.ipv4_header[4:]
        self.udp_header = self.udp_header[:4] + struct.pack('>H', (self.total_length - 20)) + self.udp_header[6:]


        # Write TI packet info
        ti_packet_info = {
            # TI radio packet info starts with 0x00 0x3c 0x00 0x00
            'header': self.ti_header,
            # Interface is the com port number (2B)
            'interface': packet['interface'],
            # After that the package is separated by 0x02
            'separator': self.separator,
            # PHY config (1B)
            'phy': packet['phy'],
            # Frequency (4B) (2B - freq. 2B - fraq. freq.)
            'frequency': packet['frequency'],
            # Channel (2B)
            'channel': packet['channel'],
            # RSSI (1B)
            'rssi': packet['rssi'],
            # Frame control sequence (1B) normally 0x80
            'fcs': packet['fcs'],
            # Command data (variable)
            'payload': packet['command_data'],
        }

        # Write data to a buffer
        buffer = bytearray()
        buffer.extend(self.ipv4_header)
        buffer.extend(self.udp_header)
        buffer.extend(struct.pack('4B', *ti_packet_info['header']))
        buffer.extend(struct.pack('H', ti_packet_info['interface']))
        buffer.extend(ti_packet_info['separator'])
        buffer.extend(bytes([ti_packet_info['phy']]))
        buffer.extend(struct.pack('4B', *ti_packet_info['frequency']))
        buffer.extend(struct.pack('2B', *ti_packet_info['channel']))
        buffer.extend(bytes.fromhex(ti_packet_info['rssi']))
        buffer.extend(bytes.fromhex(ti_packet_info['fcs']))
        buffer.extend(ti_packet_info['payload'])

        # Write data from buffer
        self.pcapOut.write(buffer)


        pass

    """
    Aux function to convert big endian string to little endian string.
    """
    def _big_endian_to_little_endian(self, big_endian):
        bytes_array = [big_endian[i:i+2] for i in range(0, len(big_endian), 2)]
        bytes_array.reverse()
        bytes_array = ''.join(bytes_array)
        return bytes_array