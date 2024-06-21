from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data
import os

# Global Header
# Packet Header
# Packet Data
# Packet Header
# Packet Data
# ...

class Pcap:
    def __init__(self) -> None:

        self.pcapFile = None

        self.global_header = {
            'magic_number': 0xa1b2c3d4, # 0xd4c3b2a1
            'version_major': 2,
            'version_minor': 4,
            'thiszone': 0,
            'sigfigs': 0,
            'snaplen': 65535,
            'network': 215 # 195 ou 215 (https://www.tcpdump.org/linktypes.html)
        }

        self.pcapFile = open('teste.pcap', 'wb')
        self.write_global_header()

        for i in range(100):
            self.write_packet_header(None)
            self.write_packet_data(None)
            pass

        self.pcapFile.close()
        pass

    def write_global_header(self):
        self.pcapFile.write(struct.pack('I', self.global_header['magic_number']))   # guint32 -> 'I' em Python
        self.pcapFile.write(struct.pack('H', self.global_header['version_major']))  # guint16 -> 'H' em Python
        self.pcapFile.write(struct.pack('H', self.global_header['version_minor']))  # guint16 -> 'H' em Python
        self.pcapFile.write(struct.pack('i', self.global_header['thiszone']))       # gint32 -> 'i' em Python
        self.pcapFile.write(struct.pack('I', self.global_header['sigfigs']))        # guint32 -> 'I' em Python
        self.pcapFile.write(struct.pack('I', self.global_header['snaplen']))        # guint32 -> 'I' em Python
        self.pcapFile.write(struct.pack('I', self.global_header['network']))        # guint32 -> 'I' em Python
        pass

    def write_packet_header(self, header):
        # response = {
        #     'sof': buffer[0:4],
        #     'packet_info': buffer[4:6],
        #     'packet_length': buffer[6:10],
        #     'command_data': buffer[10:-6],
        #     'fcs': buffer[-6:-4],
        #     'eof': buffer[-4:]
        # }
        # Timestamp Payload RSSI Status
        # 6B 0-2049B 1B 1B

        # length = int(str(header['packet_length'][8:10]) + str(header['packet_length'][6:8]), 16)


        packet_header = {
            # TODO: Implementar tempo UNIX e pegar dados do pacote
            'ts_sec': 0,
            'ts_usec': 0,
            'incl_len': 500,
            'orig_len': 0
        }

        self.pcapFile.write(struct.pack('I', packet_header['ts_sec']))   # guint32 -> 'I' em Python
        self.pcapFile.write(struct.pack('I', packet_header['ts_usec']))
        self.pcapFile.write(struct.pack('I', packet_header['incl_len']))
        self.pcapFile.write(struct.pack('I', packet_header['orig_len']))

        pass

    def write_packet_data(self, packet):
        # Write 500 random bytes to the file
        self.pcapFile.write(os.urandom(500))
        pass

if __name__ == '__main__':
    pcap = Pcap()
    pass

# TODO: Implementar a leitura do pacote e a escrita no arquivo .pcap do sniffer
# TODO: Descobrir porque a configuração da phy não está funcionando no sniffer
# TODO: Ver como passar o frame/ packet (confirmar diferença deles no 802.15.4) para o arquivo .pcap