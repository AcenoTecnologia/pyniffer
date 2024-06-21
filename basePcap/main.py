import serial
import serial.tools.list_ports
from ITSniffer import ITSniffer

if __name__ == '__main__':
    sniffer = ITSniffer()
    sniffer.open_port()
    sniffer.select_command()

