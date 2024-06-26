# TI sniffer interface

This script is a interface for serial comunication with the Texas Instrument sniffer. It allows sniffing network packets to a pcap file (`output.pcap` for example) or to a pipe (`\\.\pipe\wireshark` for example) in real time.

## Usage Example and Notes
- The code explaining how to use the interface with a file or a pipe is presented in `example.py`;
- If the option `is_pipe` is enabled Wireshark should be executed with the parameters `-k -i \\.\pipe\wireshark`.

## Known Issues

In the current state the interface:

- Blocks the IO and the script while streaming. A possible solution would be use AsyncIO;
- Doesnt calculate the RSSI value correctly;
- The IPV4 and UDP layer sent to wireshark is hardcoded and doesn't represent any actual IP address or UDP connection. Texas Instruments uses UDP to send the "TI Radio Packet Info". Because the packet data is interpreted by the Wireshark ZigBee dissector plugin made by TI, it must follow the their format, and it includes the IP/UDP layer;
- The stream method let the user specify the streaming duration by setting `read_time`. The actual read time could be bigger, because the script will wait until it recieves the End of Frame marker from the next packet to ensure that no packet is left uncompleted;
- The interface cannot sniff BLE packets yet;

## Texas Instruments Documentation Issues

During development it was found some inconsistencies between the sniffer documentation presented by Texas Instruments and the device functioning (tested on the CC1352P7):

- The baudrate presented in the documentation is `921600`, but the firmware source code uses `3000000`;
- Despite showing a state machine with a `PAUSED` state in the documentation, the firmware source code doesn't have one. Therefore, neither `pause` and `resume` commands exists;
- The packet response documentation also informs that the response frame data payload has the format: `Timestamp (6B) | Payload (0-2047B) | RSSI (1B) | Status (1B)`. But, in reality the `RSSI` value is not presented as the last byte before `Status`. This byte actually is part of the FCS for the IEEE layer;
- Following this logic, the only other position that RSSI could have is in the following payload format: `Timestamp (6B) | RSSI (1B) | Payload (0-2047B) | Status (1B)`, but this position doesn't represent the correct value;

## PHY Table Issues

- The PHY code informed by the documentation for `IEEE 802.15.4 2.4 GHz band O-QPSK` is `0x11`, but in reality it is `0x12`.

This happens because:

- The `Smart RF Sniffer Agent software` by TI has a Radio Configuration for `IEEE 802.15.4 915 MHz GSFK 200 kbps` after `0x0C`, which causes a offset of `0x01` to all subsequent values.