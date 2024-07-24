<h1 align="center">Pyniffer</h1>
<h4 align="center">This software aims to replicate basic capabilities of the <a href="https://www.ti.com/tool/PACKET-SNIFFER">SmartRF Packet Sniffer 2</a> from <a href="https://www.ti.com">Texas Instruments</a>, on a easy-to-use script in Python compatible with Linux and Windows.</h4>

The [SmartRF Packet Sniffer 2](https://www.ti.com/tool/PACKET-SNIFFER) from [Texas Instruments](https://www.ti.com) is a useful tool for sniffing packet data using some of their devices. It can save sniffed packets to a .pcap files and send packets through a pipe for live view. It also support multiple devices to be connected at once. While this script does not implement all of [SmartRF Packet Sniffer 2](https://www.ti.com/tool/PACKET-SNIFFER) capabilities, it should be enough for basic usage.

**This script was made as a proof-of-concept. [Tuxniffer](https://github.com/AcenoTecnologia/tuxniffer) does the same as this script, but in a better way.**

## Features

This script is capable of:
- Sniffing **only IEEE 802.15.4** packets sent by Texas Instruments family CC13XX, CC26XX and Launchpad in a simple and easy-to-use way.
- Supporting multiple devices simultaneously with different settings each.
- Storing packets in a .pcap file that can be opened using Wireshark.
- Viewing packets live in Wireshark through pipes.


## Usage Example and Notes
- To run the script you can use:
```sh
    python src/example.py
```


- The code explaining how to use the interface with a file or a pipe is presented in `src/example.py`;
- If the option `is_pipe` is enabled Wireshark should be executed with the parameters `-k -i \\.\pipe\wireshark`:


```sh
    wireshark -k -i \\.\pipe\wireshark
```

## Known Issues

In the current state this script:

- Blocks the IO and the script while streaming. A possible solution would be use AsyncIO, but theres no plan to implement that;
- Doesn't calculate the `RSSI` value correctly;
- The IPV4 and UDP layer sent to wireshark is hardcoded and doesn't represent any actual IP address or UDP connection. [Texas Instruments](https://www.ti.com) uses UDP to send the "TI Radio Packet Info". Because the packet data is interpreted by the Wireshark ZigBee dissector plugin made by TI, it must follow the their format, and it includes the IP/UDP layer;
- The stream method let the user specify the streaming duration by setting `read_time`. The actual read time could be bigger then the defined value, because the script will wait until it recieves the End of Frame marker from the next packet to ensure that no packet is left uncompleted;
- The interface cannot sniff BLE and other kinds of packets yet;

## Texas Instruments Documentation Issues

During development it was found some inconsistencies between the sniffer documentation presented by [Texas Instruments](https://www.ti.com) and the device functioning:

- The baudrate presented in the documentation is `921600`, but the firmware source code uses `3000000`.
- Despite showing a state machine with a `PAUSED` state in the documentation, the firmware source code doesn't have one. Therefore, neither `pause` and `resume` commands exists.
- The PHY code informed by the documentation for `IEEE 802.15.4 2.4 GHz band O-QPSK` is `0x11`, but in reality it is `0x12`.
- This happens because the [SmartRF Packet Sniffer 2](https://www.ti.com/tool/PACKET-SNIFFER) by [Texas Instruments](https://www.ti.com) has a Radio Configuration for `IEEE 802.15.4 915 MHz GSFK 200 kbps` after `0x0C`, which causes a offset of 1 to all subsequent values. This configuration is not on the reference/ documentation, but can be selected on the software. The Radio Mode table bellow is already fixed.
- The packet response documentation also informs that the response frame data payload has the format: `Timestamp (6B) | Payload (0-2047B) | RSSI (1B) | Status (1B)`. But, in reality is `Timestamp (6B) | Separator (1B) | Payload (0-2047B) | RSSI (1B) | Status (1B)`. It was not found the usage of the Separator. However, neither considering it as Timestamp or Payload work. The Timestamp gets incorrect and the Payload doesn't match the FCS at the end of the frame (last 2B of payload).
- While this software was developed using the ``CC1352P7-1`` model, the ``CC1352P1`` model was also used for tests and validation. A issue found is that on Windows, with the original [SmartRF Packet Sniffer 2](https://www.ti.com/tool/PACKET-SNIFFER), the ``CC1352P1`` could not run any 2.4GHz modes, despite having support. The solution for this issue can be found [here](https://e2e.ti.com/support/wireless-connectivity/bluetooth-group/bluetooth/f/bluetooth-forum/1229627/launchxl-cc1352p-packet-sniffer-2-error-sending-message-msg-cfgphy-problem-unknown?tisearch=e2e-sitesearch&keymatch=LAUNCHXL-CC1352P%25252525252525252520Error%25252525252525252520Sending%25252525252525252520Message#).