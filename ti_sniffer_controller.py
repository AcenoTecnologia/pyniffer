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

import serial
import time
from enum import Enum

"""
Enum to represent the state of the TI Sniffer device.
"""
class State(Enum):
    STATE_WAITING_FOR_COMMAND = 0
    STATE_INIT = 1
    STATE_STARTED = 2
    STATE_STOPPED = 3

"""
This class is responsible for controlling the TI Sniffer device.
Actions like starting, stopping, changing frequency and changing PHY are implemented here.
This class is also responsible for handling frames and packets received by the TI Sniffer.
"""
class TISnifferController:
    def __init__(self, port, debug = False):
        # Debug mode print messages
        self.debug = debug

        # Serial port configuration
        self.baudrate = 3000000
        self.port = port
        self.data_bits = serial.EIGHTBITS
        self.stop_bits = serial.STOPBITS_ONE
        self.parity = serial.PARITY_NONE
        self.default_timeout = 0.5

        # Start of Frame and End of Frame delimitations
        self.sof = [0x40, 0x53]
        self.eof = [0x40, 0x45]

        # Packet Info + Packet Length + Command Data for basic commands
        self.ping_command_base = [0x40, 0x00, 0x00]
        self.start_command_base = [0x41, 0x00, 0x00]
        self.stop_command_base = [0x42, 0x00, 0x00]
        # Packet Info + Packet Length for frequency and PHY commands
        self.frequency_command_base = [0x45, 0x04, 0x00]
        self.phy_command_base = [0x47, 0x01, 0x00]

        # Board Commands
        # Ping, start and stop commands has no payload, so command base already includes the Command Data
        # SOF |----------------------Command Base---------------------| FCS | EOF
        # SOF | Packet Info | Packet Length (0) | Command Data (None) | FCS | EOF
        self.ping_command = bytes(self.sof + self.ping_command_base + [self._calculate_fcs(self.ping_command_base)] + self.eof)
        self.start_command = bytes(self.sof + self.start_command_base + [self._calculate_fcs(self.start_command_base)] + self.eof)
        self.stop_command = bytes(self.sof + self.stop_command_base + [self._calculate_fcs(self.stop_command_base)] + self.eof)
        # Configure frequency and PHY commands have a payload, so the Command Data is separated
        # The Command Data is a parameter on the configure method. Therefore, they are not constructed here.

        # Each command has a status byte that indicates if the command was received correctly.
        self.status_lookup = {
            '00': 'Command was received correctly.',
            '01': 'Reception of Command timed out before all data was received.',
            '02': 'Computation of frame check sequence did not succeed.',
            '03': 'The Command has invalid format or is not supported.',
            '04': 'The Command is invalid for the current state of sniffer FW.',
        }

        self.board_info = {
            'status': None,
            'chip_id': None,
            'chip_rev': None,
            'fw_id': None,
            'fw_rev': None
        }

        self.metadata = {
            'interface': int(''.join(filter(str.isdigit, self.port))), # Interface number (COM port number)
            'phy': 0x12,
            'frequency': [0x92, 0x09, 0x00, 0x00],
            'channel': [0x14, 0x00],
        }

        # Manages the current state of the sniffer
        # Initialize the sniffer in the WAITING_FOR_COMMAND state
        # Its only true if the board was just booted
        self.state = State.STATE_WAITING_FOR_COMMAND

        # Serial connection
        self.ser = None
        pass

    """
    Opens a serial connection with the TI Sniffer device using the port specified in the constructor.
    Returns True if the connection was successfully opened, False otherwise.
    """
    def connect(self) -> bool:
        try:
            self.ser = serial.Serial(port=self.port, baudrate=self.baudrate, bytesize=self.data_bits, parity=self.parity, stopbits=self.stop_bits, timeout=self.default_timeout)
        except serial.SerialException:
            exit('[ERROR] Could not open serial port {}: {}'.format(self.port, serial.SerialException))
        
        if not self.ser.is_open:
            self._debug('[ERROR] Serial port {} could not be opened.'.format(self.port))
            return False

        self._change_state(State.STATE_WAITING_FOR_COMMAND)
        self.stop()

        self.configure(self.metadata['frequency'], self.metadata['phy'])

        self._debug('[INFO] Connection settings: ')
        self._debug('--Interface: COM{}'.format(self.metadata['interface']))
        self._debug('--PHY: {}'.format(hex(self.metadata['phy'])))
        self._debug('--Frequency: {}'.format(int.from_bytes(self.metadata['frequency'], byteorder='little')))
        self._debug('--Channel: {}'.format(int.from_bytes(self.metadata['channel'], byteorder='little')))

        self._debug('[INFO] Getting board information through ping command.')
        self.ping()

        return True


    """
    Closes the serial connection with the TI Sniffer device.
    Returns True if the connection was successfully closed, False otherwise.
    """
    def disconnect(self) -> bool:
        self.ser.close()
        if self.ser.is_open:
            self._debug('[ERROR] Serial port {} could not be closed.'.format(self.port))
            return False
        self._debug('[INFO] Serial port {} closed successfully.'.format(self.port))
        return not self.ser.is_open

    """
    Configures the TI Sniffer device to sniff packets with the specified frequency and PHY.
    (frequency + fractFrequency/65536) MHz.
    For example, 2450.0 MHz is 0x0992 and should be sent as [0x92 0x09 0x00 0x00].
    The TI Sniffer documentation has a table with PHY indexes for each board.
    This command only works if the sniffer is on the STOPPED state.
    This method accepts the frequency in MHz or in the format [0x92 0x09 0x00 0x00].
    Returns True if the configuration was successful, False otherwise.
    """
    def configure(self, frequency, phy) -> bool:
        if self.state != State.STATE_STOPPED:
            self._debug('[ERROR] Sniffer is not in the STOPPED state. Cannot configure frequency and PHY.')
            return False

        # If the input is in the format 2450.0, convert it to the format [0x92 0x09 0x00 0x00]
        if type(frequency) is float or type(frequency) is int:
            whole_frequency = int(frequency)
            fractionary_frequency = frequency - whole_frequency
            whole_frequency = whole_frequency.to_bytes(2, byteorder='little')
            fractionary_frequency = int(fractionary_frequency * 65536)
            fractionary_frequency = fractionary_frequency.to_bytes(2, byteorder='little')
            frequency = whole_frequency + fractionary_frequency
            frequency = [int(byte) for byte in frequency]     

        # Configure Frequency command
        freq_command = bytes(self.sof + self.frequency_command_base + frequency + [self._calculate_fcs(self.frequency_command_base, frequency)] + self.eof)

        # Configure Frequency
        self.ser.write(freq_command)
        response = self._recieve_packet()  
        self._debug('[INFO] Frequency command status: {}'.format(self._get_command_status(response['command_data'])))
        if response['command_data'] == '00':
            # Saves the new frequency as list format in the metadata
            self.metadata['frequency'] = frequency
            # Converts the frequency to MHz to show in the debug message
            whole_frequency = bytes(frequency[:2])
            fractionary_frequency = bytes(frequency[2:])
            whole_frequency = int.from_bytes(whole_frequency, byteorder='little')
            fractionary_frequency = int.from_bytes(fractionary_frequency, byteorder='little')
            frequency = whole_frequency + (fractionary_frequency / 65536)
            self._debug('[INFO] Frequency configured successfully to {} MHz.'.format(frequency))
        if response['command_data'] != '00':
            self._debug('[INFO] Frequency could not be configured correctly to {} MHz.'.format(frequency))
            return False

        # Configure PHY command
        phy_command = bytes(self.sof + self.phy_command_base + [phy] + [self._calculate_fcs(self.phy_command_base, [phy])] + self.eof)

        # Configure PHY
        self.ser.write(phy_command)
        response = self._recieve_packet()
        self._debug('[INFO] PHY command status: {}'.format(self._get_command_status(response['command_data'])))
        if response['command_data'] == '00':
            self._debug('[INFO] PHY configured successfully to {}'.format(hex(phy)))
            self.metadata['phy'] = phy
        if response['command_data'] != '00':
            self._debug('[INFO] PHY could not be configured correctly to {}'.format(hex(phy)))
            return False

        return True

    """
    Starts the sniffing process on the TI Sniffer device.
    From this point on, the device will start receiving packets.
    Those packets can be read by the user using the stream method.
    This method does not block the IO.
    Returns True if the start command was successfully sent, False otherwise.
    """
    def start(self) -> bool:
        # Send the start command to the device
        self._debug('[INFO] Start command sent.')
        self.ser.write(self.start_command)
        response = self._recieve_packet()
        self._debug('[INFO] Start command status: {}'.format(self._get_command_status(response['command_data'])))
        if response['command_data'] == '00':
            self._change_state(State.STATE_STARTED)
        return response['command_data']

    """
    Stops the sniffing process on the TI Sniffer device.
    The device will stop receiving packets.
    Returns True if the stop command was successfully sent, False otherwise.
    """
    def stop(self) -> bool:
        # Send the stop command to the device
        self._debug('[INFO] Stop command sent.')
        self.ser.write(self.stop_command)
        response = self._recieve_packet()
        self._debug('[INFO] Stop command status: {}'.format(self._get_command_status(response['command_data'])))
        if response['command_data'] == '00':
            self._change_state(State.STATE_STOPPED)
        return response['command_data']
    
    """
    The ping command is used to get the board information.
    Board information includes the Chip Id, Chip Revision, FW Id and FW Revision.
    Returns True if the ping command was successfully sent, False otherwise.
    """
    def ping(self) -> bool:
        # Send the ping command to the device
        self._debug('[INFO] Ping command sent.')
        self.ser.write(self.ping_command)
        response = self._recieve_packet()
        board_info = self._get_board_info(response)
        # Print board info
        self._debug('[INFO] Ping command status: {}'.format(self._get_command_status(board_info['status'])))
        self._debug('[INFO] Board Information:')
        self._debug('--Chip Id: {}'.format(board_info['chip_id']))
        self._debug('--Chip Revision: {}'.format(board_info['chip_rev']))
        self._debug('--FW Id: {}'.format(board_info['fw_id']))
        self._debug('--FW Revision: {}'.format(board_info['fw_rev']))

        self._debug('[INFO] Board Information updated.')
        self.board_info = board_info

        # If the board is in the WAITING_FOR_COMMAND state, change it to INIT if the ping was successful
        if board_info['status'] == '00' and self.state == State.STATE_WAITING_FOR_COMMAND:
            self._change_state(State.STATE_INIT)

        return board_info['status']

    """
    If the sniffer is in the STARTED state, this method will start streaming packets from the device.
    Each recieved packet will call a callback function called process_packet if the return info is 0xc0 (Data streaming from the sniffer).
    This callback function should be implemented by the, takes a packet as input and have no return.
    Bytes are sent in little endian format.

    If read_time is -1, the method will stream packets indefinitely (Blocking IO until interrupted).
    If read_time is a positive number, the method will stream packets for read_time seconds.
    Actual Read Time can surpass the read_time because it will wait until the end of the next packet.

    Returns True if the streaming was successful, False otherwise.
    Does not return anything if the read_time is -1.
    """
    def stream(self, packet_callback, read_time = -1) -> bool:
        if read_time == -1:
            self._debug('[INFO] Starting streaming indefinitely.')
        else:
            self._debug('[INFO] Starting streaming for {} seconds.'.format(read_time))
        # Check if the sniffer is in the STARTED state
        if self.state != State.STATE_STARTED:
            self._debug('[ERROR] Sniffer is not in the STARTED state. Cannot start streaming.')
            return False
        
        # Executes the loop for read_time seconds or forever if read_time is -1
        start_time = time.time()
        while read_time == -1 or (time.time() - start_time) < read_time:
            packet = self._recieve_packet()
            packet.update(self.metadata)
            # If the packet is a stream packet, call the packet_callback function
            if packet['packet_info'] == 'c0':
                self._debug('[INFO] Packet received. Calling packet callback after {:.3f} seconds.'.format(time.time() - start_time))
                packet_callback(packet)
        return True

    """
    Receives a packet from the TI Sniffer device.
    The packet is delimited by the SOF and EOF bytes.
    Returns a dictionary with the packet information:
    - sof: Start of Frame bytes.
    - packet_info: Packet Info byte.
    - packet_length: Packet Length bytes.
    - command_data: Command Data bytes.
    - fcs: Frame Check Sequence bytes.
    - eof: End of Frame bytes.
    """
    def _recieve_packet(self):
        # Start of Frame | Packet Info | Packet Length | Command data | FCS | End of Frame (EOF)
        # 2B             | 1B          | 2B            | 0-255B       | 1B  | 2B

        eof = ''.join(format(x, '02x') for x in self.eof)
        sof = ''.join(format(x, '02x') for x in self.sof)
        buffer = ''
        while True:
            byte = self.ser.read(1)
            buffer += byte.hex()
            if eof in buffer:
                break

        response = {
            'sof': buffer[0:4],
            'packet_info': buffer[4:6],
            'packet_length': buffer[6:10],
            'command_data': buffer[10:-6],
            'fcs': buffer[-6:-4],
            'eof': buffer[-4:]
        }

        # If the packet is a stream packet, the timestamp and the rssi are included in the packet info field
        if response['packet_info'] == 'c0':
            response['timestamp'] = response['command_data'][0:12]
            response['rssi'] = response['command_data'][12:14]
            response['command_data'] = response['command_data'][14:-2]

        return response

    """
    If debbuging is enabled, this method will print the message to the console.
    """
    def _debug(self, message):
        if self.debug:
            print('{}'.format(message))

    """
    Returns the status of a command based on the status byte received.
    """
    def _get_command_status(self, status_byte):
        if status_byte not in self.status_lookup.keys():
            return 'Invalid status byte.'
        return self.status_lookup[status_byte]
    
    """
    The ping command has a special response. It returns the board information.
    This method parses the packet and returns the board information as a dictionary.
    Input: packet - The packet received from the TI Sniffer from the ping command.
    Output: board_info - A dictionary with the board information:
        - status: 1 byte command status.
        - chip_id: 2 bytes Chip Id field (for example 0x1350).
        - chip_rev: 1 byte Chip Revision hex value (for example Revision 2.1 -> 0x21).
        - fw_id: 1 byte FW ID field.
        - fw_rev: 2 bytes FW revision field. 1 byte major revision (MSB) and 1 byte minor revison (LSB) (for example Revision 1.10 -> 0x01 0x0a).
    """
    def _get_board_info(self, packet):
        board_info = {
            'status': self._big_endian_to_little_endian(packet['command_data'][0:2]),
            'chip_id': self._big_endian_to_little_endian(packet['command_data'][2:6]),
            'chip_rev': self._big_endian_to_little_endian(packet['command_data'][6:8]),
            'fw_id': self._big_endian_to_little_endian(packet['command_data'][8:10]),
            'fw_rev': self._big_endian_to_little_endian(packet['command_data'][10:14])
        }
        return board_info

    """
    Private method that calculates the Frame Check Sequence (FCS) for a packet.
    Receives a command without the FCS and EOF bytes in the format [SOF, Packet Info, Packet Length, Command Data].
    Returns the FCS in hexadecimal format.
    """
    def _calculate_fcs(self, command, payload = None):
        packet_info, packet_length = command[0], command[1:2]
        payload = command[2:] if payload is None else payload
        # The FCS is calculated by summing the packet info, packet length and payload bytes
        # and then applying a bitwise AND with 0xFF.
        mask = 0xFF
        fcs = (packet_info + sum(packet_length) + sum(payload)) & mask
        return fcs
    
    """
    Converts a big endian string to a little endian string.
    For example: '1a2b3c' -> '3c2b1a'.
    """
    def _big_endian_to_little_endian(self, big_endian):
        # Break string into 2 characters each
        bytes_array = [big_endian[i:i+2] for i in range(0, len(big_endian), 2)]
        # Reverse the array
        bytes_array.reverse()
        # Concatenate all elements and convert to string
        bytes_array = ''.join(bytes_array)
        return bytes_array

    """
    Changes the state of the sniffer to the specified state.
    """
    def _change_state(self, state):
        self._debug('[INFO] Changing state to {}.'.format(state.name))
        self.state = state
