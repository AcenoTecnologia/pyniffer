import serial
import serial.tools.list_ports
from termcolor import colored
from pcap import Pcap
import utils

class ITSniffer:
    def __init__(self) -> None:
        # Start of Frame e End of Frame
        self.sof = bytes([0x40, 0x53])
        self.eof = bytes([0x40, 0x45])

        # Comandos
        # SOF | Packet Info | Packet Length (0) | Command Data (None) | FCS | EOF
        self.ping_command = bytes([0x40, 0x53, 0x40, 0x00, 0x00, 0x40, 0x40, 0x45])
        self.start_command = bytes([0x40, 0x53, 0x41, 0x00, 0x00, 0x41, 0x40, 0x45])
        self.stop_command = bytes([0x40, 0x53, 0x42, 0x00, 0x00, 0x42, 0x40, 0x45])

        # Is on the documentation but was not implemented in the CC1352P7 sniffer firmware (control_task.h only defines WAIT_FOR_COMMAND, INIT, STARTED and STOPPED states)
        # self.pause_command = bytes([0x40, 0x53, 0x43, 0x00, 0x00, 0x43, 0x40, 0x45])
        # self.resume_command = bytes([0x40, 0x53, 0x44, 0x00, 0x00, 0x44, 0x40, 0x45])


        # SOF | Packet Info | Packet Length (4) | Command Data (4 bytes - 0-1 freq, 2-3 frac.freq) | FCS | EOF
        self.frequency_command = bytes([0x40, 0x53,	0x45, 0x04, 0x00, 0x92, 0x09, 0x00, 0x00, 0xE4, 0x40, 0x45])
        # SOF | Packet Info | Packet Length (1) | Command Data (1 byte - PHY Index) | FCS | EOF
        # PHY index for board CC1352P7
        self.phy_command = bytes([0x40, 0x53, 0x47, 0x01, 0x00, 0x11, 0x59, 0x40, 0x45])


        # Configurações da conexão UART
        self.baudrate = 3000000
        self.port = self.select_serial_port()
        self.data_bits = serial.EIGHTBITS
        self.stop_bits = serial.STOPBITS_ONE
        self.parity = serial.PARITY_NONE

        # Serial
        self.ser = None

        # Arquivo de captura
        self.pcap = Pcap()
        pass


    """
    Método para selecionar a porta serial
    INPUT: None
    OUTPUT: string da porta serial selecionada
    """
    def select_serial_port(self) -> str:
        ports_list = [comport.device for comport in serial.tools.list_ports.comports()]

        print('Lista de portas seriais disponíveis: ')
        for idx, port in enumerate(ports_list):
            print('{0}: {1}'.format(idx, port))
        print('{0}: Entrar com valor manual'.format(len(ports_list)))
        print()

        port = ''
        while True:
            try:
                selected = int(input('Selecione uma porta: '))
            except ValueError:
                print('Valor inválido! Selecione o índice da porta serial')
            else:
                if selected<len(ports_list):
                    print( 'Porta selecionada: {0}'.format(ports_list[selected]) )
                    port = ports_list[selected]
                    break
                if selected==len(ports_list):
                    port = str( input('Digite manualmente a porta serial: ') )
                    break
                else:
                    print( 'Valor fora do intervalo válido!' )
        return port
    
    def select_command(self) -> None:
        while True:
            print('Comandos disponíveis:')
            print('1: PING')
            print('2: START')
            print('3: STOP')
            print('4: Configurar Frequência')
            print('5: Configurar PHY')
            print('6: Sair')
            try:
                selected = int(input('Selecione um comando: '))
            except ValueError:
                print('Valor inválido! Selecione o índice do comando')
            else:
                if selected==1:
                    self.print_response(self.cmd_ping())
                elif selected==2:
                    self.print_response(self.cmd_start())
                    # A partir desse ponto o sniffer começa a capturar pacotes
                    print('Deseja iniciar captura de pacotes em tempo real? (S/N)')
                    if input().upper()=='S':
                        print('Iniciando captura de pacotes...')
                        self.cmd_data_stream()
                elif selected==3:
                    self.print_response(self.cmd_stop())
                elif selected==4:
                    self.print_response(self.cmd_cfg_frequency())
                elif selected==5:
                    self.print_response(self.cmd_cfg_phy())
                elif selected==6:
                    break

                input('Pressione ENTER para continuar...')
        pass

    def open_port(self) -> None:
        self.ser = serial.Serial(port=self.port, baudrate=self.baudrate, bytesize=self.data_bits, stopbits=self.stop_bits, parity=self.parity)
        if self.ser.is_open:
            print(f'Porta Serial {self.port} aberta com sucesso com o Baudrate de {self.baudrate}')
        else:
            print(f'Falha ao abrir {self.port}')
    
    def close_port(self) -> None:
        self.ser.close()
        if not self.ser.is_open:
            print(f'Porta Serial {self.port} fechada com sucesso')
        else:
            print(f'Falha ao fechar {self.port}')
    
    def parse_response(self):
        # Start of Frame | Packet Info | Packet Length | Command data | FCS | End of Frame (EOF)
        # 2B             | 1B          | 2B            | 0-255B       | 1B  | 2B
        buffer = self.ser.read_until(self.eof).hex()
        response = {
            'sof': buffer[0:4],
            'packet_info': buffer[4:6],
            'packet_length': buffer[6:10],
            'command_data': buffer[10:-6],
            'fcs': buffer[-6:-4],
            'eof': buffer[-4:]
        }
        return response

    def print_response(self, response):
        print(colored('[COMMAND] Start of Frame: {0}'.format(utils.stream_to_bytes(response['sof'])), 'yellow'))
        print(colored('[COMMAND] Packet Info: {0}'.format(response['packet_info']), 'yellow'))
        print(colored('[COMMAND] Packet Length: {0}'.format(response['packet_length']), 'yellow'))
        print(colored('[COMMAND] Command Data: {0}'.format(response['command_data']), 'yellow'))
        print(colored('[COMMAND] FCS: {0}'.format(response['fcs']), 'yellow'))
        print(colored('[COMMAND] End of Frame: {0}'.format(response['eof']), 'yellow'))

    # ---------------------- Comandos ----------------------

    def cmd_ping(self) -> str:
        self.ser.write(self.ping_command)
        response = self.parse_response()
        return response
    
    def cmd_start(self) -> str:
        self.ser.write(self.start_command)
        response = self.parse_response()
        return response
        

    def cmd_stop(self) -> str:
        self.ser.write(self.stop_command)
        response = self.parse_response()
        return response
        

    def cmd_cfg_frequency(self) -> str:
        self.ser.write(self.frequency_command)
        response = self.parse_response()
        return response
        

    def cmd_cfg_phy(self) -> str:
        self.ser.write(self.phy_command)
        response = self.parse_response()
        return response


    def cmd_data_stream(self) -> str:
        while True:
            response = self.parse_response()
            # if packetInfo is an error
            if response['packet_info'] == 'C1':
                self.print_package_error(response)
                continue
            self.print_package(response)
            # Write to pcap file
            # self.pcap.write_packet_data(response['command_data'])
        pass

    def print_package_error(self, response):
        # Convert relevant fields to byte representation
        sof = utils.stream_to_bytes(response['sof'])
        packet_info = utils.stream_to_bytes(response['packet_info'])
        packet_length = '' + str(int(utils.stream_to_bytes(response['packet_length'])[2:], 16)) + ' bytes (' + utils.stream_to_bytes(response['packet_length']) + ')'
        fcs = utils.stream_to_bytes(response['fcs'])
        eof = utils.stream_to_bytes(response['eof'])

        # Determine error type
        error = 'RX_BUF_OVERFLOW' if response['command_data'] == '01' else 'UNKNOWN ERROR'

        # Print the formatted package error information
        print(colored('-----------------------------------------------------', 'red'))
        print(colored('[HEADER] Start of Frame: {0}'.format(sof), 'red'))
        print(colored('[HEADER] Packet Info: {0}'.format(packet_info), 'red'))
        print(colored('[HEADER] Packet Length: {0}'.format(packet_length), 'red'))
        print(colored('[ERROR] Error: {0} (Code {1})'.format(error, response['command_data']), 'red'))
        print(colored('[HEADER] FCS: {0}'.format(fcs), 'red'))
        print(colored('[HEADER] End of Frame: {0}'.format(eof), 'red'))
        print(colored('-----------------------------------------------------', 'red'))

    def print_package(self, response):
        # Start of Frame Packet Info Packet Length Error End of Frame (EOF)
        # 2B 1B 2B 1B 2 B
        sof = utils.stream_to_bytes(response['sof'])
        packet_info = utils.stream_to_bytes(response['packet_info'])
        packet_length = '' + str(int(utils.stream_to_bytes(response['packet_length'])[2:], 16)) + ' bytes (' + utils.stream_to_bytes(response['packet_length']) + ')'
        fcs = utils.stream_to_bytes(response['fcs'])
        eof = utils.stream_to_bytes(response['eof'])

        print(colored('-----------------------------------------------------', 'cyan'))
        print(colored('[HEADER] Start of Frame: {0}'.format(sof), 'cyan'))
        print(colored('[HEADER] Packet Info: {0}'.format(packet_info), 'cyan'))
        print(colored('[HEADER] Packet Length: {0}'.format(packet_length), 'cyan'))
        self.print_package_data(response['command_data'])
        print(colored('[HEADER] FCS: {0}'.format(fcs), 'cyan'))
        print(colored('[HEADER] End of Frame: {0}'.format(eof), 'cyan'))
        print(colored('-----------------------------------------------------', 'cyan'))


    def print_package_data(self, data):
        # Convert relevant fields to byte representation
        timestamp = utils.stream_to_bytes(data[0:12])
        payload = utils.stream_to_bytes(data[12:-4])
        rssi = utils.stream_to_bytes(data[-4:-2])
        dbm = utils.rssi_to_dbm(rssi)
        status = utils.stream_to_bytes(data[-2:])

        # Timestamp Payload RSSI Status
        # 6B 0-2049B 1B 1B
        microseconds = int(timestamp[2:], 16)
        miliseconds = microseconds / 1_000  # 1_000_000 microseconds = 1 second
        seconds = miliseconds / 1_000

        # Print the formatted package data information
        print(colored('[DATA] Timestamp: {0} ({1}s after sniffer initialization)'.format(timestamp, seconds), 'blue'))
        print(colored('[DATA] Payload: {0}'.format(payload), 'blue'))
        print(colored('[DATA] RSSI: {0} ({1})'.format(dbm, rssi), 'blue'))
        print(colored('[DATA] Status: {0}'.format(status), 'blue'))