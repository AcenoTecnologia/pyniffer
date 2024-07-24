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

import platform

class WiresharkPipeFactory:
    """
    Factory class to create a WiresharkPipe object.
    Returns a WiresharkPipe object according to the platform.
    """
    @staticmethod
    def create_wireshark_pipe():
        if platform.system() == 'Windows':
            from wireshark_pipe_win import WindowsWiresharkPipe
            return WindowsWiresharkPipe()
        if platform.system() == 'Linux':
            from wireshark_pipe_linux import LinuxWiresharkPipe
            return LinuxWiresharkPipe()