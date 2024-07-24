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

from wireshark_pipe import WiresharkPipe
import win32pipe, win32file, os

class WindowsWiresharkPipe(WiresharkPipe):
    def __init__(self):
        self.pipe_name = None
        self.pipe_path = None
        self.pipe = None
        pass

    def open_pipe(self, pipe_name):
        self.pipe_name = pipe_name
        self.pipe_path = r'\\.\pipe\{}'.format(pipe_name)
        self.pipe = win32pipe.CreateNamedPipe(
            self.pipe_path,
            win32pipe.PIPE_ACCESS_OUTBOUND,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536,
            300,
            None)
        pass

    def connect(self):
        win32pipe.ConnectNamedPipe(self.pipe, None)
        pass

    def close_pipe(self):
        # Close the pipe handle
        if self.pipe:
            win32file.CloseHandle(self.pipe)
        pass

    def write(self, data):
        win32file.WriteFile(self.pipe, data)
        pass