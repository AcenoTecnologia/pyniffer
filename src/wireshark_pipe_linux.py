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

import os
from wireshark_pipe import WiresharkPipe
import errno

class LinuxWiresharkPipe(WiresharkPipe):
    def __init__(self):
        self.pipe_name = None
        self.pipe_path = None
        self.pipe = None

    def open_pipe(self, pipe_name):
        self.pipe_name = pipe_name
        self.pipe_path = '/tmp/{}'.format(pipe_name)
        
        try:
            os.mkfifo(self.pipe_path)
        except OSError as oe:
            if oe.errno != errno.EEXIST:
                raise

    def connect(self):
        self.pipe = open(self.pipe_path, 'wb')

    def close_pipe(self):
        if self.pipe:
            self.pipe.close()
            os.remove(self.pipe_path)

    def write(self, data):
        if self.pipe:
            self.pipe.write(data)
            self.pipe.flush()