# Win32 Wireshark named pipes example
# Requires Python for Windows and the Python for Windows Extensions:
# http://www.python.org
# http://sourceforge.net/projects/pywin32/

import win32pipe, win32file
import time
import subprocess

#open Wireshark, configure pipe interface and start capture (not mandatory, you can also do this manually)
wireshark_cmd=['C:\Program Files\Wireshark\Wireshark.exe', r'-i\\.\pipe\wireshark','-k']
proc=subprocess.Popen(wireshark_cmd)

#create the named pipe \\.\pipe\wireshark
pipe = win32pipe.CreateNamedPipe(
    r'\\.\pipe\wireshark',
    win32pipe.PIPE_ACCESS_OUTBOUND,
    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
    1, 65536, 65536,
    300,
    None)

#connect to pipe
win32pipe.ConnectNamedPipe(pipe, None)

#open and read an arbitrary pcap file (file must in same folder than script)
cf = open(r'teste.pcap', 'rb')
data = cf.read()

#wait 2 second (not mandatory, but this let watching data coming trough the pipe)
time.sleep(2)

#send pcap data trough the pipe
win32file.WriteFile(pipe, data)

#then pcap data appears into wireshark