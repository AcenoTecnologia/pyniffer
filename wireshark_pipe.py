from abc import ABC, abstractmethod

class WiresharkPipe:

    """
    Opens a pipe for data streaming.
    """
    @abstractmethod
    def open_pipe(self, pipe_name):
        pass

    """
    Waits a connection from the pipe.
    """
    @abstractmethod
    def connect(self):
        pass

    """
    Closes the pipe.
    """
    @abstractmethod
    def close_pipe(self):
        pass

    """
    Writes data to the pipe.
    """
    @abstractmethod
    def write(self, data):
        pass