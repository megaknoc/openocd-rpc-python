#!/usr/bin/env python3
"""
OpenOCD RPC example, covered by GNU GPLv3 or later
Copyright (C) 2014 Andreas Ortmann (ortmann@finf.uni-hannover.de)


Example output:
./ocd_rpc_example.py
echo says hi!

target state: halted
target halted due to debug-request, current mode: Thread
xPSR: 0x81000000 pc: 0x000009d6 msp: 0x10001f48

variable @ 0x00000000: 0x10001ff0

variable @ 0x10001ff0: 0xdeadc0de

memory (before): ['0xdeadc0de', '0x00000000', '0xaaaaaaaa', '0x00000023',
'0x00000042', '0x0000ffff']

memory (after): ['0x00000001', '0x00000000', '0xaaaaaaaa', '0x00000023',
'0x00000042', '0x0000ffff']

"""
import socket

def strToHex(data):
    return map(strToHex, data) if isinstance(data, list) else int(data, 16)

def hexify(data):
    return "<None>" if data is None else ("0x%08x" % data)

def compareData(a, b):
    num = 0
    for i, j in zip(a, b):
        if i != j:
            print("found difference (ix=%d): %d != %d" % (num, i, j))

        num += 1


class OpenOcd:
    TOKEN = '\x1a'
    def __init__(self, verbose=False):
        #verbose = True
        self.verbose = verbose
        self.tclRpcIp       = "127.0.0.1"
        self.tclRpcPort     = 6666
        self.bufferSize     = 4096
        self.COMMAND_TOKEN  = 0x1a

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def __enter__(self):
        self.sock.connect((self.tclRpcIp, self.tclRpcPort))
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.send("exit")
        finally:
            self.sock.close()

    def send(self, cmd):
        """Send a command string to TCL RPC. Return the result that was read."""
        data = (cmd + "\x1a").encode("ascii")
        if self.verbose:
            print("<- ", data)

        self.sock.send(data)
        return self._recv()

    def _recv(self):
        """Read from the stream until the token (\x1a) was received."""
        data = bytes()
        while True:
            chunk = self.sock.recv(self.bufferSize)
            data += chunk
            if bytes(self.TOKEN, encoding="ascii") in chunk:
                break

        if self.verbose:
            print("-> ", data)

        data = data.decode("ascii").strip()
        data = data[:-1] # strip trailing \x1a

        return data

    def readVariable(self, address):
        raw = self.send("ocd_mdw 0x%x" % address).split(": ")
        return None if (len(raw) < 2) else strToHex(raw[1])

    def readMemory(self, wordLen, address, n):
        self.send("array unset output") # better to clear the array before
        self.send("mem2array output %d 0x%x %d" % (wordLen, address, n))

        output = self.send("ocd_echo $output").split(" ")

        return [int(output[2*i+1]) for i in range(len(output)//2)]

    def writeVariable(self, address, value):
        assert value is not None
        self.send("mww 0x%x 0x%x" % (address, value))

    def writeMemory(self, wordLen, address, n, data):
        array = " ".join(["%d 0x%x" % (a, b) for a, b in enumerate(data)])

        self.send("array unset myArray") # better to clear the array before
        self.send("array set myArray { %s }" % array)
        self.send("array2mem myArray 0x%x %s %d" % (wordLen, address, n))

if __name__ == "__main__":

    def show(*args):
        print(*args, end="\n\n")

    with OpenOcd() as ocd:
        ocd.send("reset")

        show(ocd.send("ocd_echo \"echo says hi!\"")[:-1])

        show(ocd.send("capture \"ocd_halt\"")[:-1])

        addr = 0
        value = ocd.readVariable(addr)
        show("variable @ %s: %s" % (hexify(addr), hexify(value)))
        addr = value

        ocd.writeVariable(addr, 0xdeadc0de)
        show("variable @ %s: %s" % (hexify(addr), hexify(ocd.readVariable(addr))))

        data = [1, 0, 0xaaaaaaaa, 0x23, 0x42, 0xffff]
        wordlen = 32
        n = len(data)

        read = ocd.readMemory(wordlen, addr, n)
        show("memory (before):", list(map(hexify, read)))

        ocd.writeMemory(wordlen, addr, n, data)

        read = ocd.readMemory(wordlen, addr, n)
        show("memory (after):", list(map(hexify, read)))

        compareData(read, data)

        ocd.send("resume")

