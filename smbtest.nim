#[
    SMB test
]#

#SMB1

import tables, os, strutils, regex, sequtils, algorithm, SMBv1, SMBv2

import net

let sock = newSocket()

sock.connect("192.168.1.22", 445.Port)
sock.send(getSMBv1NegoPacket())
echo sock.recv(10).toHex()
sock.send(getSMBv2NegoPacket())
echo sock.recv(10).toHex()
sock.send(getSMBv2NTLMNego())
echo sock.recv(100000000).toHex()
sock.close()