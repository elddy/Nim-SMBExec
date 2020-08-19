#[
    SMB test
]#

#SMB1

import net, strutils, sequtils, HelpUtil, SMB
let hash = toNTLMHash("Aa123456")
var smb = newSMB2("192.168.1.22", ".", "administrator", hash) #"47bf8039a8506cd67c524a03ff84ba4e")
discard smb.connect()

#### TreeConnect

## CheckAccess


discard smb.close()