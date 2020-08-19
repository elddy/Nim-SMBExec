#[
    SMB test
]#

#SMB1

import net, strutils, sequtils, HelpUtil, SMB
# let hash = toNTLMHash("Aa123456")
var smb = newSMB2("192.168.1.22", ".", "administrator", "47bf8039a8506cd67c524a03ff84ba4e") #"47bf8039a8506cd67c524a03ff84ba4e")
let response = smb.connect()
discard smb.exec("whoami", response)
#### TreeConnect

## CheckAccess


discard smb.close()