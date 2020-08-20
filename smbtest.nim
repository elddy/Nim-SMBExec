#[
    SMB test
]#

#SMB1

import net, strutils, sequtils, HelpUtil, SMB
let hash = toNTLMHash("לאלנחש192837")
var smb = newSMB2("192.168.1.5", ".", "administrator", "f8011acf167c3261d807ca5a5301a94e") #"47bf8039a8506cd67c524a03ff84ba4e")
let response = smb.connect()
discard smb.exec("whoami", response)
#### TreeConnect

## CheckAccess


discard smb.close()