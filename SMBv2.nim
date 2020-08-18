#[
    SMBv2 Negotiate
]#

import tables, os, strutils, regex, sequtils, algorithm, NTLM, nativesockets, random
from hmac import hmac_md5
import md5
import nimSHA2 except toHex

randomize()

var session_ID: seq[byte]

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    # for b in 0..a.len - 1:
    #     if a[b][0] == '0':
    #         a[b] = substr(a[b], 1)
    result = "0x" & a.join(",0x")

proc convertToByteArray(tab: OrderedTable): seq[byte] =
    for v in tab.values:
        result.add(v)

proc GetUInt16DataLength(start: int, data: seq[byte]): int =
    let data_length = ($(data[start])).parseInt()

    return data_length

proc userOrDomainToByteArray(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)
        result.add(0x00.byte)

proc stringToByteArray(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToByteArray(str: string): seq[byte] =
    for i in str.hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToNormalHex*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in a:
        if b != "00":
            result.add(b)

proc NewPacketSMB2Header(command: seq[byte], creditRequest: seq[byte], signing: bool, messageID: seq[byte], processID, treeID, sessionID: seq[byte]): OrderedTable[string, seq[byte]] =
    var flags: seq[byte]
    if signing:
        flags = @[0x08.byte,0x00.byte,0x00.byte,0x00.byte]
    else:
        flags = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    
    let message_ID = messageID.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])
    var process_ID = processID
    process_ID = processID.concat(@[0x00.byte,0x00.byte])

    # let message_ID = messageID.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])
    var SMB2Header = initOrderedTable[string, seq[byte]]() # $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary

    SMB2Header.add("ProtocolID", @[0xfe.byte,0x53.byte,0x4d.byte,0x42.byte]) # $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    SMB2Header.add("StructureSize",@[0x40.byte, 0x00.byte]) # $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    SMB2Header.add("CreditCharge",@[0x01.byte,0x00.byte]) # $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    SMB2Header.add("ChannelSequence",@[0x00.byte,0x00.byte]) # $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    SMB2Header.add("Reserved",@[0x00.byte,0x00.byte]) # $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    SMB2Header.add("Command", command) # $SMB2Header.Add("Command",$Command)
    SMB2Header.add("CreditRequest", creditRequest) # $SMB2Header.Add("CreditRequest",$CreditRequest)
    SMB2Header.add("Flags", flags) # $SMB2Header.Add("Flags",$flags)
    SMB2Header.add("NextCommand",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte]) # $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    SMB2Header.add("MessageID", message_ID) # $SMB2Header.Add("MessageID",$message_ID)
    SMB2Header.add("ProcessID", process_ID) # $SMB2Header.Add("ProcessID",$ProcessID)
    SMB2Header.add("TreeID", treeID) # $SMB2Header.Add("TreeID",$TreeID)
    SMB2Header.add("SessionID", sessionID) # $SMB2Header.Add("SessionID",$SessionID)
    SMB2Header.add("Signature", @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]) # $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return SMB2Header

proc NewPacketSMB2NegotiateProtocolRequest(): OrderedTable[string, seq[byte]] =

    var SMB2NegotiateProtocolRequest = initOrderedTable[string, seq[byte]]() # $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    SMB2NegotiateProtocolRequest.add("StructureSize",@[0x24.byte,0x00.byte])  
    SMB2NegotiateProtocolRequest.add("DialectCount",@[0x02.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("SecurityMode",@[0x01.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Reserved",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Capabilities",@[0x40.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("ClientGUID",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("NegotiateContextOffset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("NegotiateContextCount",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Reserved2",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Dialect",@[0x02.byte,0x02.byte])
    SMB2NegotiateProtocolRequest.add("Dialect2",@[0x10.byte,0x02.byte])
    return SMB2NegotiateProtocolRequest

proc NewPacketNetBIOSSessionService(headerLength, dataLength: int): OrderedTable[string, seq[byte]] =
    var NetBIOSSessionService = initOrderedTable[string, seq[byte]]() # $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary

    var length: seq[byte]
    if (headerLength + dataLength).toHex().hexToNormalHex().hexToByteArray().len == 1:
        length.add(0x00.byte)    
    length.add(0x00.byte)
    length = length.concat((headerLength + dataLength).toHex().hexToNormalHex().hexToByteArray())
    NetBIOSSessionService.add("MessageType", @[0x00.byte])
    NetBIOSSessionService.add("Length", length)
    return NetBIOSSessionService


proc getSMBv2NegoPacket*(): string =
    let process_ID = getCurrentProcessId().toHex().split("00").join()
    var reversing = (process_ID.hexToPSShellcode().split(","))

    let rev = reversed(reversing[..(reversing.len() - 1)])
    var revBytes: seq[byte]
    for b in rev:
        revBytes.add((b.parseHexInt()).byte)
    let 
        tree_ID = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
        session_ID = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]

    let 
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], false, @[messageID.byte], revBytes, tree_ID, session_ID)
        smb2Data = convertToByteArray NewPacketSMB2NegotiateProtocolRequest()
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()


proc getSMBv2NTLMNego*(signing: bool): string =
    inc messageID
    let process_ID = getCurrentProcessId().toHex().split("00").join()
    var reversing = (process_ID.hexToPSShellcode().split(","))

    let rev = reversed(reversing[..(reversing.len() - 1)])
    var revBytes: seq[byte]
    for b in rev:
        revBytes.add((b.parseHexInt()).byte)
    let 
        tree_ID = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
        session_ID = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    
    var negotiate_flags: seq[byte]
    if signing:
        negotiate_flags = @[0x15.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing true
    else:
        negotiate_flags = @[0x05.byte,0x80.byte,0x08.byte,0xa0.byte] # Signing false
    
    let
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x01.byte,0x00.byte], @[0x1f.byte,0x00.byte], false, @[messageID.byte], revBytes, tree_ID, session_ID)
        NTLMSSPnegotiate = convertToByteArray NewPacketNTLMSSPNegotiate(negotiate_flags, @[])
        smb2Data = convertToByteArray NewPacketSMB2SessionSetupRequest(NTLMSSPnegotiate)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()

proc getSMBv2NTLMSSP*(client_receive: string, hash: string, domain: string, username: string, signing: bool): seq[byte] =
    
    let ntlmSSP = client_receive.toHex()
    let ntlmSSP_index = ntlmSSP.find("4E544C4D53535000")
    let ntlmSSP_bytes_index = (ntlmSSP_index / 2).toInt()
    let domain_length = GetUInt16DataLength(ntlmSSP_bytes_index + 12, client_receive.stringToByteArray())
    let target_length = GetUInt16DataLength(ntlmSSP_bytes_index + 40, client_receive.stringToByteArray())

    session_ID = client_receive[44..51].stringToByteArray()
    let ntlm_challenge = (client_receive[(ntlmSSP_bytes_index + 24)..(ntlmSSP_bytes_index + 31)]).stringToByteArray()
    
    let target_details = client_receive[(ntlmSSP_bytes_index + 56 + domain_length)..(ntlmSSP_bytes_index + 55 + domain_length + target_length)]
    let target_time_bytes = (target_details[(len(target_details) - 12)..(len(target_details) - 5)]).stringToByteArray()

    var ntlm_hash_bytes = hash.parseHexStr()

    let auth_hostname = getHostname()
    let auth_hostname_bytes = auth_hostname.userOrDomainToByteArray()
    let auth_domain_bytes = domain.userOrDomainToByteArray()
    let auth_username_bytes = username.userOrDomainToByteArray()

    let auth_domain_length = @[len(auth_domain_bytes).byte, 0x00.byte]
    let auth_username_length = @[len(auth_username_bytes).byte, 0x00.byte]
    let auth_hostname_length = @[len(auth_hostname_bytes).byte, 0x00.byte]


    let auth_domain_offset = @[0x40.byte,0x00.byte,0x00.byte,0x00.byte]
    let auth_username_offset = @[(len(auth_domain_bytes) + 64).byte,0x00.byte,0x00.byte,0x00.byte]
    let auth_hostname_offset = @[(len(auth_domain_bytes) + len(auth_username_bytes) + 64).byte,0x00.byte,0x00.byte,0x00.byte]

    let auth_LM_offset = @[(len(auth_domain_bytes) + len(auth_username_bytes) + len(auth_hostname_bytes) + 64).byte,0x00.byte,0x00.byte,0x00.byte]
    
    let auth_NTLM_offset = @[(len(auth_domain_bytes) + len(auth_username_bytes) + len(auth_hostname_bytes) + 88).byte,0x00.byte,0x00.byte,0x00.byte]


    let hmac_MD5_key = ntlm_hash_bytes
    let username_and_target = username.toUpper()
    let username_and_target_bytes = username_and_target.userOrDomainToByteArray().concat(auth_domain_bytes)
    
    var 
        newData: seq[string]
    for j in username_and_target_bytes:
        newData.add j.toHex().parseHexStr()

    let ntlmv2_hash = hmac_md5(hmac_MD5_key, newData.join())

    var client_challenge: string
    for i in 1..8:
        client_challenge.add(rand(1..255).toHex().hexToNormalHex())
    

    let client_challenge_bytes = client_challenge.hexToByteArray()

    let security_blob_bytes = @[0x01.byte, 0x01.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte].concat(target_time_bytes).concat(client_challenge_bytes).concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte]).concat(target_details.stringToByteArray()).concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])
    
    
    let server_challenge_and_security_blob_bytes = ntlm_challenge.concat(security_blob_bytes)

    var 
        newBlob: seq[string]
    for j in server_challenge_and_security_blob_bytes:
        newBlob.add j.toHex().parseHexStr()

    let ntlmv2_response = hmac_md5(($ntlmv2_hash).parseHexStr(), newBlob.join())
    
    var 
        session_base_key: MD5Digest
        session_key: MD5Digest
        HMAC_SHA256: SHA256Digest

    if signing:
        session_base_key = hmac_md5(($ntlmv2_hash).parseHexStr(), ($ntlmv2_response).parseHexStr())
        session_key = session_base_key
        var count = 0
        for i in $session_key:
            HMAC_SHA256[count] = i
            inc count
    var 
        new_ntlmv2_response = toSeq(ntlmv2_response).concat(security_blob_bytes)
        ntlmv2_response_length = @[len(new_ntlmv2_response).byte, 0x00.byte]
        session_key_offset = (auth_domain_bytes.len() + auth_username_bytes.len() + auth_hostname_bytes.len() + new_ntlmv2_response.len() + 88).toHex().hexToNormalHex().hexToByteArray()
        session_key_length = @[0x00.byte, 0x00.byte]
    
    session_key_offset = session_key_offset.reversed().concat(session_key_length)

    var NTLMSSP_response = @[0x4e.byte,0x54.byte,0x4c.byte,0x4d.byte,0x53.byte,0x53.byte,0x50.byte,0x00.byte, 0x03.byte,0x00.byte,0x00.byte,0x00.byte,0x18.byte,0x00.byte,0x18.byte,0x00.byte]
    NTLMSSP_response.add(auth_LM_offset)
    NTLMSSP_response = NTLMSSP_response.concat(ntlmv2_response_length)
    NTLMSSP_response = NTLMSSP_response.concat(ntlmv2_response_length)
    NTLMSSP_response.add(auth_NTLM_offset)
    NTLMSSP_response.add(auth_domain_length)
    NTLMSSP_response.add(auth_domain_length)
    NTLMSSP_response = NTLMSSP_response.concat(auth_domain_offset)
    NTLMSSP_response.add(auth_username_length)
    NTLMSSP_response.add(auth_username_length)
    NTLMSSP_response.add(auth_username_offset)
    NTLMSSP_response.add(auth_hostname_length)
    NTLMSSP_response.add(auth_hostname_length)
    NTLMSSP_response.add(auth_hostname_offset)
    NTLMSSP_response = NTLMSSP_response.concat(session_key_length)
    NTLMSSP_response = NTLMSSP_response.concat(session_key_length)
    NTLMSSP_response = NTLMSSP_response.concat(session_key_offset)
    var negotiate_flags: seq[byte]
    if signing:
        negotiate_flags = @[0x15.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing true
    else:
        negotiate_flags = @[0x05.byte,0x80.byte,0x08.byte,0xa0.byte] # Signing false
    NTLMSSP_response = NTLMSSP_response.concat(negotiate_flags)
    NTLMSSP_response = NTLMSSP_response.concat(auth_domain_bytes)
    NTLMSSP_response = NTLMSSP_response.concat(auth_username_bytes)
    NTLMSSP_response = NTLMSSP_response.concat(auth_hostname_bytes)
    NTLMSSP_response = NTLMSSP_response.concat(@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    NTLMSSP_response = NTLMSSP_response.concat(new_ntlmv2_response)

    return NTLMSSP_response

proc getSMBv2NTLMAuth*(NTLMSSP_response: seq[byte]): string =
    inc messageID
    let process_ID = getCurrentProcessId().toHex().split("00").join()
    var reversing = (process_ID.hexToPSShellcode().split(","))

    let rev = reversed(reversing[..(reversing.len() - 1)])
    var revBytes: seq[byte]
    for b in rev:
        revBytes.add((b.parseHexInt()).byte)
    let 
        tree_ID = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]

    echo messageID.toHex().hexToNormalHex().hexToByteArray()

    let 
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x01.byte,0x00.byte], @[0x01.byte,0x00.byte], false, @[messageID.byte], revBytes, tree_ID, session_ID)
        NTLMSSP_auth = convertToByteArray NewPacketNTLMSSPAuth(NTLMSSP_response)
        smb2Data = convertToByteArray NewPacketSMB2SessionSetupRequest(NTLMSSP_auth)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)

    ## Make full packet
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()


when isMainModule:
    let 
        key = "47bf8039a8506cd67c524a03ff84ba4e".parseHexStr() # Good
        data = "ADMINISTRATOR".userOrDomainToByteArray().concat(".".userOrDomainToByteArray()) # Good
    var 
        newData: seq[string]
    for j in data:
        newData.add j.toHex().parseHexStr()
    echo "Key: ", key
    echo "Data: ", newData
    echo ($hmac_md5(key, newData.join())).hexToByteArray()


