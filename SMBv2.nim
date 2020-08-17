#[
    SMBv2 Negotiate
]#

import tables, os, strutils, regex, sequtils, algorithm, NTLM

var messageID = 1

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in 0..a.len - 1:
        if a[b][0] == '0':
            a[b] = substr(a[b], 1)
    result = "0x" & a.join(",0x")

proc NewPacketSMB2Header(command: seq[byte], creditRequest: seq[byte], signing: bool, messageID: seq[byte], processID, treeID, sessionID: seq[byte]): OrderedTable[string, seq[byte]] =
    var flags: seq[byte]
    if signing:
        flags = @[0x08.byte,0x00.byte,0x00.byte,0x00.byte]
    else:
        flags = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    
    let message_ID = messageID.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])
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
    SMB2Header.add("ProcessID", processID) # $SMB2Header.Add("ProcessID",$ProcessID)
    SMB2Header.add("TreeID", treeID) # $SMB2Header.Add("TreeID",$TreeID)
    SMB2Header.add("SessionID", sessionID) # $SMB2Header.Add("SessionID",$SessionID)
    SMB2Header.add("Signature", @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]) # $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return SMB2Header

proc NewPacketSMB2NegotiateProtocolRequest(): OrderedTable[string, seq[byte]] =

    var SMB2NegotiateProtocolRequest = initOrderedTable[string, seq[byte]]() # $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    SMB2NegotiateProtocolRequest.add("StructureSize",@[0x24.byte,0x00.byte])  
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

    let temp = (headerLength + dataLength).toHex()
    var length: seq[byte]
    length.add(0x00.byte)
    length.add(0x00.byte)
    length.add((temp.split("00").join().hexToPSShellcode()).parseHexInt().byte)
    NetBIOSSessionService.add("MessageType", @[0x00.byte])
    NetBIOSSessionService.add("Length", length)
    return NetBIOSSessionService

proc convertToByteArray(tab: OrderedTable): seq[byte] =
    for v in tab.values:
        result.add(v)

proc GetUInt16DataLength(start: int, data: seq[byte]): uint16 =
    let num = ($(data[start]) & $(data[start+1])).parseInt()
    let data_length: uint16 = uint16(num)

    return data_length

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
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], false, @[message_ID.byte], revBytes, tree_ID, session_ID)
        smb2Data = convertToByteArray NewPacketSMB2NegotiateProtocolRequest()
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()


proc getSMBv2NTLMNego*(): string =
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
        negotiate_flags = @[0x15.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing true
        # negotiate_flags = @[0x05.byte,0x80.byte,0x08.byte,0xa0.byte] # Signing false
    let
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x01.byte,0x00.byte], @[0x1f.byte,0x00.byte], false, @[message_ID.byte], revBytes, tree_ID, session_ID)
        NTLMSSPnegotiate = convertToByteArray NewPacketNTLMSSPNegotiate(negotiate_flags, @[])
        smb2Data = convertToByteArray NewPacketSMB2SessionSetupRequest(NTLMSSPnegotiate)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    # echo (strPacket).parseHexStr()
    return (strPacket).parseHexStr()

proc getSMBv2NTLMSSP*(client_receive: string): seq[byte] =
    
    let ntlmSSP = client_receive.toHex()
    let ntlmSSP_index = ntlmSSP.find("4E544C4D53535000")
    let ntlmSSP_bytes_index = ntlmSSP_index / 2 
    let domain_length = GetUInt16DataLength(ntlmSSP_bytes_index + 12, client_receive)
