#[
    SMBv1 Negotiate
]#

import tables, os, strutils, regex, sequtils, algorithm

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in 0..a.len - 1:
        if a[b][0] == '0':
            a[b] = substr(a[b], 1)
    result = "0x" & a.join(",0x")

proc NewPacketSMBHeader(command, flags1, flags2, treeID, processID, userID: seq[byte]): OrderedTable[string, seq[byte]] =
    
    var SMBHeader = initOrderedTable[string, seq[byte]]() # $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    let process = processID[0..1] # $ProcessID = $ProcessID[0,1]

    SMBHeader.add("Protocol", @[0xff.byte,0x53.byte,0x4d.byte,0x42.byte])# $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    SMBHeader.add("Command", command)# $SMBHeader.Add("Command",$Command)
    SMBHeader.add("ErrorClass", @[0x00.byte])# $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    SMBHeader.add("Reserved", @[0x00.byte])# $SMBHeader.Add("Reserved",[Byte[]](0x00))
    SMBHeader.add("ErrorCode", @[0x00.byte, 0x00.byte])# $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    SMBHeader.add("Flags", flags1)# $SMBHeader.Add("Flags",$Flags)
    SMBHeader.add("Flags2", flags2)# $SMBHeader.Add("Flags2",$Flags2)
    SMBHeader.add("ProcessIDHigh", @[0x00.byte,0x00.byte])# $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    SMBHeader.add("Signature", @[0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte,0x00.byte])# $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    SMBHeader.add("Reserved2", @[0x00.byte,0x00.byte])# $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    SMBHeader.add("TreeID", treeID)# $SMBHeader.Add("TreeID",$TreeID)
    SMBHeader.add("ProcessID",process)# $SMBHeader.Add("ProcessID",$ProcessID)
    SMBHeader.add("UserID",userID)# $SMBHeader.Add("UserID",$UserID)
    SMBHeader.add("MultiplexID", @[0x00.byte,0x00.byte])# $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))
    return SMBHeader

proc NewPacketSMBNegotiateProtocolRequest(version: string): OrderedTable[string, seq[byte]] =
    var byte_count: seq[byte]
    if version == "SMB1":
        byte_count = @[0x0c.byte, 0x00.byte]
    else:
        byte_count = @[0x22.byte, 0x00.byte]
    
    var SMBNegotiateProtocolRequest = initOrderedTable[string, seq[byte]]() # $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary

    SMBNegotiateProtocolRequest.add("WordCount", @[0x00.byte]) #$SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    SMBNegotiateProtocolRequest.add("ByteCount", byte_count) #     $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat", @[0x02.byte]) #     $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name",@[0x4e.byte,0x54.byte,0x20.byte,0x4c.byte,0x4d.byte,0x20.byte,0x30.byte,0x2e.byte,0x31.byte,0x32.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if version != "SMB1":
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat2",@[0x02.byte]) #  $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name2",@[0x53.byte,0x4d.byte,0x42.byte,0x20.byte,0x32.byte,0x2e.byte,0x30.byte,0x30.byte,0x32.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat3",@[0x02.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name3",@[0x53.byte,0x4d.byte,0x42.byte,0x20.byte,0x32.byte,0x2e.byte,0x3f.byte,0x3f.byte,0x3f.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))

    return SMBNegotiateProtocolRequest

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

proc getSMBv1NegoPacket*(): string =
    let process_ID = getCurrentProcessId().toHex().split("00").join()
    var reversing = (process_ID.hexToPSShellcode().split(","))

    let rev = reversed(reversing[..(reversing.len() - 1)])
    var revBytes: seq[byte]
    for b in rev:
        revBytes.add((b.parseHexInt()).byte)

    let 
        smbHeader = convertToByteArray NewPacketSMBHeader(@[0x72.byte], @[0x18.byte], @[0x01.byte,0x48.byte], @[0xff.byte,0xff.byte], revBytes, @[0x00.byte,0x00.byte])
        smbData = convertToByteArray NewPacketSMBNegotiateProtocolRequest("SMB2.1")
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smbHeader.len(), smbData.len())
        fullPacket = concat(netBiosSession, smbHeader, smbData)
    
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()


