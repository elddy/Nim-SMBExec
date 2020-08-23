#[
    SMBv2 Helper
]#
import tables, HelpUtil

proc NewPacketSMB2TreeConnectRequest*(Buffer: seq[byte]): OrderedTable[string, seq[byte]] =

    let path_length = getBytes(Buffer.len)[..1]

    var SMB2TreeConnectRequest = initOrderedTable[string, seq[byte]]()
    SMB2TreeConnectRequest.add("StructureSize",@[0x09.byte,0x00.byte])
    SMB2TreeConnectRequest.add("Reserved",@[0x00.byte,0x00.byte])
    SMB2TreeConnectRequest.add("PathOffset",@[0x48.byte,0x00.byte])
    SMB2TreeConnectRequest.add("PathLength",path_length)
    SMB2TreeConnectRequest.add("Buffer",Buffer)

    return SMB2TreeConnectRequest

proc NewPacketSMB2CreateRequestFile*(NamedPipe: seq[byte]): OrderedTable[string, seq[byte]] =
    
    let name_length = getBytes(NamedPipe.len)[..1]

    var SMB2CreateRequestFile = initOrderedTable[string, seq[byte]]()
    SMB2CreateRequestFile.add("StructureSize",@[0x39.byte,0x00.byte])
    SMB2CreateRequestFile.add("Flags",@[0x00.byte])
    SMB2CreateRequestFile.add("RequestedOplockLevel",@[0x00.byte])
    SMB2CreateRequestFile.add("Impersonation",@[0x02.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("SMBCreateFlags",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("Reserved",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("DesiredAccess",@[0x03.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("FileAttributes",@[0x80.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("ShareAccess",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("CreateDisposition",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("CreateOptions",@[0x40.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("NameOffset",@[0x78.byte,0x00.byte])
    SMB2CreateRequestFile.add("NameLength",name_length)
    SMB2CreateRequestFile.add("CreateContextsOffset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("CreateContextsLength",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CreateRequestFile.add("Buffer",NamedPipe)

    return SMB2CreateRequestFile

proc NewPacketSMB2ReadRequest*(FileID: seq[byte]): OrderedTable[string, seq[byte]] =

    var SMB2ReadRequest = initOrderedTable[string, seq[byte]]()
    SMB2ReadRequest.add("StructureSize",@[0x31.byte,0x00.byte])
    SMB2ReadRequest.add("Padding",@[0x50.byte])
    SMB2ReadRequest.add("Flags",@[0x00.byte])
    SMB2ReadRequest.add("Length",@[0x00.byte,0x00.byte,0x10.byte,0x00.byte])
    SMB2ReadRequest.add("Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2ReadRequest.add("FileID",FileID)
    SMB2ReadRequest.add("MinimumCount",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2ReadRequest.add("Channel",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2ReadRequest.add("RemainingBytes",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2ReadRequest.add("ReadChannelInfoOffset",@[0x00.byte,0x00.byte])
    SMB2ReadRequest.add("ReadChannelInfoLength",@[0x00.byte,0x00.byte])
    SMB2ReadRequest.add("Buffer",@[0x30.byte])

    return SMB2ReadRequest

proc NewPacketSMB2WriteRequest*(FileID: seq[byte], RPCLength: int): OrderedTable[string, seq[byte]] =

    let write_length = getBytes(RPCLength)

    var SMB2WriteRequest = initOrderedTable[string, seq[byte]]()
    SMB2WriteRequest.add("StructureSize",@[0x31.byte,0x00.byte])
    SMB2WriteRequest.add("DataOffset",@[0x70.byte,0x00.byte])
    SMB2WriteRequest.add("Length",write_length)
    SMB2WriteRequest.add("Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2WriteRequest.add("FileID",FileID)
    SMB2WriteRequest.add("Channel",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2WriteRequest.add("RemainingBytes",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2WriteRequest.add("WriteChannelInfoOffset",@[0x00.byte,0x00.byte])
    SMB2WriteRequest.add("WriteChannelInfoLength",@[0x00.byte,0x00.byte])
    SMB2WriteRequest.add("Flags",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])

    return SMB2WriteRequest

proc NewPacketSMB2CloseRequest*(FileID: seq[byte]): OrderedTable[string, seq[byte]] =

    var SMB2CloseRequest = initOrderedTable[string, seq[byte]]()
    SMB2CloseRequest.add("StructureSize",@[0x18.byte,0x00.byte])
    SMB2CloseRequest.add("Flags",@[0x00.byte,0x00.byte])
    SMB2CloseRequest.add("Reserved",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2CloseRequest.add("FileID",FileID)

    return SMB2CloseRequest

proc NewPacketSMB2TreeDisconnectRequest*(): OrderedTable[string, seq[byte]] =    
    
    var SMB2TreeDisconnectRequest = initOrderedTable[string, seq[byte]]()
    SMB2TreeDisconnectRequest.add("StructureSize",@[0x04.byte,0x00.byte])
    SMB2TreeDisconnectRequest.add("Reserved",@[0x00.byte,0x00.byte])

    return SMB2TreeDisconnectRequest

proc NewPacketSMB2SessionLogoffRequest*(): OrderedTable[string, seq[byte]] =    
    
    var SMB2SessionLogoffRequest = initOrderedTable[string, seq[byte]]()
    SMB2SessionLogoffRequest.add("StructureSize",@[0x04.byte,0x00.byte])
    SMB2SessionLogoffRequest.add("Reserved",@[0x00.byte,0x00.byte])

    return SMB2SessionLogoffRequest