#[
    RPC
]#
import tables, HelpUtil

proc NewPacketRPCBind*(FragLength: seq[byte],CallID: int,NumCtxItems: seq[byte],ContextID: seq[byte],UUID: seq[byte],UUIDVersion: seq[byte]): OrderedTable[string, seq[byte]] =

    let call_ID: seq[byte] = getBytes(CallID)

    var RPCBind = initOrderedTable[string, seq[byte]]()
    RPCBind.add("Version",@[0x05.byte])
    RPCBind.add("VersionMinor",@[0x00.byte])
    RPCBind.add("PacketType",@[0x0b.byte])
    RPCBind.add("PacketFlags",@[0x03.byte])
    RPCBind.add("DataRepresentation",@[0x10.byte,0x00.byte,0x00.byte,0x00.byte])
    RPCBind.add("FragLength",FragLength)
    RPCBind.add("AuthLength",@[0x00.byte,0x00.byte])
    RPCBind.add("CallID",call_ID)
    RPCBind.add("MaxXmitFrag",@[0xb8.byte,0x10.byte])
    RPCBind.add("MaxRecvFrag",@[0xb8.byte,0x10.byte])
    RPCBind.add("AssocGroup",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    RPCBind.add("NumCtxItems",NumCtxItems)
    RPCBind.add("Unknown",@[0x00.byte,0x00.byte,0x00.byte])
    RPCBind.add("ContextID",ContextID)
    RPCBind.add("NumTransItems",@[0x01.byte])
    RPCBind.add("Unknown2",@[0x00.byte])
    RPCBind.add("Interface",UUID)
    RPCBind.add("InterfaceVer",UUIDVersion)
    RPCBind.add("InterfaceVerMinor",@[0x00.byte,0x00.byte])
    RPCBind.add("TransferSyntax",@[0x04.byte,0x5d.byte,0x88.byte,0x8a.byte,0xeb.byte,0x1c.byte,0xc9.byte,0x11.byte,0x9f.byte,0xe8.byte,0x08.byte,0x00.byte,0x2b.byte,0x10.byte,0x48.byte,0x60.byte])
    RPCBind.add("TransferSyntaxVer",@[0x02.byte,0x00.byte,0x00.byte,0x00.byte])

    if NumCtxItems[0] == 2:
    
        RPCBind.add("ContextID2",@[0x01.byte,0x00.byte])
        RPCBind.add("NumTransItems2",@[0x01.byte])
        RPCBind.add("Unknown3",@[0x00.byte])
        RPCBind.add("Interface2",UUID)
        RPCBind.add("InterfaceVer2",UUIDVersion)
        RPCBind.add("InterfaceVerMinor2",@[0x00.byte,0x00.byte])
        RPCBind.add("TransferSyntax2",@[0x2c.byte,0x1c.byte,0xb7.byte,0x6c.byte,0x12.byte,0x98.byte,0x40.byte,0x45.byte,0x03.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("TransferSyntaxVer2",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
    
    elif NumCtxItems[0] == 3:
    
        RPCBind.add("ContextID2",@[0x01.byte,0x00.byte])
        RPCBind.add("NumTransItems2",@[0x01.byte])
        RPCBind.add("Unknown3",@[0x00.byte])
        RPCBind.add("Interface2",UUID)
        RPCBind.add("InterfaceVer2",UUIDVersion)
        RPCBind.add("InterfaceVerMinor2",@[0x00.byte,0x00.byte])
        RPCBind.add("TransferSyntax2",@[0x33.byte,0x05.byte,0x71.byte,0x71.byte,0xba.byte,0xbe.byte,0x37.byte,0x49.byte,0x83.byte,0x19.byte,0xb5.byte,0xdb.byte,0xef.byte,0x9c.byte,0xcc.byte,0x36.byte])
        RPCBind.add("TransferSyntaxVer2",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("ContextID3",@[0x02.byte,0x00.byte])
        RPCBind.add("NumTransItems3",@[0x01.byte])
        RPCBind.add("Unknown4",@[0x00.byte])
        RPCBind.add("Interface3",UUID)
        RPCBind.add("InterfaceVer3",UUIDVersion)
        RPCBind.add("InterfaceVerMinor3",@[0x00.byte,0x00.byte])
        RPCBind.add("TransferSyntax3",@[0x2c.byte,0x1c.byte,0xb7.byte,0x6c.byte,0x12.byte,0x98.byte,0x40.byte,0x45.byte,0x03.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("TransferSyntaxVer3",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
    

    if call_ID[0] == 3:
    
        RPCBind.add("AuthType",@[0x0a.byte])
        RPCBind.add("AuthLevel",@[0x02.byte])
        RPCBind.add("AuthPadLength",@[0x00.byte])
        RPCBind.add("AuthReserved",@[0x00.byte])
        RPCBind.add("ContextID3",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("Identifier",@[0x4e.byte,0x54.byte,0x4c.byte,0x4d.byte,0x53.byte,0x53.byte,0x50.byte,0x00.byte])
        RPCBind.add("MessageType",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("NegotiateFlags",@[0x97.byte,0x82.byte,0x08.byte,0xe2.byte])
        RPCBind.add("CallingWorkstationDomain",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("CallingWorkstationName",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
        RPCBind.add("OSVersion",@[0x06.byte,0x01.byte,0xb1.byte,0x1d.byte,0x00.byte,0x00.byte,0x00.byte,0x0f.byte])
    

    return RPCBind

proc NewPacketRPCRequest*(Flags: seq[byte],ServiceLength: int,AuthLength: int,AuthPadding: int,CallID: seq[byte],ContextID: seq[byte],Opnum: seq[byte],Data: seq[byte]): OrderedTable[string, seq[byte]] =
    
    var full_auth_length: int

    if AuthLength > 0:
        full_auth_length = AuthLength + AuthPadding + 8
    
    let 
        write_length: seq[byte] = getBytes(ServiceLength + 24 + full_auth_length + Data.len)
        frag_length: seq[byte] = write_length[..1]
        alloc_hint: seq[byte] = getBytes(ServiceLength + Data.len)
        auth_length: seq[byte] = (getBytes(AuthLength))[..1]

    var RPCRequest = initOrderedTable[string, seq[byte]]()
    RPCRequest.add("Version",@[0x05.byte])
    RPCRequest.add("VersionMinor",@[0x00.byte])
    RPCRequest.add("PacketType",@[0x00.byte])
    RPCRequest.add("PacketFlags",Flags)
    RPCRequest.add("DataRepresentation",@[0x10.byte,0x00.byte,0x00.byte,0x00.byte])
    RPCRequest.add("FragLength",frag_length)
    RPCRequest.add("AuthLength",auth_length)
    RPCRequest.add("CallID",CallID)
    RPCRequest.add("AllocHint",alloc_hint)
    RPCRequest.add("ContextID",ContextID)
    RPCRequest.add("Opnum",Opnum)

    if Data.len > 0:
        RPCRequest.add("Data",Data)

    return RPCRequest
