#[
    SCM
]#
import random, strutils, sequtils, tables, HelpUtil

randomize()

proc NewPacketSCMOpenSCManagerW* (packet_service: seq[byte],packet_service_length: seq[byte]): OrderedTable[string, seq[byte]] =

    var 
        packet_referent_ID1_string: string
        packet_referent_ID2_string: string
    for i in 1..2:
        packet_referent_ID1_string.add(rand(1..255).toHex().hexToNormalHex())
        packet_referent_ID2_string.add(rand(1..255).toHex().hexToNormalHex())

    var 
        packet_referent_ID1 = packet_referent_ID1_string.hexToByteArray()
        packet_referent_ID2 = packet_referent_ID2_string.hexToByteArray()

    # packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    # packet_referent_ID1 = packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16(_,16)}
    packet_referent_ID1 = packet_referent_ID1.concat(@[0x00.byte,0x00.byte])
    # packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    # packet_referent_ID2 = packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16(_,16)}
    packet_referent_ID2 = packet_referent_ID2.concat(@[0x00.byte,0x00.byte])

    var packet_SCMOpenSCManagerW = initOrderedTable[string, seq[byte]]()
    packet_SCMOpenSCManagerW.add("MachineName_ReferentID",packet_referent_ID1)
    packet_SCMOpenSCManagerW.add("MachineName_MaxCount",packet_service_length)
    packet_SCMOpenSCManagerW.add("MachineName_Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    packet_SCMOpenSCManagerW.add("MachineName_ActualCount",packet_service_length)
    packet_SCMOpenSCManagerW.add("MachineName",packet_service)
    packet_SCMOpenSCManagerW.add("Database_ReferentID",packet_referent_ID2)
    packet_SCMOpenSCManagerW.add("Database_NameMaxCount",@[0x0f.byte,0x00.byte,0x00.byte,0x00.byte])
    packet_SCMOpenSCManagerW.add("Database_NameOffset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    packet_SCMOpenSCManagerW.add("Database_NameActualCount",@[0x0f.byte,0x00.byte,0x00.byte,0x00.byte])
    packet_SCMOpenSCManagerW.add("Database",@[0x53.byte,0x00.byte,0x65.byte,0x00.byte,0x72.byte,0x00.byte,0x76.byte,0x00.byte,0x69.byte,0x00.byte,0x63.byte,0x00.byte,0x65.byte,0x00.byte,0x73.byte,0x00.byte,0x41.byte,0x00.byte,0x63.byte,0x00.byte,0x74.byte,0x00.byte,0x69.byte,0x00.byte,0x76.byte,0x00.byte,0x65.byte,0x00.byte,0x00.byte,0x00.byte])
    packet_SCMOpenSCManagerW.add("Unknown",@[0xbf.byte,0xbf.byte])
    packet_SCMOpenSCManagerW.add("AccessMask",@[0x3f.byte,0x00.byte,0x00.byte,0x00.byte])
    
    return packet_SCMOpenSCManagerW

proc NewPacketSCMCreateServiceW*(ContextHandle: seq[byte],Service: seq[byte],ServiceLength: seq[byte],Command: seq[byte],CommandLength: seq[byte]): OrderedTable[string, seq[byte]] =
                
    var 
        referent_ID_string: string
    for i in 1..2:
        referent_ID_string.add(rand(1..255).toHex().hexToNormalHex())

    var 
        referent_ID = referent_ID_string.hexToByteArray()

    # referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    # referent_ID = referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16(_,16)}
    referent_ID = referent_ID.concat(@[0x00.byte,0x00.byte])
    # referent_ID += 0x00.byte,0x00.byte

    var SCMCreateServiceW = initOrderedTable[string, seq[byte]]()
    SCMCreateServiceW.add("ContextHandle",ContextHandle)
    SCMCreateServiceW.add("ServiceName_MaxCount",ServiceLength)
    SCMCreateServiceW.add("ServiceName_Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("ServiceName_ActualCount",ServiceLength)
    SCMCreateServiceW.add("ServiceName",Service)
    SCMCreateServiceW.add("DisplayName_ReferentID",referent_ID)
    SCMCreateServiceW.add("DisplayName_MaxCount",ServiceLength)
    SCMCreateServiceW.add("DisplayName_Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("DisplayName_ActualCount",ServiceLength)
    SCMCreateServiceW.add("DisplayName",Service)
    SCMCreateServiceW.add("AccessMask",@[0xff.byte,0x01.byte,0x0f.byte,0x00.byte])
    SCMCreateServiceW.add("ServiceType",@[0x10.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("ServiceStartType",@[0x03.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("ServiceErrorControl",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("BinaryPathName_MaxCount",CommandLength)
    SCMCreateServiceW.add("BinaryPathName_Offset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("BinaryPathName_ActualCount",CommandLength)
    SCMCreateServiceW.add("BinaryPathName",Command)
    SCMCreateServiceW.add("NULLPointer",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("TagID",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("NULLPointer2",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("DependSize",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("NULLPointer3",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("NULLPointer4",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SCMCreateServiceW.add("PasswordSize",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])

    return SCMCreateServiceW

proc NewPacketSCMStartServiceW*(ContextHandle: seq[byte]): OrderedTable[string, seq[byte]] =

    var SCMStartServiceW = initOrderedTable[string, seq[byte]]()
    SCMStartServiceW.add("ContextHandle",ContextHandle)
    SCMStartServiceW.add("Unknown",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])

    return SCMStartServiceW

proc NewPacketSCMDeleteServiceW*(ContextHandle: seq[byte]): OrderedTable[string, seq[byte]] =

    var SCMDeleteServiceW = initOrderedTable[string, seq[byte]]()
    SCMDeleteServiceW.add("ContextHandle",ContextHandle)

    return SCMDeleteServiceW

proc NewPacketSCMCloseServiceHandle*(ContextHandle: seq[byte]): OrderedTable[string, seq[byte]] =

    var SCM_CloseServiceW = initOrderedTable[string, seq[byte]]()
    SCM_CloseServiceW.add("ContextHandle",ContextHandle)

    return SCM_CloseServiceW