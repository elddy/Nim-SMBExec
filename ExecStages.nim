#[
    Exec Stages
]#

import strutils, sequtils, tables, net, os, math
import HelpUtil, SCM, RPC, SMBv2, NTLM, SMBv2Helper
from hmac import hmac_sha256
import nimSHA2 except toHex

## Enum of stages
type
    Stage* = enum
        TreeConnect, CheckAccess, CloseRequset, CloseServiceHandle, 
        CreateRequest, CreateServiceW, CreateServiceW_First, 
        CreateServiceW_Middle, CreateServiceW_Last, DeleteServiceW,
        Logoff, OpenSCManagerW, ReadRequest, RPCBind, SendReceive,
        StartServiceW, StatusPending, StatusReceived, TreeDisconnect,
        Exit

## Global
const named_pipe_UUID* = @[0x81.byte,0xbb.byte,0x7a.byte,0x36.byte,0x44.byte,0x98.byte,0xf1.byte,0x35.byte,0xad.byte,0x32.byte,0x98.byte,0xf0.byte,0x38.byte,0x00.byte,0x10.byte,0x03.byte]

var 
    SMB_named_pipe_bytes = @[0x73.byte,0x00.byte,0x76.byte,0x00.byte,0x63.byte,0x00.byte,0x63.byte,0x00.byte,0x74.byte,0x00.byte,0x6c.byte,0x00.byte]
    SMBPath*: string
    SMBPathBytes*: seq[byte]
    SMBService*: string
    SMBServiceBytes*: seq[byte]
    SMBServiceLength*: seq[byte]
    SMBExecCommand*: seq[string]
    SMBExecCommandBytes*: seq[byte]
    SMBExecCommandLengthBytes*: seq[byte]
    SMBSplitIndex*: int
    client_receive: seq[string]
    client_send: string
    stage*: Stage
    stage_current: Stage
    stage_next: Stage
    file_ID*: seq[byte]
    SMB_execute: bool = true
    SMB_close_service_handle_stage: int
    SMB_split_stage_final: int
    SMB_split_stage: int
    Sleep: int = 150
    SCM_data: seq[byte]
    SMB_service_context_handle: seq[byte]
    SMB_service_manager_context_handle: seq[byte]
    SMB_split_index_tracker: int

proc treeConnect(socket: Socket): Stage =
    treeID = client_receive[40..43].join().hexToByteArray()
    stage_current = stage
    inc messageID

    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x03.byte, 0x00.byte], @[0x01.byte, 0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)
        SMB2_header = convertToByteArray packet_SMB2_header
        SMB2_data = convertToByteArray NewPacketSMB2TreeConnectRequest(SMBPathBytes)
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len, SMB2_data.len)

    if signing:
        let 
            SMB2_sign = SMB2_header.concat(SMB2_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data)
    
    ## Make packet
    client_send = buildPacket(fullPacket)
    
    try:
        socket.send(client_send)
        client_receive = socket.recvPacket(1024, 100)
        if (getStatusPending(client_receive[12..15])):
            result = StatusPending
        else:
            result = StatusReceived
    except Exception as E:
        echo "[-] Session connection is closed, Error: ", E.msg
        result = Exit

proc treeDisconnect(): Stage =
    inc messageID
    stage_current = stage
    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x04.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)
        SMB2_header = convertToByteArray packet_SMB2_header
        packet_SMB2_data = NewPacketSMB2TreeDisconnectRequest()
    let 
        SMB2_data = convertToByteArray packet_SMB2_data
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), SMB2_data.len())

    if signing:
        let 
            SMB2_sign = SMB2_header.concat(SMB2_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullpacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data)
    client_send = buildPacket(fullpacket)
    result = SendReceive

proc checkAccess(): Stage =
    if client_receive[128..131] == @["00", "00", "00", "00"] and client_receive[108..127] != @["00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00"]:
        SMB_service_manager_context_handle = client_receive[108..127].join().hexToByteArray()
        echo "The user has Service Control Manager write privilege on the target"
        if SMB_execute:
            
            SCM_data = convertToByteArray NewPacketSCMCreateServiceW(SMB_service_manager_context_handle, SMBServiceBytes, SMBServiceLength, SMBExecCommandBytes, SMBExecCommandLengthBytes)

            if SCM_data.len < SMBSplitIndex:
                result = CreateServiceW
            else:
                result = CreateServiceW_First
        else:
            SMB_close_service_handle_stage = 2
            result = CloseServiceHandle
        
    elif client_receive[128..131] == @["05", "00", "00", "00"]:
        echo "The user does not have Service Control Manager write privilege on the target"
        result = Exit 
    
    else:
        echo "Something went wrong with the target"
        result = Exit

proc closeRequset(): Stage =
    inc messageID
    stage_current = stage
    var 
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x06.byte,0x00.byte], @[0x01.byte,0x00.byte], false, @[messageID.byte], process_ID, tree_ID, session_ID)
        smb2Data = convertToByteArray NewPacketSMB2CloseRequest(file_ID)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        
        SMB2_sign: seq[byte]
        SMB2_signature: seq[byte]
    
    if signing:
        SMB2_sign = smb2Header.concat(smb2Data)
        SMB2_signature = ($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray()
        SMB2_signature = SMB2_signature[..15]
        var smb2HeaderPacket = NewPacketSMB2Header(@[0x06.byte,0x00.byte], @[0x01.byte,0x00.byte], false, @[messageID.byte], process_ID, tree_ID, session_ID)
        smb2HeaderPacket["Signature"] = SMB2_signature
        smb2Header = convertToByteArray smb2HeaderPacket

    let fullPacket = concat(netBiosSession, smb2Header, smb2Data)

    ## Make packet
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc createRequest(socket: Socket): Stage =
    inc messageID
    stage_current = stage
    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x05.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], process_ID, tree_ID, session_ID)
        smb2Header = convertToByteArray packet_SMB2_header
    
    var packet_SMB2_data = NewPacketSMB2CreateRequestFile(SMB_named_pipe_bytes)
    packet_SMB2_data["Share_Access"] = @[0x07.byte, 0x00.byte, 0x00.byte, 0x00.byte]
    
    let 
        smb2Data = convertToByteArray packet_SMB2_data
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())

    if signing:
        var 
            SMB2_sign = smb2Header.concat(smb2Data)
            SMB2_signature = ($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray()
        SMB2_signature = SMB2_signature[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        smb2Header = convertToByteArray packet_SMB2_header
    
    let fullPacket = concat(netBiosSession, smb2Header, smb2Data)

    ## Make packet
    client_send = buildPacket(fullPacket)

    socket.send(client_send)

    client_receive = socket.recvPacket(1024, 100)

    if getStatusPending(client_receive[12..15]):
        result = StatusPending
    else:
        result = StatusReceived

proc readRequest(): Stage =
    sleep(Sleep)
    stage_current = stage
    inc messageID

    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x08.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], process_ID, tree_ID, session_ID)
        packet_SMB2_data = NewPacketSMB2ReadRequest(file_ID)
    packet_SMB2_data["Length"] = @[0xff.byte, 0x00.byte, 0x00.byte, 0x00.byte]
    
    var 
        smb2Header = convertToByteArray packet_SMB2_header
        smb2Data = convertToByteArray packet_SMB2_data
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())

    if signing:
        var 
            SMB2_sign = smb2Header.concat(smb2Data)
            SMB2_signature = ($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray()
        SMB2_signature = SMB2_signature[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        smb2Header = convertToByteArray packet_SMB2_header
    
    let fullPacket = concat(netBiosSession, smb2Header, smb2Data)

    ## Make packet
    client_send = buildPacket(fullPacket)
    
    result = SendReceive

proc statusPending(socket: Socket): Stage =
    if client_receive[12..15] != @["03", "01", "00", "00"]:
        result = StatusReceived
    # else:
    #     result = stage

proc statusReceived(): Stage =
    case stage_current:
    of CloseRequset:
        result = TreeDisconnect
    of CloseServiceHandle:
        if SMB_close_service_handle_stage == 2:
            result = CloseServiceHandle
        else:
            result = CloseRequset
    of CreateRequest:
        file_ID = client_receive[132..147].join().hexToByteArray()
        if stage != Exit:
            result = RPCBind
    of CreateServiceW:
        result = ReadRequest
        stage_next = StartServiceW
    of CreateServiceW_First:
        if SMB_split_stage_final <= 2:
            result = CreateServiceW_Last
        else:
            SMB_split_stage = 2
            result = CreateServiceW_Middle
    of CreateServiceW_Middle:
        if SMB_split_stage >= SMB_split_stage_final:
            result = CreateServiceW_Last
        else:
            result = CreateServiceW_Middle
    of CreateServiceW_Last:
        result = ReadRequest
        stage_next = StartServiceW
    of DeleteServiceW:
        result = ReadRequest
        stage_next = CloseServiceHandle
        SMB_close_service_handle_stage = 1
    of Logoff:
        result = Exit
    of OpenSCManagerW:
        result = ReadRequest
        stage_next = CheckAccess
    of ReadRequest:
        result = stage_next
    of RPCBind:
        result = ReadRequest
        stage_next = OpenSCManagerW
    of StartServiceW:
        result = ReadRequest
        stage_next = DeleteServiceW
    of TreeConnect:
        tree_ID = client_receive[40..43].join().hexToByteArray()
        result = CreateRequest
    of TreeDisconnect:
        result = Logoff
    else:
        discard

proc rpcBind(): Stage =
    stage_current = stage
    inc messageID
    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], process_ID, tree_ID, session_ID)
        RPC_data = convertToByteArray NewPacketRPCBind(@[0x48.byte,0x00.byte], 1, @[0x01.byte], @[0x00.byte, 0x00.byte], named_pipe_UUID, @[0x02.byte, 0x00.byte])
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, RPC_data.len)
        SMB2_header = convertToByteArray packet_SMB2_header
        RPC_data_length = SMB2_data.len + RPC_data.len
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)
    if signing:
        var 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data)
            SMB2_signature = ($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray()
        SMB2_signature = SMB2_signature[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header
    
    let fullPacket = concat(netBiosSession, SMB2_header, SMB2_data, RPC_data)


    ## Make packet
    client_send = buildPacket(fullPacket)

    result = SendReceive
    
proc sendReceive(socket: Socket): Stage =
    socket.send(client_send)

    client_receive = socket.recvPacket(1024, 500)
    if getStatusPending(client_receive[12..15]):
        result = StatusPending
    else:
        result = StatusReceived

proc closeServiceHandle(): Stage =
    var packet_SCM_data: OrderedTable[string, seq[byte]] 

    if SMB_close_service_handle_stage == 1:
        echo "Service deleted"
        packet_SCM_data = NewPacketSCMCloseServiceHandle(SMB_service_context_handle)
    
    else:
        packet_SCM_data = NewPacketSCMCloseServiceHandle(SMB_service_manager_context_handle)

    inc SMB_close_service_handle_stage
    stage_current = stage
    inc messageID
    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    SCM_data = convertToByteArray packet_SCM_data
    let 
        RPC_data =  convertToByteArray NewPacketRPCRequest(@[0x03.byte], SCM_data.len(), 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[])
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, (RPC_data.len() + SCM_data.len()))
    var SMB2_header = convertToByteArray packet_SMB2_header
    let 
        RPC_data_length = SMB2_data.len() + SCM_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)

    if signing:
        let 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data, SCM_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data, SCM_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc createServiceW(): Stage =

    stage_current = stage
    inc messageID
    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    let 
        RPC_data = convertToByteArray NewPacketRPCRequest(@[0x03.byte], SCM_data.len(), 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x0c.byte, 0x00.byte], @[])
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, (RPC_data.len() + SCM_data.len()))
    var SMB2_header = convertToByteArray packet_SMB2_header
    let
        RPC_data_length = SMB2_data.len() + SCM_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)

    if signing:
        let 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data, SCM_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data, SCM_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc openSCManagerW(): Stage =
    stage_current = stage
    inc messageID
    
    SCM_data = convertToByteArray NewPacketSCMOpenSCManagerW(SMB_service_bytes, SMB_service_length)
    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)
        RPC_data = convertToByteArray NewPacketRPCRequest(@[0x03.byte], SCM_data.len, 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte, 0x00.byte], @[0x0f.byte, 0x00.byte], @[])
        SMB2_header = convertToByteArray packet_SMB2_header
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, RPC_data.len + SCM_data.len)   
        RPC_data_length = SMB2_data.len + SCM_data.len + RPC_data.len
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)
    
    if signing:
        let 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data, SCM_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header
    
    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data, SCM_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc createServiceW_First(): Stage =
    stage_current = stage
    SMB_split_stage_final = ceil(SCM_data.len() / SMB_split_index).toInt()
    inc messageID
    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    let
        SCM_data_first = SCM_data[0..(SMB_split_index - 1)]

    var packet_RPC_data = NewPacketRPCRequest(@[0x01.byte], 0, 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x0c.byte,0x00.byte], SCM_data_first)
    packet_RPC_data["AllocHint"] = getBytes(SCM_data.len()) 
    SMB_split_index_tracker = SMB_split_index

    var
        RPC_data = convertToByteArray packet_RPC_data
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(fileID, RPC_data.len())
        SMB2_header = convertToByteArray packet_SMB2_header
        RPC_data_length = SMB2_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)

    if signing:
        let 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc logOff(): Stage =
    stage_current = stage
    inc messageID
    var 
        packet_SMB2_header = NewPacketSMB2Header(@[0x02.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)
        SMB2_data = convertToByteArray NewPacketSMB2SessionLogoffRequest()
        SMB2_header = convertToByteArray packet_SMB2_header
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), SMB2_data.len())
    
    if signing:
        var 
            SMB2_sign = SMB2_header.concat(SMB2_data)
            SMB2_signature = ($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray()
        SMB2_signature = SMB2_signature[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header
    
    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc createServiceW_Middle(): Stage =
    stage_current = stage

    inc SMB_split_stage
    inc messageID

    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    var SCM_data_middle = SCM_data[SMB_split_index_tracker..(SMB_split_index_tracker + SMB_split_index - 1)]
    SMB_split_index_tracker = SMB_split_index_tracker + SMB_split_index
    var packet_RPC_data = NewPacketRPCRequest(@[0x00.byte], 0, 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x0c.byte,0x00.byte], SCM_data_middle)
    packet_RPC_data["AllocHint"] = getBytes(SCM_data.len() - (SMB_split_index_tracker + SMB_split_index))
    var   
        RPC_data = convertToByteArray packet_RPC_data
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, RPC_data.len())
        SMB2_header = convertToByteArray packet_SMB2_header
        RPC_data_length = SMB2_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)
    
    if signing:
            let 
                SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data)
                SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
            packet_SMB2_header["Signature"] = SMB2_signature
            SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc createServiceW_Last(): Stage =

    stage_current = stage
    inc messageID
    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    var
        SCM_data_last = SCM_data[SMB_split_index_tracker..SCM_data.len()]
        RPC_data = convertToByteArray NewPacketRPCRequest(@[0x02.byte], 0, 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x0c.byte,0x00.byte], SCM_data_last)
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(fileID, RPC_data.len())
        SMB2_header = convertToByteArray packet_SMB2_header
        RPC_data_length = SMB2_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)

    if signing:
            let 
                SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data)
                SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
            packet_SMB2_header["Signature"] = SMB2_signature
            SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc startServiceW(): Stage =
    if client_receive[132..135] == @["00", "00", "00", "00"]:
        echo "Service created on the target"
        SMB_service_context_handle = client_receive[112..131].join().hexToByteArray()
        stage_current = stage
        inc messageID

        var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)
        var
            SCM_data = convertToByteArray NewPacketSCMStartServiceW(SMB_service_context_handle)
            RPC_data = convertToByteArray NewPacketRPCRequest(@[0x03.byte], SCM_data.len(), 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x13.byte,0x00.byte], @[])
            SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(fileID, (RPC_data.len() + SCM_data.len()))
            SMB2_header = convertToByteArray packet_SMB2_header
            RPC_data_length = SMB2_data.len() + SCM_data.len() + RPC_data.len()
            NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)
        
        if signing:
                let 
                    SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data, SCM_data)
                    SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
                packet_SMB2_header["Signature"] = SMB2_signature
                SMB2_header = convertToByteArray packet_SMB2_header
    
        let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data, SCM_data)
        client_send = buildPacket(fullPacket)
        echo "Trying to execute command on the target"
        result = SendReceive
    elif client_receive[132..135] == @["31", "04", "00", "00"]:
        echo "Service creation failed on target"
        result = Exit
    else:
        echo "Service creation fault context mismatch"
        result = Exit

proc deleteServiceW(): Stage =

    if client_receive[108..111] == @["1d","04","00","00"]:
        echo "[+] Command executed with service" 
    elif client_receive[108..111] == @["02","00","00","00"]: 
        echo "[-] Service failed to start"

    stage_current = stage
    inc messageID
    var packet_SMB2_header = NewPacketSMB2Header(@[0x09.byte,0x00.byte], @[0x01.byte,0x00.byte], signing, @[messageID.byte], processID, treeID, sessionID)

    var
        SCM_data = convertToByteArray NewPacketSCMDeleteServiceW(SMB_service_context_handle)
        RPC_data = convertToByteArray NewPacketRPCRequest(@[0x03.byte], SCM_data.len(), 0, 0, @[0x01.byte,0x00.byte,0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], @[0x02.byte,0x00.byte], @[])
        SMB2_data = convertToByteArray NewPacketSMB2WriteRequest(file_ID, (RPC_data.len() + SCM_data.len()))
        SMB2_header = convertToByteArray packet_SMB2_header
        RPC_data_length = SMB2_data.len() + SCM_data.len() + RPC_data.len()
        NetBIOS_session_service = convertToByteArray NewPacketNetBIOSSessionService(SMB2_header.len(), RPC_data_length)

    if signing:
        let 
            SMB2_sign = concat(SMB2_header, SMB2_data, RPC_data, SCM_data)
            SMB2_signature = (($hmac_sha256(HMAC_SHA256_key.byteArrayToString().parseHexStr(), SMB2_sign.byteArrayToString().parseHexStr())).hexToByteArray())[..15]
        packet_SMB2_header["Signature"] = SMB2_signature
        SMB2_header = convertToByteArray packet_SMB2_header

    let fullPacket = concat(NetBIOS_session_service, SMB2_header, SMB2_data, RPC_data, SCM_data)
    client_send = buildPacket(fullPacket)
    result = SendReceive

proc execStages*(target, service, command: string, socket: Socket, responseFromClient: seq[string]) = 
    client_receive = responseFromClient
    SMBPath = r"\\" & target & r"\IPC$"
    SMBPathBytes = SMBPath.unicodeGetBytes()
    SMBService = service
    SMBServiceBytes = SMBService.unicodeGetBytes()
    let full_command = "%COMSPEC% /C " & "\"" & command & "\""

    if SMBServiceBytes.len mod 2 != 0:
        SMBServiceBytes = SMBServiceBytes.concat(@[0x00.byte, 0x00.byte])
    else:
        SMBServiceBytes = SMBServiceBytes.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])

    SMBServiceLength = getBytes(SMBService.len + 1)

    for i in unicodeGetBytes(full_command):
        SMBExecCommand.add i.toHex()

    if full_command.len mod 2 != 0:
        SMBExecCommand = SMBExecCommand.concat(@["00", "00"])
    else:
        SMBExecCommand = SMBExecCommand.concat(@["00", "00", "00", "00"])

    SMBExecCommandBytes = SMBExecCommand.join().hexToByteArray() 
    SMBExecCommandLengthBytes = getBytes((SMBExecCommand.len() / 2).int)
    SMBSplitIndex = 4256

    ## Start checking stages
    while stage != Exit:
        case stage
        of CheckAccess:
            stage = checkAccess()
            # echo stage
        of CloseRequset:
            stage = closeRequset()
            # echo stage
        of TreeConnect:
            stage = treeConnect(socket)
            # echo stage
        of CreateRequest:
            stage = createRequest(socket)
            # echo stage
        of Exit:
            # echo stage
            continue
        of CloseServiceHandle:
            stage = closeServiceHandle()
            # echo stage
        of CreateServiceW:
            stage = createServiceW()
            # echo stage
        of CreateServiceW_First:
            stage = createServiceW_First()
            # echo stage
        of CreateServiceW_Middle:
            stage = createServiceW_Middle()
            # echo stage
        of CreateServiceW_Last:
            stage = createServiceW_Last()
            # echo stage
        of DeleteServiceW:
            stage = deleteServiceW()
            # echo stage
        of Logoff:
            stage = logOff()
            # echo stage
        of OpenSCManagerW:
            stage = openSCManagerW()
            # echo stage
        of RPCBind:
            stage = rpcBind()
            # echo stage
        of ReadRequest:
            stage = readRequest()
            # echo stage
        of SendReceive:
            stage = sendReceive(socket)
            # echo stage
        of StartServiceW:
            stage = startServiceW()
            # echo stage
        of StatusPending:
            stage = statusPending(socket)
            # echo stage
        of StatusReceived:
            stage = statusReceived()
            # echo stage
        of TreeDisconnect:
            stage = treeDisconnect()
            # echo stage



