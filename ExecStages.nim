#[
    Exec Stages
]#

import strutils, sequtils, tables, net
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
    file_ID*: seq[byte]


proc checkAccess(): Stage =
    if client_receive[128..131] == @["00", "00", "00", "00"] and client_receive[108..127] != @["00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00","00", "00", "00", "00"]:
        let SMB_service_manager_context_handle = client_receive[108..127].join().hexToByteArray()

        echo "The user has Service Control Manager write privilege on the target"

        let SCM_data = convertToByteArray NewPacketSCMCreateServiceW(SMB_service_manager_context_handle, SMBServiceBytes, SMBServiceLength, SMBExecCommandBytes, SMBExecCommandLengthBytes)

        if SCM_data.len < SMBSplitIndex:
            result = CreateServiceW
        else:
            result = CreateServiceW_First
        
    elif client_receive[128..131] == @["05", "00", "00", "00"]:
        echo "The user does not have Service Control Manager write privilege on the target"
        result = Exit 
    
    else:
        echo "Something went wrong with the target"
        result = Exit

proc closeRequset(): Stage =
    inc messageID
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
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    client_send = (strPacket).parseHexStr()
    result = SendReceive

proc createRequest(sock: Socket): Stage =
    inc messageID
    var 
        SMB_named_pipe_bytes = @[0x73.byte,0x00.byte,0x76.byte,0x00.byte,0x63.byte,0x00.byte,0x63.byte,0x00.byte,0x74.byte,0x00.byte,0x6c.byte,0x00.byte]
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
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    client_send = (strPacket).parseHexStr()

    sock.send(client_send)

    client_receive = sock.recvPacket(1024, 100)

    if getStatusPending(client_receive[12..15]):
        result = StatusPending
    else:
        result = StatusReceived

proc execStages*(target, service, command: string, responseFromClient: seq[string]): bool =
    
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

    discard checkAccess()
    ## Start checking stages
    # while stage != Exit:
    #     case stage
    #     of CheckAccess:
    #         stage = checkAccess()
    #     of CloseRequset:
    #         stage = closeRequset()
    #     of CreateRequest:
    #         stage = createRequest(SMB.socket)
    return true


