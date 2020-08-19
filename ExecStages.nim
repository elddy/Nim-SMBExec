#[
    Exec Stages
]#

import strutils, sequtils
import HelpUtil, SCM, RPC, SMBv2, NTLM

## Enum of stages
type
    Stage = enum
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
    let 
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x06.byte,0x00.byte], @[0x01.byte,0x00.byte], false, @[messageID.byte], process_ID, tree_ID, session_ID)
        smb2Data = convertToByteArray NewPacketSMB2NegotiateProtocolRequest()
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)

proc execStages*(command, target, service: string, responseFromClient: seq[string]): bool =
    
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
    var stage: Stage = TreeConnect
    while stage != Exit:
        case stage
        of CheckAccess:
            stage = checkAccess()
        of CloseRequset:
            stage = 

