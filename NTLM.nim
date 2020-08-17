#[
    NTLM
]#

import tables, os, strutils, regex, sequtils, algorithm

var messageID* = 1

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in 0..a.len - 1:
        if a[b][0] == '0':
            a[b] = substr(a[b], 1)
    result = "0x" & a.join(",0x")

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

proc NewPacketNTLMSSPNegotiate*(negotiateFlags: seq[byte], version: seq[byte]): OrderedTable[string, seq[byte]] =

    let 
        NTLMSSP_length = @[(version.len() + 32).byte]
        ASN_length_1 = @[(NTLMSSP_length[0] + 32).byte]
        ASN_length_2 = @[(NTLMSSP_length[0] + 22).byte]
        ASN_length_3 = @[(NTLMSSP_length[0] + 20).byte]
        ASN_length_4 = @[(NTLMSSP_length[0] + 2).byte]
    # echo NTLMSSP_length
    var NTLMSSPNegotiate = initOrderedTable[string, seq[byte]]()#     NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    NTLMSSPNegotiate.add("InitialContextTokenID",@[0x60.byte])#     NTLMSSPNegotiate.add("InitialContextTokenID",@[0x60.byte])

    NTLMSSPNegotiate.add("InitialcontextTokenLength",ASN_length_1)#     NTLMSSPNegotiate.add("InitialcontextTokenLength",$ASN_length_1)
    NTLMSSPNegotiate.add("ThisMechID",@[0x06.byte])#     NTLMSSPNegotiate.add("ThisMechID",@[0x06.byte])
    NTLMSSPNegotiate.add("ThisMechLength",@[0x06.byte])#     NTLMSSPNegotiate.add("ThisMechLength",@[0x06.byte])
    NTLMSSPNegotiate.add("OID",@[0x2b.byte,0x06.byte,0x01.byte,0x05.byte,0x05.byte,0x02.byte])#     NTLMSSPNegotiate.add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    NTLMSSPNegotiate.add("InnerContextTokenID",@[0xa0.byte])#     NTLMSSPNegotiate.add("InnerContextTokenID",[Byte[]](0xa0))
    NTLMSSPNegotiate.add("InnerContextTokenLength",ASN_length_2)#     NTLMSSPNegotiate.add("InnerContextTokenLength",$ASN_length_2)
    NTLMSSPNegotiate.add("InnerContextTokenID2",@[0x30.byte])#     NTLMSSPNegotiate.add("InnerContextTokenID2",@[0x30.byte])
    NTLMSSPNegotiate.add("InnerContextTokenLength2",ASN_length_3)#     NTLMSSPNegotiate.add("InnerContextTokenLength2",$ASN_length_3)
    NTLMSSPNegotiate.add("MechTypesID",@[0xa0.byte])#     NTLMSSPNegotiate.add("MechTypesID",[Byte[]](0xa0))
    NTLMSSPNegotiate.add("MechTypesLength",@[0x0e.byte])#     NTLMSSPNegotiate.add("MechTypesLength",@[0x0e.byte])
    NTLMSSPNegotiate.add("MechTypesID2",@[0x30.byte])#     NTLMSSPNegotiate.add("MechTypesID2",@[0x30.byte])
    NTLMSSPNegotiate.add("MechTypesLength2",@[0x0c.byte])#     NTLMSSPNegotiate.add("MechTypesLength2",@[0x0c.byte])
    NTLMSSPNegotiate.add("MechTypesID3",@[0x06.byte])#     NTLMSSPNegotiate.add("MechTypesID3",@[0x06.byte])
    NTLMSSPNegotiate.add("MechTypesLength3",@[0x0a.byte])#     NTLMSSPNegotiate.add("MechTypesLength3",@[0x0a.byte])
    NTLMSSPNegotiate.add("MechType",@[0x2b.byte,0x06.byte,0x01.byte,0x04.byte,0x01.byte,0x82.byte,0x37.byte,0x02.byte,0x02.byte,0x0a.byte])#     NTLMSSPNegotiate.add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    NTLMSSPNegotiate.add("MechTokenID",@[0xa2.byte])#     NTLMSSPNegotiate.add("MechTokenID",[Byte[]](0xa2))
    NTLMSSPNegotiate.add("MechTokenLength",ASN_length_4)#     NTLMSSPNegotiate.add("MechTokenLength",$ASN_length_4)
    NTLMSSPNegotiate.add("NTLMSSPID",@[0x04.byte])#     NTLMSSPNegotiate.add("NTLMSSPID",@[0x04.byte])
    NTLMSSPNegotiate.add("NTLMSSPLength",NTLMSSP_length)#     NTLMSSPNegotiate.add("NTLMSSPLength",$NTLMSSP_length)
    NTLMSSPNegotiate.add("Identifier",@[0x4e.byte,0x54.byte,0x4c.byte,0x4d.byte,0x53.byte,0x53.byte,0x50.byte,0x00.byte])#     NTLMSSPNegotiate.add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    NTLMSSPNegotiate.add("MessageType",@[0x01.byte,0x00.byte,0x00.byte,0x00.byte])#     NTLMSSPNegotiate.add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    NTLMSSPNegotiate.add("NegotiateFlags",negotiateFlags) #     NTLMSSPNegotiate.add("NegotiateFlags",$NegotiateFlags)
    NTLMSSPNegotiate.add("CallingWorkstationDomain",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])#     NTLMSSPNegotiate.add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    NTLMSSPNegotiate.add("CallingWorkstationName",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])#     NTLMSSPNegotiate.add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if version.len > 0:
        NTLMSSPNegotiate.add("Version",version)

    return NTLMSSPNegotiate

proc NewPacketSMB2SessionSetupRequest*(securityBlob: seq[byte]): OrderedTable[string, seq[byte]] =
    # echo "Yes, ", len(securityBlob).byte
    var security_buffer_length = len(securityBlob).toHex().hexToNormalHex().hexToByteArray().concat(@[0x00.byte]) #([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    var SMB2SessionSetupRequest = initOrderedTable[string, seq[byte]]()
    SMB2SessionSetupRequest.add("StructureSize",@[0x00.byte, 0x00.byte, 0x19.byte,0x00.byte])
    SMB2SessionSetupRequest.add("Flags",@[0x00.byte])
    SMB2SessionSetupRequest.add("SecurityMode",@[0x01.byte])
    SMB2SessionSetupRequest.add("Capabilities",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2SessionSetupRequest.add("Channel",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2SessionSetupRequest.add("SecurityBufferOffset",@[0x58.byte,0x00.byte])
    SMB2SessionSetupRequest.add("SecurityBufferLength",security_buffer_length)
    SMB2SessionSetupRequest.add("PreviousSessionID",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2SessionSetupRequest.add("Buffer",securityBlob)

    return SMB2SessionSetupRequest 

proc NewPacketNTLMSSPAuth*(NTLMResponse: seq[byte]): OrderedTable[string, seq[byte]] =
    let 
        NTLMSSP_length = len(NTLMResponse).toHex().hexToNormalHex().hexToByteArray().concat(@[0x00.byte]) # [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
        ASN_length_1 = (len(NTLMResponse) + 12).toHex().hexToNormalHex().hexToByteArray().concat(@[0x00.byte]) # [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
        ASN_length_2 = (len(NTLMResponse) + 8).toHex().hexToNormalHex().hexToByteArray().concat(@[0x00.byte]) # [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
        ASN_length_3 = (len(NTLMResponse) + 4).toHex().hexToNormalHex().hexToByteArray().concat(@[0x00.byte]) # [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    var NTLMSSPAuth = initOrderedTable[string, seq[byte]]() # $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    NTLMSSPAuth.add("ASNID",@[0xa1.byte, 0x82.byte]) # $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    NTLMSSPAuth.add("ASNLength", ASN_length_1) # $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    NTLMSSPAuth.add("ASNID2",@[0x30.byte, 0x82.byte]) # $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    NTLMSSPAuth.add("ASNLength2", ASN_length_2) # $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    NTLMSSPAuth.add("ASNID3",@[0xa2.byte,0x82.byte]) # $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    NTLMSSPAuth.add("ASNLength3",ASN_length_3) # $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    NTLMSSPAuth.add("NTLMSSPID", @[0x04.byte,0x82.byte]) # $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    NTLMSSPAuth.add("NTLMSSPLength", NTLMSSP_length) # $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    NTLMSSPAuth.add("NTLMResponse", NTLMResponse) # $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return NTLMSSPAuth 

when isMainModule:
    discard NewPacketNTLMSSPNegotiate(@[], @[])