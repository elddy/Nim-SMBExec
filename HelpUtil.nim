#[
    HelpUtil
]#

import tables, strutils, regex, sequtils, algorithm

proc hexToNormalHexArray*(hex: string): seq[string] =
    var a = findAndCaptureAll(hex, re"..")
    for b in a:
        if b != "00":
            result.add(b)

proc getBytes*(val: int): seq[byte] =
    let hexed = val.toHex().hexToNormalHexArray()
    if hexed.len > 1:
        result.add(hexed[1].parseHexInt().byte)
    result.add(hexed[0].parseHexInt().byte)
    result.concat(@[0x00.byte,0x00.byte])

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    result = "0x" & a.join(",0x")

proc convertToByteArray*(tab: OrderedTable): seq[byte] =
    for v in tab.values:
        result.add(v)

proc GetUInt16DataLength*(start: int, data: seq[byte]): int =
    let data_length = ($(data[start])).parseInt()

    return data_length

proc unicodeGetBytes*(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)
        result.add(0x00.byte)

proc stringToByteArray*(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToByteArray*(str: string): seq[byte] =
    for i in str.hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToNormalHex*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in a:
        if b != "00":
            result.add(b)

proc pidToByteArray*(pid: int): seq[byte] =
    result = pid.toHex().hexToNormalHex().hexToByteArray().reversed()
