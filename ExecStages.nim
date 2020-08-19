#[
    Exec Stages
]#

proc checkAccess(response: seq[string]): bool =
    if response[128..131] == @["00", "00", "00", "00"]