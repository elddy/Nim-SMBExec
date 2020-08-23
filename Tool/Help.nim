#[
    Help module
]#

import parseopt, net, strutils, os, random, terminal

var target*, domain*, user*, hash*, pass*, command*, service*: string

type
    STATUS* = enum
        Error, Success, Info

randomize()

#[
    Prints nice and all
]#
proc printC*(stat: STATUS, text: string) = 
    case stat
    of Error:
        stdout.styledWrite(fgRed, "[-] ")
    of Success:
        stdout.styledWrite(fgGreen, "[+] ")
    of Info:
        stdout.styledWrite(fgYellow, "[*] ")
    echo text

proc rndStr*(): string =
  for _ in .. 6:
    add(result, char(rand(int('A') .. int('z'))))

proc printHelp() =
    when defined windows:
        echo """
Nim SMBExec.
Usage:
    SMBExec.exe -target:<IP | Hostname> -domain:<Domain> -user:<Username> -pass:<Password> | -hash:<NT Hash> -command:"<Command>" [-service:<Service Name>]
    SMBExec.exe (-h | --help)
Options:
    -h --help         Show this screen.
    -target           Target IP or Hostname.
    -domain           Domain of user (For local user enter ".").
    -username, -user  Target Username.
    -password, -pass  Password of user (Optional).
    -hash             Hash of user password (Required when not using -password).
    -command          Command to run under the service.
    -service          Service name of the new created service (Optional).       
        """

    when defined linux:
        echo """
Nim SMBExec.
Usage:
    ./SMBExec -target:<IP | Hostname> -domain:<Domain> -user:<Username> -pass:<Password> | -hash:<NT Hash> -command:"<Command>" [-service:<Service Name>]
    ./SMBExec (-h | --help)
Options:
    -h --help         Show this screen.
    -target           Target IP or Hostname.
    -domain           Domain of user (For local user enter ".").
    -username, -user  Target Username.
    -password, -pass  Password of user (Optional).
    -hash             Hash of user password (Required when not using -password).
    -command          Command to run under the service.
    -service          Service name of the new created service (Optional).       
        """

proc checkParams*() =
    var 
        p = initOptParser(commandLineParams())
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdLongOption:
            if p.key.toLower == "target":
                target = p.val
            elif p.key.toLower == "domain":
                domain = p.val
            elif p.key.toLower == "user" or p.key.toLower == "username":
                user = p.val
            elif p.key.toLower == "hash":
                hash = p.val
            elif p.key.toLower == "pass" or p.key.toLower == "password":
                pass = p.val
            elif p.key.toLower == "command":
                command = p.val
            elif p.key.toLower == "service":
                service = p.val
        else:
            break
    if target == "" or domain == "" or user == "" or (hash == "" and pass == "") or command == "":
        printHelp()
        quit(-1)
