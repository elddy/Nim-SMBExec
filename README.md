# Nim-SMBExec
SMBExec implementation in Nim - SMBv2 using NTLM Authentication with Pass-The-Hash technique

## Install
```
nimble install SMBExec
```

## Usage
```Nim
import SMBExec
```

## Examples
Create SMB object, connect to target and execute a command under specified service name:
```Nim
let hash = toNTLMHash("SecretPassword") # Returns NTLMHash => e.g 47bf8039a8506cd67c524a03ff84ba4e

var smb = newSMB2("IP Address/Hostname", "Domain", "Username", "Password Hash", "ServiceName (Optional)") # Creates SMB object

let response = smb.connect() # Connect and authenticate to the target via SMB

smb.exec("cmd command", response) # Response from the negotiation

smb.close() # Close socket
```
## Support
### Only supports SMBv2

## Credits
Powershell: Invoke-SMBExec - https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1
