# T1028: Windows Remote Management

Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the ```winrm``` command or by any number of programs such as ```PowerShell```.

## Detection
Monitor use of *WinRM* within an environment by tracking service execution. If it is not normally used or is disabled, then this may be an indicator of suspicious behavior. Monitor processes created and actions taken by the *WinRM* process or a *WinRM* invoked script to correlate it with other related events.

```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "wsmprovhost.exe" OR "winrm.cmd" OR 
process_command_line = ".*Enable-PSRemoting -Force.*" OR ".*Invoke-Command -computer_name.*" OR 
                       "wmic.*node.*process call create.*"
                       
```
