# T1086: Powershell

PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including Empire, PowerSploit, and PSAttack.

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI).

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*.Download*" or "*Net.WebClient*"

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "powershell.exe" or "powershell_ise.exe" or "psexec.exe"
```
