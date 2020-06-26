# T1118: Install Util

InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is located in the .NET directories on a Windows system: ```C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe``` and ```C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe```. InstallUtil.exe is digitally signed by Microsoft.

Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil may also be used to bypass process whitelisting through use of attributes within the binary that execute the class decorated with the attribute [```System.ComponentModel.RunInstaller(true)```]

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "InstallUtil.exe" OR
process_command_line = "*\/logfile= \/LogToConsole=false \/U*"
```
