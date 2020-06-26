# T1127 Trusted Developer Utilities
There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions.
* MSBuild
* DNX
* RCSI
* WinDbg/CDB
* Tracker

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "MSBuild.exe" or "msxsl.exe"

Event 2
Sysmon Event ID = 11
target_file_name = "\\AppData\\Local\\Microsoft\\CLR_v2.0.*\\UsageLogs\\"
```
