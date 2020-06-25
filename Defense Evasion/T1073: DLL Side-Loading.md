# T1073 DLL Side-Loading

Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable to side-loading to load a malicious DLL.

## Detection
```
Event 1
Sysmon Event ID = 7 
driver_loaded = "*\\System.Management.Automation.ni.dll" OR
                "*\\System.Management.Automation.dll" OR 
                "*\\PowerShdll.dll"

process_name != "powershell.exe" OR process_name != "powershellise.exe"

Event 2
Sysmon Event ID = 7 
driver_loaded = "wmiutils.dll"
process_path != "C:\\Windows\\*"
```
