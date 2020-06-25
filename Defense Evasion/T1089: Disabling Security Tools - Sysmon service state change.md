# T1089 Disabling Security Tools - Sysmon service state change

Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = ["net.exe" OR "sc.exe"]
cmdline = "stop"
```
