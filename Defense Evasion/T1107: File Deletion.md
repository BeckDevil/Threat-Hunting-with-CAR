# T1107 File Deletion

Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native cmd functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools.

# Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = ["*remove-item*", "vssadmin*Delete Shadows /All /Q*", 
                        "*wmic*shadowcopy delete*", "*wbdadmin* delete catalog -q*", 
                        "*bcdedit*bootstatuspolicy ignoreallfailures*", "*bcdedit*recoveryenabled no*"

```
