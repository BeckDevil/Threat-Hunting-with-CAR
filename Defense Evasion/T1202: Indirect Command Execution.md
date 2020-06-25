# T1202: Indirect Command Execution

Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command-Line Interface, Run window, or via scripts.

Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_name = "pcalua.exe" OR
process_name = "pcalua.exe" OR "bash.exe" "forfiles.exe"
```
