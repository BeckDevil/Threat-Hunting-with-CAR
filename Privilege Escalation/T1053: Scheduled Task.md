# T1053 Scheduled Task

Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system.

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "taskeng.exe" or "schtasks.exe" or "svchost.exe"
process_parent_path != "C:\\Windows\\System32\\services.exe"

Event 2
Sysmon Event ID = 11
process_path != "C:\\WINDOWS\\system32\\svchost.exe" 
file_path = "C:\\Windows\\System32\\Tasks\\*" or "C:\\Windows\\Tasks\\*"
```
