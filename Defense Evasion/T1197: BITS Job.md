# T1197 BITS Job

Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.

Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also allow Persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.

## Detection
```
Event 1
Sysmon Event ID = 3 (MESSAGE the FLOW)
process_name = "bitsadmin.exe"

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "bitsadmin.exe" OR
process_command_line = "*Start-BitsTransfer*"
```
