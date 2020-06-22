# T1077 WIndows Admin Shares 

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$, and IPC$.

Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB) to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.

The Net utility can be used to connect to Windows admin shares on remote systems using net use commands with valid credentials.

## Detection
Ensure that proper logging of accounts used to log into systems is turned on and centrally collected. Windows logging is able to collect success/failure for accounts that may be used to move laterally and can be collected using tools such as Windows Event Forwarding. Monitor remote login events and associated SMB activity for file transfers and remote process execution. Monitor the actions of remote users who connect to administrative shares. Monitor for use of tools and commands to connect to remote shares, such as Net, on the command-line interface and Discovery techniques that could be used to find remotely accessible systems.
```
Event 1
Sysmon Event ID = 3
process_name = "net.exe" AND
process_command_line = "net.*use.*$" OR "net.*session.*$" OR "net.*file.*$"

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "net.exe" AND process_command_line = "net.*share.*$"

Event 3
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "net.exe" OR process_name=powershell.exe) AND
process_command_line = "net.*use.*$" OR "net.*session.*$" OR "net.*file.*$" OR "New-PSDrive.*root.*"
```
