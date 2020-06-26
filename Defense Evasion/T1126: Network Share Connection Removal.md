# T1126: Network Share Connection Removal
Windows shared drive and Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the net use \system\share /delete command.

Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
(process_name = "net.exe" AND process_command_line = "*net* delete*") OR 
process_command_line = "*Remove-SmbShare*" OR "*Remove-FileShare*"

```
