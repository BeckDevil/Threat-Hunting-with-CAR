# T1002: Data Compress

An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "powershell.exe" AND process_command_line="*-Recurse | Compress-Archive*") OR 
process_name = "rar.exe" AND process_command_line="rar*a*") OR
process_name = "7z.exe" or "*zip.exe"

Event 2
Sysmon Event ID = 11
file_name = ["*.zip", "*.rar", "*.arj", "*.gz", "*.tar", "*.tgz", "*.7z", "*.zip", "*.tar.gz", "*.bin"]
```
