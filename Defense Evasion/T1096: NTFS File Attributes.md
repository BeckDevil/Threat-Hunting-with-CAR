# T1096: NTFS File Attributes
Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. Within MFT entries are file attributes, such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files).

Adversaries may store malicious data or binaries in file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "fsutil.exe" 
proces_command_line = "*usn*deletejournal*"
```
