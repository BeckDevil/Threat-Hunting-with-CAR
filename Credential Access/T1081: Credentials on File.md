# T1081 Credentials On File

Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*findstr* /si pass*" OR "*select-string -Pattern pass*" OR "*list vdir*/text:password*"

```
