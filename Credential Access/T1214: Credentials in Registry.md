# T1214 Credentials in Registry

The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information:

```
Local Machine Hive: reg query HKLM /f password /t REG_SZ /s
Current User Hive: reg query HKCU /f password /t REG_SZ /s
```

## Detection
 ```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*reg* query HKLM \/f password \/t REG_SZ \/s*" OR
                       "reg* query HKCU \/f password \/t REG_SZ \/s" OR 
                       "*Get-UnattendedInstallFile*" OR
                       "*Get-Webconfig*" OR
                       "*Get-ApplicationHost*" OR
                       "*Get-SiteListPassword*" OR
                       "*Get-CachedGPPPassword*" OR
                       "*Get-RegistryAutoLogon*"

 ```
