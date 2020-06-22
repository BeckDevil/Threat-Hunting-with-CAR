# T1037 Logon Scripts 
## Windows
Windows allows logon scripts to be run whenever a specific user or group of users log into a system. The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server.

If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

## Mac
Mac allows login and logoff hooks to be run as root whenever a specific user logs into or out of a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike startup items, a login hook executes as root [2]. There can only be one login hook at a time though. If adversaries can access these scripts, they can insert additional code to the script to execute their tools when a user logs in.

## Detection 
```
Sysmon Event ID = 1 
Windows Security Event ID = 4688
process_command_line = "REG.*ADD.*HKCU\\Environment.*UserInitMprLogonScript.*"
```
