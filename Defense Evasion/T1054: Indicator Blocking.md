# T1054: Indicator Blocking

An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW), by tampering settings that control the collection and flow of event telemetry. These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as PowerShell or Windows Management Instrumentation.

ETW interruption can be achieved multiple ways, however most directly by defining conditions using the PowerShell Set-EtwTraceProvider cmdlet or by interfacing directly with the registry to make alterations.

In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process responsible for forwarding telemetry and/or creating a host-based firewall rule to block traffic to specific hosts responsible for aggregating events, such as security information and event management (SIEM) products.

## Detection 

```
Event 1
Sysmon Event ID = 12 or 13 or 14
registry_key_path = "HKLM\\System\\CurrentControlSet\\Services\\SysmonDrv\\*" OR
                    "HKLM\\System\\CurrentControlSet\\Services\\Sysmon\\*" OR
                    "HKLM\\System\\CurrentControlSet\\Services\\Sysmon64\\*"
process_name != "Sysmon64.exe" or "Sysmon.exe"

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "fltmc.exe" OR
process_command_line = "*fltmc*unload*"
```
