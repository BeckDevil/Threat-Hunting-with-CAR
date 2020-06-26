# T1117: Regsvr32

Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries.

Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary.

Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. This variation of the technique is often referred to as a "Squiblydoo" attack and has been used in campaigns targeting governments.

Regsvr32.exe can also be leveraged to register a COM Object used to establish Persistence via Component Object Model Hijacking. 

## Detection
```
Event 1
Sysmon Event ID = 3
process_parent_path = "*\\regsvr32.exe" OR 
process_path = "*\\regsvr32.exe"

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "regsvr32.exe" or "rundll32.exe" or "certutil.exe") OR
process_command_line = "*scrobj.dll*"
```
