# T1179 Hooking 

Windows processes often leverage application programming interface (API) functions to perform tasks that require reusable system resources. Windows API functions are typically stored in dynamic-link libraries (DLLs) as exported functions.

Hooking involves redirecting calls to these functions and can be implemented via:
```
- Hooks procedures, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.
- Import address table (IAT) hooking, which use modifications to a process’s IAT, where pointers to imported API functions are stored.
- Inline hooking, which overwrites the first bytes in an API function to redirect code flow.
```
Similar to Process Injection, adversaries may use hooking to load and execute malicious code within the context of another process, masking the execution while also allowing access to the process's memory and possibly elevated privileges. Installing hooking mechanisms may also provide Persistence via continuous invocation when the functions are called through normal use.

Malicious hooking mechanisms may also capture API calls that include parameters that reveal user authentication credentials for Credential Access.

Hooking is commonly utilized by Rootkits to conceal files, processes, Registry keys, and other objects in order to hide malware and associated behaviors.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688 
process_name = "mavinject.exe" OR
process_command_line = "*/INJECTRUNNING*"
```
