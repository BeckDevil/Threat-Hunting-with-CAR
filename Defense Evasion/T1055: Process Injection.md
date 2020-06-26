# T1055: Process Injection

Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

## Windows
There are multiple approaches to injecting code into a live process. Windows implementations include:

* Dynamic-link library (DLL) injection involves writing the path to a malicious DLL inside a process then invoking execution by creating a remote thread.
* Portable executable injection involves writing malicious code directly into the process (without a file on disk) then invoking execution with either additional code or by creating a remote thread. The displacement of the injected code introduces the additional requirement for functionality to remap memory references. Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue.
* Thread execution hijacking involves injecting malicious code or the path to a DLL into a thread of a process. Similar to Process Hollowing, the thread must first be suspended.
* Asynchronous Procedure Call (APC) injection involves attaching malicious code to the APC Queue of a process's thread. Queued APC functions are executed when the thread enters an alterable state. A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. AtomBombing is another variation that utilizes APCs to invoke malicious code previously written to the global atom table.
* Thread Local Storage (TLS) callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point.

## Detection
```
Event 1
Sysmon Event ID = 8
StartFunction = "*LoadLibrary*"

Event 2
Sysmon Event ID = 8
target_process_address = 0x*0B80

Event 3
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*Invoke-DllInjection*" or "*C:\\windows\sysnative\\*"
```
