# T1088 Bypass User Account Control

Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs are allowed to elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box. An example of this is use of rundll32.exe to load a specifically crafted DLL which loads an auto-elevated COM object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user. Adversaries can use these techniques to elevate privileges to administrator if the target process is unprotected.

Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains an extensive list of methods that have been discovered and implemented within UACMe, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

- eventvwr.exe can auto-elevate and execute a specified binary or script.

Another bypass is possible through some Lateral Movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on lateral systems and default to high integrity.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_path = ["*\\eventvwr.exe", "*\\fodhelper.exe"]

Event 2
Sysmon Event ID = 12, 13, or 14
registry_key_path \in ["*\\mscfile\\shell\\open\\command\\*", "*\\ms-settings\\shell\\open\\command\\*"] AND
sid not in ["S-1-5-18", "S-1-5-19", "S-1-5-20")
```
