# T1036: Masquerading
Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.

One variant is for an executable to be placed in a commonly trusted directory or given the name of a legitimate, trusted program. Alternatively, the filename given may be a close approximation of legitimate programs or something innocuous. An example of this is when a common system utility or program is moved and renamed to avoid detection based on its usage. This is done to bypass tools that trust executables by relying on file name or path, as well as to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate.

A third variant uses the right-to-left override (RTLO or RLO) character (U+202E) as a means of tricking a user into executing what they think is a benign file type but is actually executable code. RTLO is a non-printing character that causes the text that follows it to be displayed in reverse. For example, 
```
- A Windows screensaver file named March 25 \u202Excod.scr will display as March 25 rcs.docx. 
- A JavaScript file named photo_high_re\u202Egnp.js will be displayed as photo_high_resj.png. 
```
A common use of this technique is with spearphishing attachments since it can trick both end users and defenders if they are not aware of how their tools display and render the RTLO character. Use of the RTLO character has been seen in many targeted intrusion attempts and criminal activity. RTLO can be used in the Windows Registry as well, where regedit.exe displays the reversed characters but the command line tool reg.exe does not by default. 

Adversaries may modify a binary's metadata, including such fields as icons, version, name of the product, description, and copyright, to better blend in with the environment and increase chances of deceiving a security analyst or product.

## Windows
In another variation of this technique, an adversary may use a renamed copy of a legitimate utility, such as rundll32.exe. An alternative case occurs when a legitimate utility is moved to a different directory and also renamed to avoid detections based on system utilities executing from non-standard paths. An example of abuse of trusted locations in Windows would be the ```C:\Windows\System32``` directory. Examples of trusted binary names that can be given to malicious binares include "explorer.exe" and "svchost.exe".

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = ["*.doc.*", "*.docx.*", "*.xls.*", "*.xlsx.*", "*.pdf.*", "*.rtf.*", "*.jpg.*", "*.png.*", "*.jpeg.*", "*.zip.*", "*.rar.*", "*.ppt.*", "*.pptx.*"]

Event 2
Sysmon Event ID = 11
file_path = ["*SysWOW64*", "*System32*", "*AppData*"] AND 
file_name = ["*.exe", "*.dll", "*.bat", "*.com", "*.ps1", "*.py", "*.js", "*.vbs", "*.hta"]

Event 3
Sysmon Event ID = 1
Windows Security Event ID = 4688
(process_name = "svchost.exe" AND process_parent_name != "services.exe") OR
process_name = "scvhost.exe"

Event 4
Sysmon Event ID = 1
Windows Security Event ID = 4688
(process_name = "explorer.exe" AND process_parent_name != "userinit.exe")
```
