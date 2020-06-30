# Spearphishing Attachment
Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.

## Detection
```
Event 1
Sysmon Event ID = 11 
file_name = ["*.docm", "*.xlsm", "*.pptm", "*.ps1", "*.py", "*.js", "*.vbs", "*.hta", "*.bat", "*.slk", "*.jspx", "*.cmd", "*.php", "*.pyw", "*.xla", "*.application", "*.potm", "*.csproj", "*.aspx", "*.exe"]

Event 2
Sysmon Event ID = 13 
registry_key_path = "*trustrecords*", "*TargetObject=*Software\\Microsoft\\VBA\\7.1\\Common*"

```
