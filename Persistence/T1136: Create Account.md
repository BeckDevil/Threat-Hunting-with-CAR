# T1136: Create Account
Adversaries with a sufficient level of access may create a local system, domain, or cloud tenant account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

## Windows
The net user commands can be used to create a local or domain account.

## Office 365
An adversary with access to a Global Admin account can create another account and assign it the Global Admin role for persistent access to the Office 365 tenant

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = ["*New-LocalUser*", "*net*user*add*"]
