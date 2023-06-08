# Windows_Priv-Esc_Cheatsheet
## Initial Enumeration
### System Enumeration
  ```bash
  systeminfo
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
  hostname
  wmic qfc
  wmic qfc get Caption,Description,HotFixID,InstalledON
  wmic logicaldisk get Caption,Description,ProviderName
  ```

## Kernel Exploits
## Credentials
## Windows Subsystem for Linux
## Impersonation and Potato Attacks
## RunAs
## Registry
## Exe FIles
## Startup Application
## DLL Hijacking
## Service Permissions (Paths)
## CVE-2019-1388



