# Windows_Priv-Esc_Cheatsheet
## Initial Enumeration
### System Enumeration
  ```cmd
  systeminfo
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
  hostname
  wmic qfc
  wmic qfc get Caption,Description,HotFixID,InstalledON
  wmic logicaldisk get Caption,Description,ProviderName
  ```

### User Enumeration
  ```cmd
  whoami
  whoami /priv
  whoami /groups
  net user
  net user administrator
  net localgroup
  net local group administrators
  
  ```

### Network Enumeration
  ```cmd
  ipconfig
  ipconfig /all
  arp -a
  route print
  netstat -ano
  ```

### Password Enumeration
  ```cmd
  findstr /si password *.txt *.ini *.config
  ```

### AV Enumeration
  ```sc
  sc query windefend
  sc queryex type= service
  netsh advfirewall dump
  netsh firewall show state
  netsh firewall show config
  ```

## Kernel Exploits
  1. Get the system info
  ```cmd
  systeminfo
  ```
  2. Run an exploit suggester against the system info
  3. Work through and reasearch the vulnerabilities
  4. Run the exploit
  5. NT Authority\system! 

## Credentials
###
###
###
## Windows Subsystem for Linux
## Impersonation and Potato Attacks
## RunAs
## Registry
## Exe FIles
## Startup Application
## DLL Hijacking
## Service Permissions (Paths)
## CVE-2019-1388



