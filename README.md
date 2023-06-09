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

## Passwords
### Search for Passwords
  1. In a txt file
  ```cmd
  findstr /si password *.txt
  findstr /si password *.ini
  findstr /si password *.xml
  ```
  2. In Config Files
  ```cmd
  dir /s *pass* == *cred* == *vnc* == *.config*
  ```
  3. In all files 
  ```cmd
  findstr /spin "password" *.*
  ```

### Files Worth Checking that have Credentials
  * c:\sysprep.inf
  * c:\sysprep\sysprep.xml
  * c:\unattend.xml
  * %WINDIR%\Panther\Unattend\Unattended.xml
  * %WINDIR%\Panther\Unattended.xml
  ```cmd
  dir c:\*vnc.ini /s /b
  dir c:\*ultravnc.ini /s /b 
  dir c:\ /s /b | findstr /si *vnc.ini
  ```
  
### In Registry
#### VNC
  ```cmd
  reg query "HKCU\Software\ORL\WinVNC3\Password"
  ```
#### Windows autologin
  ```cmd
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
  ```
#### SNMP Parameters
  ```cmd
  reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
  ```
#### Putty
  ```cmd
  reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
  ```
#### Search for Password in Registry
  ```cmd
  reg query HKLM /f password /t REG_SZ /s
  reg query HKCU /f password /t REG_SZ /s
  ```

## Windows Subsystem for Linux
### Locate bash.exe
  ```cmd
  where /R C;\Windows bash.exe
  ```
### Locate wsl.exe
  ```cmd
  where /R C;\Windows wsl.exe
  ```

## Impersonation and Potato Attacks
## RunAs
## Registry
## Exe FIles
## Startup Application
## DLL Hijacking
## Service Permissions (Paths)
## CVE-2019-1388



