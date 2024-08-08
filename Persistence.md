# WINDOWS
## Registry keys


## Services
  >services running at system level being changed to a different executable
tasklist /svc

### Commands
  tasklist /svc
  get-ciminstance win32_service | format-list name, pathname

bcdedit | findstr /i winload
> winload.exe = BIOS, winload.efi = UEFI

powershell profiles

checking the spooler

sc query spooler
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services | findstr Spooler
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler

keys
HKCU\Software\Microsoft\Windows\CurrentVersion\Run 
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 
HKLM\Software\Microsoft\Windows\CurrentVersion\Run 
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services



the boot
bcdedit



