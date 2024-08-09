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


# Linux

/etc/init
/etc/profile
.bash_profile and .bashrc files

## Commands

student@linux-opstation-kspt:~$ sudo xxd -l 512 -g 1 /dev/vda
dd if=/dev/vda of=MBRcopy bs=512 count=1


cat /etc/systemd/system/display-manager.service | tail -n 13

man xxd
xxd -l 1 mbroken

> the MBR will always end in 55AA. Otherwise will indicate a problem.








