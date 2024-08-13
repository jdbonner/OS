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





## processes

### PWSHLL PROCESS commands


View all Processes, not sorted.
Get-Process


View all Processes, sort them by PID.
Get-Process | Sort -Property Id | more


View all processes, but sort by PID and only show the properties I define.
Get-Process | Select Name, Id, Description | Sort -Property Id | more


View only the processes I define and sort by PID
Get-Process SMSS,CSRSS,LSASS | Sort -Property Id


View modules/DLLs used by defined process and their file locations.
Get-Process chrome | foreach {$_.modules} | more
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more


View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.
Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '*chrome*' | more
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more
Pipe in a ft -wrap to see full file name/path.


Use the Get-Ciminstance Win32_Process cmdlet to veiw processes with PPID
1) View Process instances with Win32 process.
Get-Ciminstance Win32_Process


2) View the additional Properties with Get-Member
Get-CimInstance Win32_Process | Get-Member


3) View the processes with PID and PPID sorted by PID
Get-CimInstance Win32_Process | select name,ProcessId,ParentProcessId | sort processid


View an instance of all Win32 (system) services.
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
Pipe in ft -wrap to see full file name/path
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | ft -wrap | more




Powershell process and DLLs

Which Windows commands let us view processes?
PowerShell: Get-Process - Microsoft Reference
CMD: tasklist


View all Processes, not sorted.
Get-Process


View all Processes, sort them by PID.
Get-Process | Sort -Property Id | more


View all processes, but sort by PID and only show the properties I define.
Get-Process | Select Name, Id, Description | Sort -Property Id | more


View only the processes I define and sort by PID
Get-Process SMSS,CSRSS,LSASS | Sort -Property Id


View modules/DLLs used by defined process and their file locations.
Get-Process chrome | foreach {$_.modules} | more
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more


View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.
Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '*chrome*' | more
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more
Pipe in a ft -wrap to see full file name/path.

Use the Get-Ciminstance Win32_Process cmdlet to veiw processes with PPID
1) View Process instances with Win32 process.
Get-Ciminstance Win32_Process

2) View the additional Properties with Get-Member
Get-CimInstance Win32_Process | Get-Member

3) View the processes with PID and PPID sorted by PID
Get-CimInstance Win32_Process | select name,ProcessId,ParentProcessId | sort processid


View an instance of all Win32 (system) services.
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
Pipe in ft -wrap to see full file name/path
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | ft -wrap | more


View all processes
tasklist

Display verbose task information in the output
tasklist /v

Display service information for each process without truncation
tasklist /svc


Display modules/dlls associated to all processes.
tasklist /m | more

Display modules/dlls associated to a specific process.
tasklist /m /fi "IMAGENAME eq chrome.exe"


Formating options
tasklist /fo:{table|list|csv}`
tasklist /fo:table | more
tasklist /fo:list | more
tasklist /fo:csv | more


Filtering for specific string/process
tasklist /fi "IMAGENAME eq lsass.exe"


## Viewing services

### commands

In Powershell:
Get-Ciminstance - Microsoft Reference
Get-Service - Microsoft Reference


In Command Prompt:
net start - Shows currently running services
sc query - Microsoft Reference


View only system services and display Name, PID, and the path they are initiated from.
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
Pipe in a ft -wrap to see full pathname.


View all services.
Get-service


View a defined service, showing all properties in list format.
get-service ALG | format-list *


View only currently running services.
Get-Service | Where-Object {$_.Status -eq "Running"}


View Services
sc query


View extended information for all services.
sc queryex type=service


View extended information for all inactive services.
sc queryex type=service state=inactive


View all currently running services.
net start


## Scheduled tasks
### commands

View all properties of the first scheduled task.
Powershell
Get-ScheduledTask | Select * | select -First 1
command line
schtasks /query /tn "IchBinBosh" /v /fo list

What are some Registry keys that can be used for autoruns?
Registry Keys Locations, Locations connected with Services.
HKLM\Software\Microsoft\Windows\CurrentVersion\Run - Local Machine
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\System\CurrentControlSet\Services

Remember that the Users have individual Hives with autoruns as well as the Current User.
HKCU\Software\Microsoft\Windows\CurrentVersion\Run - Current User
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Run - Specific User
HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\RunOnce

The order in which services are loaded can be adjusted.
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder
HKEY_LOCAL_MACHINE\CurrentControlSet\Control\GroupOrderList



Create Task to open listening Port via the PowerShell Process.
Opens port listening on port 6666 every 15 minutes.
1. In CMD, run the following.
schtasks /Create /TN IchBinBosh /SC MINUTE /MO 15 /TR "powershell.exe -win hidden -encode JABMAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAATABpAHMAdABlAG4AZQByACgANgA2ADYANgApADsAJABMAC4AUwB0AGEAcgB0ACgAKQA7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AcwAgADYAMAA="
2. *If the script stops working* - run the following commands instead in Powershell to create a listening port:
$command = '$L=New-Object System.Net.Sockets.TcpListener(6666);$L.Start();Start-Sleep -s 60'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -encodedCommand $encodedCommand

In Command Prompt
schtasks /query | select-string -pattern IchBinBosh -Context 2,4

In PowerShell
Get-ScheduledTask | Select * | select-string -pattern IchBinBosh -Context 2,4

In GUI
Show in either Task Scheduler or AutoRuns.

### Network Connection

Show all Connections in the "Established" state.
Get-NetTCPConnection -State Established


Show netstat help and point out the following:
netstat /?


Displays all TCP/UDP connections with ports in numerical form with PID and executable associated to the connections
netstat -anob | more



## SYSINTERNALS

pslist /?
pslist -s 100 -r 10










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


### process validity

ps 
top
htop
ps -elf
For user-space processes /sbin/init ( PID = 1 )
For kernel-space processes [kthreadd] ( PID = 2 )
grep UID /etc/login.defs
kill -9 <PID> or pkill -9 <process name>
Stop Process = SIGSTOP(19) (pause signal, let’s you continue later, does not kill process)
End Process = SIGTERM(15) (termination signal, the right way, the application can intercept this signal and initiate shutdown tasks such as temp file cleanup)
Kill Process = SIGKILL(9) (kill signal, extreme, only use if SIGTERM doesn’t work, won’t initiate shutdown tasks)


Shows some simple commands and switch options to view Linux processes
ps -elf #Displays processes
  -e #Displays every process on the system
  -l #Lists processes in a long format
  -f #Does a full-format listing
ps --ppid 2 -lf #Displays only kthreadd processes (so, only kernel-space processes)
  Processes spawned from kthreadd will always have a PPID of 2
ps --ppid 2 -Nlf #Displays anything except kthreadd processes (so, only user-space processes)
  -N #Negates the selection
ps -elf --forest #Displays processes in an ASCII tree
  --forest #ASCII art process tree



disown -a && exit #Close a shell/terminal and force all children to be adopted


ps --ppid 1 -lf

List all unit files that systemd has listed as active
systemctl list-units

List all units that systemd has loaded or attempted to load into memory, including those that are not currently active, add the --all switch:
systemctl list-units --all



Two types of cron jobs
  System cron jobs
    run as root and rigidly scheduled
    perform system-wide maintenance tasks (Cleaning out /tmp or rotating logs)
    controlled by /etc/crontab
  
  User cron jobs
    Use 'crontab’ command to create user cron jobs
    stored in /var/spool/cron/crontabs/

Viewing File Descriptors
sudo lsof | tail -30

List all open files for a specific process.
sudo lsof -c sshd


Grab the PID of a process.
ps -elf | grep sshd


List contents for that PID directory.
sudo ls -l /proc/14139
















