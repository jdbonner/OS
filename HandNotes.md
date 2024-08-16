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


## Artifacts
```
Artifacts are objects or areas in the computer system containting information relevant to activities of the users.
Security Identifier Sids, are used for the user specificregistry locations.
get-localUser | select name,sid
get-localuser
get-wmiobject
```
## UserAssist
```
UserAssist keys are located in:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count\
and encoded in ROT13


CEBFF5CD-ACE2-4F4F-9178-9926F41749EA A list of applications, files, links, and other objects that have been accessed
F4E57C4B-2036-45F0-A9AB-443BCFE33D9F Lists the Shortcut Links used to start programs

Example:
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
```
## Windows Background Actiity Moderator (BAM)
```
a Windows service that Controls activity of background applications.
BAM Provides the following:
full path of an executable
last execution date/time.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings #On 1809 and Newer
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings #On 1803 and be

COMMANDS:

#cmd command
systeminfo

#powershell
Get-Computerinfo
Get-ComputerInfo | select osname,osversion,OsHardwareAbstractionLayer

#BAM entries for every user on the system
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\*

#Output shows all users BAM artifacts
wmic useraccount  get caption,sid | more
Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1584283910-3275287195-1754958050-1005'

```
## Recycle Bin
```
A place where deleted things go.

recycle bin is identified by:
SID - determines which user deleted it
Timestamp - When it was deleted
$RXXXXXX - content of deleted files
$IXXXXXX - original PATH and name

C:\$Recycle.bin (Hidden System Folder)

#COMMANDS

#Find the Contents of the Recycle Bin
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName

#Match SID to USER:
wmic useraccount where 'sid="S-1-5-21-1584283910-3275287195-1754958050-1005"' get name

#To find Recycle Bin artifacts for a specific user, match the SID, then append it to the previous command:
Get-Content 'C:\$Recycle.Bin\S-1-5-21-1584283910-3275287195-1754958050-1005\$R8QZ1U8.txt'

```
## Prefetch
```
Prefetch files are created by the windows operating system when an application is run from a specific location for the first time.

Location
Win7/8/10
C:\Windows\Prefetch

Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select -First 8


```
## Jump Lists
```
The Windows 7-10 taskbar (Jump List) is engineered to allow users to “jump” or access items they have frequently or recently used quickly and easily.

First time of execution of application.

Creation Time = First time item added to the AppID file.

Last time of execution of application w/file open.

Modification Time = Last time item added to the AppID file.

Location
Win7/8/10

C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations (C:\Users\king\AppData\Roaming\Microsoft\Windows\Recent)

Show in Explorer:
C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations (C:\Users\king\AppData\Roaming\Microsoft\Windows\Recent)

Programs/Items that were recently used
Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction Continue | select FullName, LastAccessTime
Get-Childitem -Recurse $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName,LastAccessTime
-OR-
Make sure sysinternals is mounted or unzipped
Gci C:\users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations | % {z:\strings.exe -accepteula $_} >> c:\recentdocs.txt

```

## Recent files
```
Registry Key that will track the last files and folders opened and is used to populate data in “Recent” menus of the Start menu.
Tracks last 150 files or folders opened.

Location
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt


#COMMANDS

#Query the Hex Value Stored in the Key
Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'
#With the * we can see the types of files/ information that was recently viewed.
Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt'

#Converting a Single Value from Hex to Unicode
[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."0")

Convert all of a users values from HEX to Unicode
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {
    [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)

```
## Browser Artifacts
```
Stores details for each user account. Records number of times a site is visited (frequency). History will record the access to the file on the website that was accessed via a link. Many sites in history will list the files that were opened from remote sites and downloaded to the local system.

Location
Win7/8/10:
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\history

#Show Location in Explorer so students have a visual reference of where they’re pulling this information from.
Location: C:\Users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\

#AOI
URLS
Current Session/Tabs
Top Sites

#BE SURE TO ACCEPT EULA
-accepteula

Z:\strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula

```

## Auditing

The Auditing Windows portion of this FG covers the concept of Windows Auditing using native tools along with the analysis of generated artifacts using cmd, powershell, or the GUI based program Eventviewer.

Enable auditing on a text file Examples:
```
PS C:\Users\andy.dwyer\Desktop\Audit> new-item C:\Users\andy.dwyer\Desktop\Auditing.txt
    Directory: C:\Users\andy.dwyer\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   2:45 PM              0 Auditing.txt
```
#note location
#see demo

## Event Logs
```
#events that happen in your computer

Locations
*.evtx files accessed by:
Windows Event View Application
Get-eventlog or Get-WinEvent in Powershell
wevtutil in Command Prompt

#COMMANDS

#Powershell
auditpol
auditpol /get /category:"Object Access"
auditpol /set /subcategory:"File System"
auditpol /set /subcategory:"File System" /success:disable
# Command Prompt: Checking System Wide Auditing Policy for all objects
auditpol /get /category:* 

#View Event Logs in Powershell
#Shows the newest/last 10 entries in the system log. Point out what the three dots (…​) mean and how to print the rest of the entry. (ex. | format-table -wrap)
Get-EventLog -LogName System -Newest 10
#Add the format-table -wrap option to print the truncated part of the entry.
Get-EventLog -LogName System -Newest 3 | Format-Table -Wrap

#Search the Security Event Log and show the entire message
#This is all of the information currently in the Security log. Point out the abundance of information that would need to be parsed through.
Get-Eventlog -LogName Security | ft -wrap

#Search through the entire Security log for a specific string
#Explain that you search through all of the log entries using findstr or select-string for specific strings, the biggest difference between the two is that findstr has a case insensitive option — findstr /i <string>
PS C:\> Get-Eventlog -LogName Security | ft -wrap | findstr /i StR1nG 


Get-EventLog is limited to the default Windows Logs of Security, Application, System,and Windows Powershell (Windows 8.1 and up)
Get-Winevent will cover all the default eventlogs and all of the remaining custom application logs


#Finding Log Type to Query
#Lists all of the logs available to Winevent
Get-WinEvent -Listlog *
#Shows the number of logs, point out the volume of possible information
(Get-WinEvent -Listlog *).count
#Search through the list of logs to find logs that pertain to Security
Get-WinEvent -Listlog * | findstr /i "Security"

#Checking If a User Logged on
#Using Get-WinEvent with -FilterHashtable allows you to filter for more than one criteria. In this instance filter for the Security log and the id of 4624 (discussed below).
Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap
#Same command as above with a specific string search using findstr /i.
Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap | findstr /i "generated"


#Checking Powershell Operational Logs
#Output shows searching through PowerShell Operational logs for a specific string.
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object {$_.Message -ilike "*RunspacePool*"} | Format-List
#Command used to search through PowerShell Operational logs for a specific Pipeline ID.
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object {$_.Message -ilike "*Pipeline ID = ##"} | Format-List



#CMD
*Viewing Logs in Command Prompt *
#Use wevtutil (Windows Event Utility) to show all logs available to the command prompt tool using el (enumerate logs)
wevtutil el
#Shows the number of Windows logs, you can use find with \c to count the lines containing the following string \v to invert the following string "" (a null string)
wevtutil el | find /c /v ""
#Shows the Security Log information
wevtutil gli security
#Shows the last 3 events with qe (query event) from the security log and view in human readable format.
wevtutil qe security /c:3 /f:text


```
## Powershell Artifacts
```
PowerShell Transcript is a feature that creates a record of all or part of a PowerShell session to a text file.

#Creates a text file and records part of all of a PowerShell session.
Start-Transcript


#Shows all of the commands entered during the current session.
Get-History


Location:
C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

#Use Get-Content to access the the history
#Prints the contents of the history file
Get-Content "C:\users\$env:username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

#How do I enable Script Block logging?
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f


```


##################################################################




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




## Auditing and Logging

### what is logging
```
Logging is "a record of performance, events, or day-to-day activities"
Offense

How can someone use this data to detect, investigate, and halt my presence within a system?

How can I blend in with standard system activity?

Defense:

How can I use this data to determine actions attempted or taken on a host?

What artifacts or IOCs(Indicators of Compromise) did the adversary leave behind?

```
### logging Daemons
```
logging is controlled by syslog or journald
Both services store their logs in /var/log
```
### Syslog Daemon
```
Syslog stores its logs as human-readable text documents within /var/log. It is configured using files in /etc/rsyslog/

#Logs messages from standard and privileged user authentication facilities to /var/log/auth.log
auth,authpriv.*			-/var/log/auth.log
#Everything except authentication logs is logged to /var/log/syslog
*.*;auth,authpriv.none		-/var/log/syslog
#This line is commented out and nothing will be done with it
#daemon.*			-/var/log/daemon.log
#Logs kernel facility logs with a severities of Emergency, Alert, and Critical to /var/log/kern.log.
kern.critical		        -/var/log/kern.log



mail.info matches all messages produced by the kernel with severity of #equal to and greater than (greater severity) 6/Informational (severity 0 - 6).
mail.!info matches all messages produced by the kernel with severity of #less than and not including (lesser severity) 6/Informational (severity 7).
```
### Filtering syslog log files
```
#Filtering Syslog Output With Grep
cat /var/log/syslog | grep timesyncd
#Grep for the string timesyncd in /var/log/syslog

#Filtering Syslog Output With Grep
cat /var/log/syslog | grep -R "\w*\.\w*\.\w*"
#Using grep to match on the patterns that loosely resemble an IP address or domain names within var/log/syslog





```
### log rotations
```
The concept of Log Rotations limit the content in logs based off defined spans of time for ease of use and administration. If log rotation is not implemented, logs will grow infinitely. Since they are text files, it makes them very hard to read.
A daily cron job runs the logrotate binary controls log rotations. The cron job runs logrotate with the path to its configuration file /etc/logrotate.conf as an argument. /etc/logrotate.conf defines how often logs are rotated.

#Show Log Rotations
cat /etc/logrotate.conf
#Log rotation occurs weekly


#Showing Rotated logs
ls -l /var/log
#Current version of auth.log
-rw-r-----  1 syslog    adm              54651 Feb 26 20:17 auth.log
#auth.log from 1 week ago
-rw-r-----  1 syslog    adm              43270 Feb 20 23:17 auth.log.1 
#auth.log from 2 weeks ago in a zipped file.
-rw-r-----  1 syslog    adm               5069 Feb 14 23:17 auth.log.2.gz


```
### Essential syslog locations
```
#authentication
Any logs having to do with logins and authentication attempts. .
/var/log/auth.log - Authentication related events .
/var/run/utmp - Users currently logged in .. Not in human readable format. Must use last command .
/var/log/wtmp - History file for utmp .. Not in human readable format. Must use last command .
*/var/log/btmp - Failed login attempts

#application
Any logs having to do with programs. .
Apache - Webserver (dir) .
apt - Package Manager (dir) . /var/log/mysql.log


#system
/var/log/messages - Legacy Catch all
/var/log/syslog - Ubuntu/Debian Catch all
dmesg = Device Messenger (queires /proc/kmsg)
  Kernel Ring Buffer - Never fills
  First logs generated by the system

#Logging at a Glance
Location: All logs are in /var, most are in /var/log
Config File: /etc/rsyslog.conf
Service: /usr/sbin/rsyslogd

```
##Journald logs
```
Journald or systemd-journald.service is the logging daemon for systemd init Linux systems. It logs everything in regards to *.units from unit startup status to logs generated by each individual unit.
Journald stores its logs in binary form.
journalctl is the open command that reads them.

Basic Journal ctf usage
journalctl -e 
Tell journalctl to show the last logs its received with -e.

```
### Journald Features
```
#1. Filtering logs by Boot
#Show boot ids which separate logs based on when the machine was restarted
journalctl --list-boots
#Tell journalctl to only show logs relating to that boot id.

journalctl -b b3076f6774b841e08c19236bf327f529

#2. Filtering Logs by a specific unit
#Show only ssh.service logs in journalctl
journalctl -u ssh.service

#3. Filtering Logs since a specific time period
#Only show logs pertaining to ssh.service from up to 2 days ago in journalctl
journalctl -u ssh.service --since "2 days ago"


```
## Log Formats
```
Simple Text Documents, Markup Languages, and JavaScript Object Notation (JSON).

#Simple Text Documents
ctrl-f searches or grep

#Syslog Message Format

#Markup Languages
Uses a schema like HTML so it has tags and attributes like a webpage. Also, it is serialized.

#XML Example
Xpath Syntax: xpath -q -e '//element/@attribute' file.xml


#grabs all ips from xml
xpath -q -e '//host/address/@addr | //host/ports/port/@portid' output.xml

```
## JavaScript Object Notation (JSON)
```
Serialized data interchange format designed to be parsed by machines.

#example
{"ts":1615383120.600619,"uid":"CLdOLa12ikO7IbVX0d","id.orig_h":"10.50.24.73","id.orig_p":19831,"id.resp_h":"192.168.65.20","id.resp_p":110,"proto":"tcp","duration":0.000010013580322265625,"orig_bytes":0,"resp_bytes":0,"conn_state":"REJ","missed_bytes":0,"history":"Sr","orig_pkts":1,"orig_ip_bytes":60,"resp_pkts":1,"resp_ip_bytes":40}

Kind of difficult to parse because its length. Try pretty printing it at the following link: https://jsonformatter.org/json-pretty-print
Like XML, JSON needs can be queried using special programs. To query JSON use jq or JSON Query.
Here is a JSON Query Tutorial - https://docs.jsonata.org/simple
Here is a Online JSON Query tool - https://jqplay.org/
Here is a jq Syntax Overview - https://www.linode.com/docs/guides/using-jq-to-process-json-on-the-command-line/
Here is a jq Cheat sheet - https://cheat.sh/jq

https://docs.jsonata.org/simple
https://jqplay.org/
https://www.linode.com/docs/guides/using-jq-to-process-json-on-the-command-line/
https://cheat.sh/jq

#command examples

cat conn.log | jq .

cat conn.log | jq '."id.orig_h"' | sort -u | wc -l

cat conn.log | jq 'select(.resp_bytes >= 40).ts' | wc -l # select the ts line from all blocks where "resp_bytes" >= 40 and gets the count
cat conn.log | jq '.resp_bytes >= 40' | grep "true" |wc -l # gets boolean values for each resp_bytes value, filters out falses and gets the count



```











#####################################

# Memory Analysis
```
Memory forensics (also known as memory analysis) refers to the analysis of volatile data in a computer’s memory. Information security professionals conduct memory forensics to investigate and identify attacks or malicious behaviors that do not leave detectable tracks on hard drive data.

Bash history writes to ~/.bash_history
If a user deletes ~/.bash_history , recovery of data is still possible.
Volatility reads deleted or modified logs and scraped from memory using the mfind, mcat & mls plugins.

Order of Volatility From Most to Least
CPU registers, cache
Routing table, ARP cache, process table, kernel stats, memory
Temporary file systems
Disk
Remote logging and monitoring data
Physical configuration, network topology
Archival media - backups



```





