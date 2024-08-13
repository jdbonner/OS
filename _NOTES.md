# Resources
```
###############################RESOURCES###############################
#OS Activities
http://10.50.22.197:8000/
#Student Guide
https://os.cybbh.io/public
stack number: 2
10.50.38.199

```
# Login
```
###############################ACTIVITIES LOG###############################
#username
JOBO-M-006
#pw hint
Favorite DS3 knight
###############################BLANK###############################
###############################REMOTE COMMAND###############################
https://cctc.cybbh.io/students/students/latest/Day_0_Setup.html

#command for xfreerdp
xfreerdp /u:$USER /v:$IP_ADDRESS> /dynamic-resolution +glyph-cache +clipboard
xfreerdp /u:student /v:10.50.38.199 /dynamic-resolution +glyph-cache +clipboard


###############################END###############################
```
# Day 1
```
##############################################################DAY 1##############################################################
###############################$PROFILE###############################
$PROFILE 
PowerShell supports several profile files and host programs, like Windows, support their own specific profiles. 
The profiles below are listed in order of precedence with the first profile having the highest precedence.

All Users, All Hosts
$PsHome\Profile.ps1

All Users, Current Host
$PsHome\Microsoft.PowerShell_profile.ps1

Current User, All Hosts
$Home\[My]Documents\Profile.ps1

Current User, Current Host
$Home\[My ]Documents\WindowsPowerShell\Profile.ps1



###############################END###############################
##############################################################END OF DAY 1##############################################################
```
# Day 2
```
##############################################################DAY 2##############################################################
###############################WINDOWS REGISTRY###############################
1. Windows Registry Introduction
The The Windows Registry is a central hierarchical database used in Windows to store information that is necessary to configure the system for one or more users, applications, and hardware devices.

Think of the Windows Registry like a huge Rolodex.

everything in Windows has a card/place with all of it’s information.

Includes location, information, settings, options, and other values for programs and hardware installed

Why is the registry important?

Anyone can hide all sorts of data including passwords, malicious code, and executable/binary files in the Registry.

They can effectively hide data in registry keys’ value entries.

By using different encoding techniques, they could obfuscate or hide data from forensic examiners.

It is important to know what right looks like and the places that are most likely to be compromised by a malicious actor.

Comparing the Registry in Windows to Linux
The registry in Windows is like a combination of multiple directories in Linux.

For example: Driver information is kept in the registry in Windows, but in /dev in Linux.

System configurations in Windows are in HKEY_LOCAL_MACHINE, but in /etc (and a few other directories) in Linux.

2. Registry structure
2.1 Registry Keys and Values
The registry is comprised of Keys, Subkeys and Values structured in a tree format.

Keys - are known as Registry Hives and can contain subkeys and values.

Subkeys - can contain subkeys and values

Values - contain data in specific formats.

2.2 Registry Hives or Root Keys
A registry hive is a group of keys and thier associated values that are loaded when the system is started or a specific user logs in.

There are five Registry Hives

HKEY_LOCAL_MACHINE

HKEY_USERS

HKEY_CURRENT_USERS

HKEY_CURRENT_CONFIG

HKEY_CLASSES_ROOT



HKEY_LOCAL_MACHINE (HKLM)
Contains configuration information for the entire computer. Its values are read every time the machine is started regardless of the user who logs in. Its subkeys are :
HARDWARE - contains a database of installed devices along with their drivers
SAM - Security Account Manager stores user and group accounts along with NTLM hashes of passwords
Security - Local Security policy accessed by lsass.exe used to determine rights and permissions for users on the machine
System - Contains keys pertaining to system startup such as programs started on boot or driver load order.



HKEY_USERS (HKU)
Contains all all user profiles on the system. Contains one key per user on the system. 
Each key is named after the SID(Security Identifier) of the user.

-User Environment settings for the desktop
-shortcuts
-File associations

A SID has four components:
SID = S-1-5-21-2948704478-3101701159-1111693228-1002
S represents SID
1 revision level (1) - Indicates the version of the SID structure that’s used in a particular SID.
An identifier authority (5, NT Authority) - Identifier Authority: This is a series of digits that identifies the entity that issued the SID. 
In the case of Active Directory, the identifier authority is always "5" for the Security IDentifier Authority (SID Authority).
A domain identifier 21-2948704478-3101701159-1111693228 (48 bit (6 byte) numbers)

Some HKEY_USERS are called Well Known SIDs.. They identify default accounts in Windows used for various purposes. 
In this example the 21 represents the subauthority within the domain identifier. Examples include:
S-1-5-18 refers to LocalSystem account.
S-1-5-19 refers to LocalService account. It is used to run local services that do not require LocalSystem account.
S-1-5-20 refers to NetworkService account. It is used to run network services that do not require LocalSystem account.
S-1-5-21-domain-500 Refers to the built in local administrator account.
-1002 = RID A variable number of subauthority or relative identifier (RID) values that uniquely identify the trustee relative to the authority that issued the SID




HKEY_CURRENT_USER (HKCU)
HKEY_CURRENT_USER is the copy of the logged in user’s registry key based on thier SID from HKEY_USERS.

HKEY_USERS (HIVE)
              └──SID (S-1-5-21-3939661428-3032410992-3449649886-XXXX) (Key)
HKEY_USERS\S-1-5-21-3939661428-3032410992-3449649886-XXXX



HKEY_CURRENT_CONFIG (HKCC)
HKEY_CURRENT_CONFIG is a symbolic link (pointer or shortcut or alias) to the following registry key:

HKEY_Local_Machine (HIVE)
              └──SYSTEM (Key)
                      └──CurrentControlSet (Subkey)
                                    └── Hardware Profiles (Subkey)
                                                └── Current (Subkey)
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current




HKEY_CLASSES_ROOT (HKCR)
HKEY_CLASSES_ROOT is a symbolic link (pointer or shortcut or alias) to the following registry key:

HKEY_Local_Machine (HIVE)
              └──Software (Key)
                      └──Classes (Subkey)
HKEY_LOCAL_MACHINE\Software\Classes

Contains file name extension associations and COM class registration information such as ProgIDs, CLSIDs, and IIDs.

It is primarily intended for compatibility with the registry in 16-bit Windows

###############################END###############################
###############################BLANK###############################
2.3 Registry Structure and Data Types


Table 1. Registry Path Hive and Supporting Files
HKLM\SAM

SAM, SAM.LOG

HKLM\SECURITY

SECURITY, SECURITY.LOG

HKLM\SOFTWARE

software, software.LOG, software.sav

HKLM\SYSTEM

system, system.LOG, system.sav

HKLM\HARDWARE

(Dynamic/Volatile Hive)

HKU\.DEFAULT

default, default.LOG, default.sav

HKU\SID

NTUSER.DAT

HKU\SID_CLASSES

UsrClass.dat, UsrClass.dat.LOG

The above Table shows the registry path and their corresponding hives on disk.

All hives in HKLM are stored in %SYSTEMROOT%\System32\config\ (%SYSTEMROOT% usually refers to C:\WINDOWS).

HKLM\HARDWARE is a dynamic hive that is created each time the system boots and it is created and managed entirely in memory.

HKU\SID hive file is stored in user home directory, which is %USERPROFILE%\NTUSER.DAT.

HKU\SID_CLASSES hive file correspond to "%USERPROFILE%\Application Data\Local\Microsoft\Windows\UsrClass.dat"

Table 2. Types of extensions and what they mean (Might be hidden)
No extension

Actual Hive File

.alt extension

Backup copy of hive, used in Windows 2000

.log extension

Transaction log of changes to a hive

.sav extension

Backup copy of hive created at the end of text-mode (console)







###############################END###############################
###############################BLANK###############################
3. Registry Manipulation
3.1 View/manipulate the registry with a GUI
regedit.exe

GUI

Located at C:\Windows\regedit.exe

Can connect to a remote registry, but only using the PC’s workgroup or domain Name

Needs the RemoteRegistry Service (svchost.exe / regsvc.dll) to be running to work

Commonly disabled using group policy

Can load hives files from disk to the active registry

Can export binary .hiv files as well as text .reg files

Can only query HKLM and HKU remotely

Regedit.exe shares similarities with the C: drive file hierarchy. Keys can be manipulated just like files.
Using Regedit.exe to query the Registry
Click on the search bar and type in regedit.exe
If prompted by UAC, click yes
Click on the drop down for HKEY_CURRENT_USER
Click the drop down for Software
Click the drop down for Microsoft
Click the drop down for Windows
Click the drop down for CurrentVersion
Click the drop down for Run
We have successfully queried a key using regedit.exe


3.2 View/manipulate the registry via CMDLINE
reg.exe

CLI

Located at C:\Windows\System32\reg.exe

Can connect to a remote registry, using the PC’s NetBios Name or IP address

Does not have to be in workgroup/domain. Only need username/password

Needs the RemoteRegistry Service (svchost.exe / regsvc.dll) to be running to work

Can load hives files from disk to the active registry

Available in XP and beyond

Can only export text .reg files

Can only query HKLM and HKU remotely

Reg.exe Syntax

More Reg.exe Syntax

Reg.exe help
reg /?                    #Displays help for all of the reg.exe commands
reg query /?              #Displays help for the `reg query`
reg add /?                #Displays help for `reg add`
reg delete /?             #Displays help for `reg delete`
Reg query - Reads keys from specific registry locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Reg add - Adds keys to specific registry locations
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme /t REG_SZ /d C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
The /v stands for Value; In this case the name of this Key Value.

The /t stands for Type; Types can be any of the Data Types that we went over earlier.

The /d stands for Data; Is what is the actual Data or in this case a command to open a file every time the system is ran.

Reg delete - Deletes Keys
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme
3.3 Registry Manipulation with PowerShell


Certain Root Hives are loaded automatically into PSDrives (HKLM: and HKCU:); navigation of the registry is very similar to folder⇒file

Minimum commands to know
Query

Get-ChildItem cmdlet gets the items in one or more specified locations.

Get-ItemProperty cmdlet gets the items in one or more specified locations.

Get-Item cmdlet gets the item at the specified location. It doesn’t get the contents of the item at the location unless you use a wildcard character (*) to request all the contents of the item.

Modify

Set-ItemProperty cmdlet changes the value of the property of the specified item. example, changing setting to :true or :false.

Remove-ItemProperty cmdlet to delete registry values and the data that they store.

Create

New-Item cmdlet creates a new item and sets its value. In the registry, New-Item creates registry keys and entries.

New-Itemproperty cmdlet creates a new property for a specified item and sets its value. Typically, this cmdlet is used to create new registry values, because registry values are properties of a registry key item.



3.3.1 Reading Registry Objects with PowerShell
Get-ChildItem - Reads sub keys from the input value
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 

Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ 
The returns nothing because it is listing the sub keys of \Run.
Run has no sub keys, only values.

Returns sub keys of \CurrentVersion
Get-Item - Reads the value of the inputted object
Get-item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Notice how the output of the command is different than Get-ChildItem.

It reads key values, not sub keys.



3.3.2 Creating Registry objects with Powershell
New-Item - Creates a new sub key associated within a hive
New-Item "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Force
Creates a new sub key in Trusted Documents for document.doc

Trusted documents is for documents with active content i.e. embedded macros.
New-ItemProperty - Creates a new value associated with a sub key
New-ItemProperty "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc" -PropertyType Binary -Value ([byte[]](0x30,0x31,0xFF)) 

New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -PropertyType String -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
Creates a new value in the \TrustRecords key
Creates a value in the \Run key
Outside of the scope of the class but in case you want to know more about that byte array


3.3.3 Modifying Registry objects with PowerShell
Rename-ItemProperty - Modifies a value associated with a sub key
Rename-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name SecurityHealth -NewName Test
Remove-ItemProperty - Removes a value associated with a sub key
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc"
Set-ItemProperty - Change the value of a sub key
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -Value Bacon.exe


3.4 Sethc.exe Demonstration
Demo: Demonstrate the application of a registry "tweak" via the GUI and CMD-line using sethc.exe.

What is sethc.exe?

Windows contains a feature called stick keys, which is an accessibility feature to help Windows users who have physical disabilities.

It essentially serializes keystrokes instead of pressing multiple keys at a time, so it allows the user to press and release a modifier key, such as Shift, Ctrl, Alt, or the Windows key, and have it remain active until any other key is pressed.

You activate stick keys by pressing the Shift key 5 times. When you activate stick keys, you are launching a file, C:\Windows\System32\sethc.exe, which executes as SYSTEM.

While this exploit is protected by current AV, you still might see it in customer networks who don’t follow DISA STIGs.



Create a new Registry key using PowerShell
This will create a backdoor onto a box which will trigger Windows Defender. So first we need to disable it.
Disable Windows Defender Real Time Protection
Set-MpPreference -DisableRealtimeMonitoring $TRUE
Sometimes, the previous command may not work as expected. In such cases, you can follow these steps:
Click the Windows button in the lower-left corner of your desktop.
Navigate to "Virus & threat protection."
Under "Virus & threat protection settings," click "Manage settings."
Finally, toggle off "Real-Time protection." These steps will help you turn off real-time protection using the Windows Security interface.
Create a new Registry key using New-Item in PowerShell
new-item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
Create a new Registry key property using New-ItemProperty in PowerShell
New-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger -Type String -Value C:\Windows\System32\cmd.exe
Calling our new value in order to privilege escalate
Rapidly press the SHIFT key 5 times

A command shell opens

Type whoami

You should be army\john.huntsman or whoever your user account is

Now log off the system and press the SHIFT key 5 times

A command shell opens

Type whoami

Now you are NT AUTHORITY\SYSTEM

As SYSTEM user, we could open the Registry and copy the SAM database to access password hashes
Create a network share to Sysinternals
net use * http://live.sysinternals.com
The net use command allows us to map a network location and navigate it like it is a local directory.

You can run net use and it will show detailed information about currently mapped drives and devices.

Additionally you can run net use /help for a listing of most common parameters.

Type *autoruns -accepteula*
If we are running remote operations on a target, if we run a SysInternals command for the first time, we will be prompted by a popup to accept the EULA. The -accepteula switch will prevent this and prevent us from being discovered.
Using Autoruns to view the created Registry key
In Autoruns, click on the Image Hijacks Button
Right click on the sethc.exe and select Jump to Entry…​
Right click on the sethc.exe key and select export
Name the file "Totally Legit Windows Update" and save it to your Desktop
Delete the sethc.exe key using the GUI

###############################END###############################
###############################BLANK###############################
4. Powershell PSDrives
What is a PowerShell PSDrive?
A Windows PowerShell drive is a data store location that you can access like a file system drive in Windows PowerShell.

You cannot access them by using other Windows tools, such as File Explorer or Cmd.exe.

Basically, a PSDrive creates a temporary or permanent way for PowerShell to navigate the registry just like you could navigate the file system.

Another way to create/use a remote connection is to use PSDrive (PowerShell Drive).

A group of providers connect different forms of storage to PowerShell and make them look like and perform like a file system.



Finding current PSDrives
Get-PSDrive
To create a new Windows PowerShell drive, you must supply three parameters:

A Name for the drive (you can use any valid Windows PowerShell name)

The PSProvider (use "FileSystem" for file system locations, "Registry" for registry locations, and it could also be a shared folder on a remote server.)

The Root, that is, the path to the root of the new drive.



Table 3. What are PSDrive Providers
Providers: "Registry" - for registry locations, "FileSystem" for file system locations

Certificate: for any installed digital certificates

Alias: for aliases used by PowerShell

Function: Provides access to the functions defined in PowerShel

Variable: supports the variables that PowerShell creates, including the automatic variables, the preference variables, and the variables that you create.

WSMAN: (Web Services Manager)lets you add, change, clear, and delete WS-Management configuration data on local or remote computers.

Environment: Provides access to the Windows environment variable.

Table 4. What are PSDrive Names?
PSDrive uses Names for each drive.

Names of the drive can be longer than just a letter and can be as explanatory as you want.

PowerShell needs a : (colon) after the name to change directory to the drive.

Table 5. What’s this all a Root?
Root specifies the data store location to which a PowerShell drive is mapped of a local computer, a remote computer, or even a website.

When Root is a UNC (Universal Naming Convention) path, such as \\Server\Share, the credential specified in the value of the Credential parameter is used to create the PSDrive.

Show all Environmental Variables in the Env: directory
Get-ChildItem Env:
Show all Environmental Variables in the GUI
Control Panel > System > click on Advanced system settings.
Then click on Environmental Variables.
The results should be the same as GCI ENV.
Make a directory for our demo
mkdir demo
Creating a PSDrive
New-PSDrive -Name Demo -PSProvider FileSystem -Root c:\Demo   #Review command: Get-Help New-PSDrive for this syntax.
Show the difference from changing directory to C:\Demo and Demo:
cd C:\Demo
cd Demo:
Creating an invalid PSDrive
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USER
This will create an error. Try and mount the new drive and watch it error out. PowerShell will allow you to create a directory with a Root location that doesn’t exist.
Mounting invalid PSDrive
gci HKU:
Get-ChildItem HKU:
Delete the bad PSDrive
Remove-PSDrive HKU
Now create the drive correctly
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
Changing directories with PowerShell
cd Registry::HKEY_LOCAL_MACHINE 
cd HKU: 
C: 
Changing directories the default way in PowerShell
Changing directories after mounting with PSDrive
Changing back to c:\ drive
PSDrive Can be used to create shortcuts to commonly used file locations too.
New-PSDrive -Name Desktop -PSProvider FileSystem -Root C:\users\student\Desktop
cd Desktop:
Creating a Shortcut to the Run Key
New-PSDrive -Name HKLM-Run -PSProvider Registry -Root HKEY_Local_Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
cd HKLM-Run:
We can also map network shares with New-PSDrive.
Emulating net use functionality with New-PSDrive
[String]$WebDAVShare = '\\live.sysinternals.com\Tools'          
New-PSDrive -Name S -PSProvider FileSystem -Root $WebDAVShare   
cd S:                                                           
Creating a string variable of '\\live.sysinternals.com\Tools' as if we do not it will fail out.
Using our new Variable $WebDAVShare we can now successfully create the drive.
Changing directories to our link '\\live.sysinternals.com\Tools'.
Map to an Internal Server
New-PSDrive -Name FileServer -PSProvider FileSystem -Root "\\file-server\warrior share"
Disable the task manager using the Regedit GUI
In regedit, navigate to HKCU/SOFTWARE/MICROSOFT/WINDOWS/CURRENTVERSION/POLICIES
Make a new key called "System" by right clicking and selecting New then Key
Add a new DWORD value to that key called "DisableTaskMgr" by right clicking and selecting New then DWORD
Double click the new value and change the 0 to a 1
Try to open task Manager (you will see that you cannot)
Remove the new key by right clicking the key and selecting delete
###############################END###############################
###############################BLANK###############################
5. Registry Locations of Interest


5.1 Do I need to remember all of the locations in the Registry?
The Registry in a Windows 10 Computer has over 3 million entries; it is impossible to know them all.

It is more important to understand the concepts supporting the Windows Registry than to know millions of keys.



5.2 Registry Changes
Changes to the registry often require a restart, as many programs read the registry values upon load.

Whether the entire system needs to be restarted, or just a program, depends on the registry setting changes.

Some changes do take effect immediately, as we saw with the disable taskmgr key that was created.

It is also important to note that some parts of the registry are always loaded into memory.



5.3 Forensically Relevant Keys
These are keys that hold any type of information that can be used to gather intelligence or track events.

These are some but not all of the keys that can be considered relevant to you or your mission set.

SANS Registry Cheat Sheet

Why do we care?
We are looking for keys that can be used for Persistence

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access

As well as Privilege Escalation.

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network.


Microsoft Edge Internet URL history and Browser Artifacts and Forensics

HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\Children\001\Internet Explorer\DOMStorage



USB history / USB Forensics

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB

This registry key contains information about all USB devices that have been connected to the system at some point, regardless of whether they are currently connected or not. It includes information about the USB controllers, hubs, and individual devices. Each device is typically identified by a unique identifier (like a device instance path or hardware ID).

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR

This registry key specifically deals with USB storage devices, such as USB flash drives, external hard drives, etc. It contains information about connected USB storage devices, including details like device instance paths, hardware IDs, and other configuration information.



Recent MRU history / MRU in forensics
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

MRU is the abbreviation for most-recently-used.

This key maintains a list of recently opened or saved files via typical Windows Explorer-style common dialog boxes (i.e. Open dialog box and Save dialog box).

For instance, files (e.g. .txt, .pdf, htm, .jpg) that are recently opened or saved files from within a web browser (including IE and Firefox) are maintained.



Recent Files with LNK files
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs



Windows User Profiles User Account Forensics

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList



Saved Network Profiles and How to decode Network history
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles



Windows Virtual Memory and why it is important
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management

This key maintains Windows virtual memory (paging file) configuration.

The paging file (usually C:\pagefile.sys) may contain evidence/important information that could be removed once the suspect computer is shutdown.



Recent search terms using Windows default search and Cortana
HKEY_CURRENT_USER\Software\Microsoft\Windows Search\ProcessedSearchRoots

Index of Search results by SID

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search

Recent files searched



5.4 Registry locations that can be utilized for persistence
Persistence According to MITRE

Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder - MITRE

Table 6. System-wide and per-user autoruns
HKLM\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run

HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKLM\SYSTEM\CurrentControlSet\services

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon



5.5 Critical Registry Locations
These are keys that have value for red and blue teams to be taken advantage of.

HKLM\BCD00000000

Replacement of old boot.ini file

HKLM\SAM\SAM

Use "psexec -s -i regedit" from administrator cmd.exe to view the SAM

It opens a new regedit.exe window with system permissions

PSEXEC is a SYSINTERNALS tool.
HKU\<SID>\Software\Policies\Microsoft\Windows\System\Scripts

Group policy Logon/Logoff Scripts defined here
###############################END###############################
###############################BLANK###############################
6. Security
Each key in the registry of Windows NT versions can have an associated Security Descriptor.

The security descriptor contains an Access Control List (ACL) that describes which user groups or individual users are granted or denied access permissions.

An ACL is a list of Access Control Entries (ACE). The security descriptor can be explicit or inherited from a parent object.

Each ACE in an ACL identifies a trustee and specifies the access rights allowed, denied, or audited for that trustee.

The security descriptor for a securable object can contain two types of ACLs: a DACL and a SACL.

A Discretionary Access Control List (DACL) identifies the trustees that are allowed or denied access to a secured object.

A System Access Control List (SACL) enables administrators to log attempts to access a secured object.

Table 7. Registry permissions
Permission

Description

Query Value

The right to read the registry key value.

Set Value

The right to write a new value

Create Subkey

The right to create subkeys.

Enumerate

Subkeys Allow the enumeration of subkeys.

Notify

The right to request change notifications for registry keys or subkeys.

Create Link

Reserved by the operating system.

Delete

The right to delete a key.

Write DACL

The right to modify permissions of the container’s DACL.

Write Owner

The right to modify the container’s owner.

Read Control

The right to read the DACL.

Special ACEs on the security descriptor can also implement Mandatory Integrity Control for the registry key and subkeys.

A process running at a lower integrity level cannot write, change or delete a registry key/value, even if the account of the process has otherwise been granted access through the ACL.

An example would be if Internet Explorer is running in Protected Mode and can read medium and low integrity registry keys/values of the currently logged on user, but it can only modify low integrity keys.
Windows Resource Protection uses security to deny Administrators and the system WRITE access to some sensitive keys to protect the integrity of the system from malware and accidental modification.
###############################END###############################
##############################################################ADS##############################################################
###############################BLANK###############################
1. Alternate Data Streams
ADS was first introduced to NTFS in Windows NT 3.1 and was Microsoft’s attempt at implementing filesystem forks in order to maintain compatibility with other filesystems like Apple’s HFS+ and Novell’s NWFS and NSS.

In NTFS – files consists of attributes, security settings, mainstreams and alternate streams. By default, only the mainstream is visible.

ADS has been used to store metadata, like file attributes, icons, image thumbnails.

Great way to hide data using NTFS.

Can be scanned by antivirus (Windows Defender Smartscreen is ADS aware).

Does not change the MD5 hash of the file.

Deleted once copied to a fat32.

Cannot be disabled.

[filename.extension]:[alternate_stream_name]:$DATA

###############################END###############################
###############################BLANK###############################
2. Alternate Data Streams in Command Prompt
The demonstrations below are the basics of creating and viewing alternate data streams on a file and directory. The ADS demo will need a elevated command prompt (cmd.exe) and also an elevated PowerShell or PowerShell ISE window. You should understand that just because something isn’t viewable by normal means, doesn’t mean something isn’t hidden. It thus becomes important to understand the commands used to enumerate, recognize indicators, and list contents for ADS.



Perform steps below in an elevated CMD shell.

1. Creating a regular data stream on a file
C:\windows\system32>echo Always try your best > reminder.txt 

C:\windows\system32>dir reminder.txt 
 Directory of C:\windows\system32
 02/27/2021 07:13 PM                 25 reminder.txt
                1 File(s)            25 bytes
                0 Dir(s) 20,060,768,688 bytes free

C:\windows\system32>type reminder.txt 
Always try your best
echo content Always do your best into new file called reminder.txt.
dir, for files, displays the file name extension and size in bytes.
type displays contents of a text file, showing Always do your best.


2. Creating an Alternate Data Stream on a file
C:\windows\system32>echo social security numbers > reminder.txt:secret.info 

C:\windows\system32>dir reminder.txt 
 Directory of C:\windows\system32
 02/27/2021 07:13 PM                  23 reminder.txt
                 1 File(s)            23 bytes
                 0 Dir(s) 20,060,712,960 bytes free

C:\windows\system32>type reminder.txt 
Always try your best
echo content social security numbers into the ADS :secret.info of reminder.txt.
dir shows no visible change to reminder.txt even after previous added ADS content.
type shows no visible change to content of reminder.txt even after previous added ADS content.
Refs: dir / echo / type



3. Viewing an Alternate Data Stream on a file.
C:\windows\system32>more < reminder.txt:secret.info 
social security numbers

C:\windows\system32>notepad reminder.txt:secret.info 

C:\windows\system32>dir /R reminder.txt 
 Directory of C:\windows\system32
 02/27/2021 07:13 PM                   23 reminder.txt
                                       26 reminder.txt:secret.info:$DATA
                1 File(s)              23 bytes
                0 Dir(s)   20,060,557,312 bytes free

C:\windows\system32>type reminder.txt:secret.info 
The filename, directory name, or volume label syntax is incorrect.
Read contents of reminder.txt:secret.info into more, showing ADS content social security numbers.
Shows another way to view ADS content using notepad.
dir /R displays the ADS info (not the same as listing the ADS contents however). $DATA will be discussed later.
Unfortunately, some commands and applications like the type are unable to list ADS content.


4. Creating and Viewing an Alternate Data Stream on a directory
C:\windows\system32>mkdir kids 

C:\windows\system32>echo top-secret information > kids:hidden.txt 

C:\windows\system32>dir /R kids 
 Directory of C:\windows\system32\kids
 02/27/2021 07:29 PM      <DIR>           .
                                       25 .:hidden.txt:$DATA
 02/27/2021 07:29 PM      <DIR>           ..
               0 File(s)                0 bytes
               2 Dir(s)    20,060,160,000 bytes free

C:\windows\system32>more < kids:hidden.txt 
top-secret information
mkdir creates a directory called kids.
echo writes content top-secret information in ADS to kids:hidden.txt.
dir /R shows ADS info for kids directory. Notice the ADS hidden.txt created earlier and the main stream $DATA.
more shows ADS contents of kids:hidden.txt and we see top-secret information.
###############################END###############################
###############################BLANK###############################
3. Alternate Data Streams in PowerShell
1. Creating a regular data stream on a file.
PS C:\windows\system32>echo "Always do your best" > reminder.txt 

PS C:\windows\system32>Get-ChildItem .\reminder.txt 
    Directory: C:\windows\system32
Mode                LastWriteTime        Length  name
----                -------------        ------  ----
-a----           2/28/2021  2:40 AM          44   reminder.txt

PS C:\windows\system32>Get-Content reminder.txt 
Always do your best
echo content Always do your best into a new file called reminder.txt.
Get-ChildItem, just like dir example, will show a file’s attributes, last modified time (LastWriteTime), size (Length), and name.
Get-Content shows the content of the file reminder.txt: Always do your best.


2. Creating an Alternate Data Stream on a file.
PS C:\windows\system32>Set-Content .\reminder.txt -Value "social security numbers" -Stream secret.info 

PS C:\windows\system32>Get-Childitem reminder.txt 
    Directory: C:\windows\system32
Mode                LastWriteTime        Length  name
----                -------------        ------  ----
-a----           2/28/2021  2:41 AM          44   reminder.txt

PS C:\windows\system32>Get-Content reminder.txt 
Always do your best
Set-Content writes new or replaces existing content in a file; Using -Value and -Stream to create an ADS on reminder.txt.
Get-Childitem shows no visible change to reminder.txt even after previous added ADS content.
Get-Content shows no visible change to content of reminder.txt even after previous added ADS content.


3. Viewing an Alternate Data Stream on a file.
PS C:\windows\system32>Get-Item reminder.txt -Stream * 
PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\reminder.txt::$DATA
PSParentPath : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
PSChildName : reminder.txt::$DATA
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\windows\system32\reminder.txt 
Stream        : :$DATA 
Length        : 44

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\reminder.txt:secret.info
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
PSChildName  : reminder.txt:secret.info
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\windows\system32\reminder.txt
Stream        : secret.info 
Length        : 25

PS C:\windows\system32>Get-Content reminder.txt -Stream secret.info 
social security numbers
Get-Item with the -Stream option allows us to see all streams for *reminder.txt.
FileName property provides the full path info for reminder.txt.
Stream property lists $DATA which is the main stream and commonly expected on most files. $DATA is the actual content.
Stream property lists secret.info which is an ADS to be investigated since it is outside the norm.
Get-Content with option and value -Stream secret.info gets us our ADS content, social security numbers.
The last command can be further improved to list only the FileName and Stream properties.
Get-Item reminder.txt -Stream * | select FileName,Stream
###############################END###############################
###############################BLANK###############################
4. Malicious Alternate Data Streams
In this demonstration, we will show how malicious logic can be embedded in an Alternate Data Stream to execute on a system. There are a plethora of ways a malicious ADS could be triggered to exploit vulnerabilities in a system and grant access or establish persistence for a bad guy.

1. Creating a Malicious Alternate Data Stream
PS C:\windows\system32> Write-Output "Nothing to see here!" > test.txt 

PS C:\windows\system32>Add-Content -Path .\test.txt -Value 'Dim oShell' -Stream 'secret.vbs' 
PS C:\windows\system32>Add-Content -Path .\test.txt -Value 'Set oShell = Wscript.CreateObject ("Wscript.Shell")' -Stream 'secret.vbs'
PS C:\windows\system32>Add-Content -Path .\test.txt -Value 'oShell.run "cmd /k CD C:\Program Files & ping 8.8.8.8" ,1 , true ' -Stream 'secret.vbs'

PS C:\windows\system32>Get-Content .\test.txt 
Nothing to see here!

PS C:\windows\system32>Get-Content .\test.txt -Stream secret.vbs 
Dim oShell
Set oShell = Wscript.CreateObject ("Wscript.Shell")
oShell.run "cmd /k CD C:\Program Files & ping 8.8.8.8" ,1 , true
Write-Output functions like echo and sends the content Nothing to see here! to a new file called test.txt.
Add-Content lines add some Visual Basic Studio (VBS) code to the ADS secret.vbs on test.txt.
Get-Content shows no visible change to test.txt even after previous added ADS content.
With -Stream secret.vbs we see our ADS content.


2. Executing a Malicious Alternate Data Stream
PS C:\windows\system32>wscript .\test.txt:secret.vbs 
_opens CMD.exe and pings google_
wscript part of Windows Script Host allows us to run the VBS code contained in .\test.txt:secret.vbs


3. Output
Pinging 8.8.8.8 with 32 bytes of data: 
Reply from 8.8.8.8: bytes=32 time=6ms TTL 113
Reply from 8.8.8.8: bytes=32 time=6ms TTL 113
Reply from 8.8.8.8: bytes=32 time=5ms TTL 113
Reply from 8.8.8.8: bytes=32 time=5ms TTL 113

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip in milli-seconds:
    Minimum = 5ms, Maximum = 6ms, Average = 5 master

C:\Program Files>
Output of VBS code is a simple ping to Google. Not so malicious after all…​


3. Does file hash change if we alter the Alternate Data Stream?
C:\Program Files>cd C:\windows\system32 

C:\windows\system32>certutil -hashfile test.txt MD5 
MD5 hash of test.txt:
cb73eeca4f440ee9c6e16ad3cfddb10a
CertUtil: -hashfile command completed successfully.

C:\windows\system32>notepad test.txt:secret.vbs 
_enter some extra code or remove some code_

C:\windows\system32>more < test.txt:secret.vbs 
Dim oShell
Set oShell = Wscript.CreateObject ("Wscript.Shell")
oShell.run "cmd /k CD C:\Program Files & ping 8.8.8.8" ,1 , true
words and such

C:\windows\system32>certutil -hashfile test.txt MD5 
MD5 hash of test.txt:
cb73eeca4f440ee9c6e16ad3cfddb10a
CertUtil: -hashfile command completed successfully.
Change directories to C:\windows\system32 where test.txt is.
Add or remove some code to :secret.vbs with notepad.
Verify changes to ADS content with more.
Runs certutil again to show the hash hasn’t changed.
Changing the ADS content of a file does not affect the file hash. Only changing the actual content on the main stream ($DATA) will result in a change in the file hash. This is important because an operator cannot assume a file was not tampered with just because the file hash has not changed.

###############################END###############################
##############################################################END OF DAY 2##############################################################
```
```
##############################################################DAY 3##############################################################
###############################LINUX ESSENTIALS###############################
###############################TLO###############################
Terminal Learning Objectives
1. Explain the Purpose of Understanding the Linux Environment
2. Identify Commands to Enumerate Processes
3. Identify Methods of Automation and Logic
4. Identify Critical Locations in the Linux File System
5. Discuss String Manipulation Techniques to Identify Key Information
6. Complete Linux Essentials CTFd Challenges PE
###############################END###############################
###############################COMMANDS###############################
1. Commands, Arguments, and Help
BASH, much like PowerShell, does 4 things:

Execute Commands with or without arguments

Redirect output from commands to a variety of locations (covered later)

Parse text(string) input and output into lines formatted as the user finds useful

Accept scripts to automate execution of all the above tasks

CLI will be synonymous with the terminal or command line from here on out.


1.1 Commands
As previously stated, terminals are interfaces used to run commands on the system. It’s common to find not only all the features of a GUI program in it’s CLI counterpart, but most of the time you actually gain additional functionality as well.

Running an executable in a bash terminal
student:~$ pwd 
/home/student 
pwd (print working directory) command.
the output of the command, returned on a new line.
"Newline" is a character that is commonly used to represent the beginning of a new line, or end of an old one. While common, not all commands return their results with a newline character added to the end (\n). When using methodologies such as hashing, these invisible blank newline characters should be taken into account.


1.1.1 Situational Awareness
After first obtaining access to a system an operator must gather as much information about their environment as possible, this is referred to as situational awareness. pwd is just one command of many on Linux which can provide us some insight.

Other commands to help gain situational awareness:

hostname or uname -a displays the name of the host you are currently on.

whoami shows the user you are currently logged in as (useful after gaining access through service exploitation).

w or who shows who else is logged in.

ip addr or ifconfig displays network interfaces and configured IP addresses.

ip neigh or arp displays MAC addresses of devices observed on the network.

ip route or route shows where packets will be routed for a particular destination address.

ss or netstat will show network connections, with the appropriate flags will show listening ports

nft list tables or iptables -L to view firewall rules.

sudo -l displays commands the user may run with elevated permissions.

Depending on the age and distribution of Linux some commands may not be installed or require privilege escalation through sudo to run.


1.2 Arguments
Almost all commands you ever come across will take additional parameters or arguments that modify the functionality of the base command. In some cases, arguments are even required and the command will not function without it.

Running a Command with and without an Argument
student:~$ cd / 
student:~$ ls 
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  vmlinuz
student:~$ ls -l 
drwxr-xr-x   2 root root  4096 Feb  4  2020 bin
drwxr-xr-x   3 root root  4096 Feb  4  2020 boot
drwxr-xr-x  19 root root  3840 Jan 23 12:29 dev
drwxr-xr-x 117 root root  4096 Feb 12 16:49 etc
drwxr-xr-x   4 root root  4096 Jan 23 12:25 home
_truncated_
cd / required for demo.
ls with no arguments.
ls -l changes the output to long list format.


1.3 Help
Terminals were created in the age before the internet, so when they are installed, the documentation is included.

Running a command with an argument to get help
student:~$ ls --help 
Usage: ls [OPTION]... [FILE]...
List information about the FILEs (the current directory by default).
Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

Mandatory arguments to long options are mandatory for short options too.
  -a, --all                  do not ignore entries starting with .
  -A, --almost-all           do not list implied . and ..
      --author               with -l, print the author of each file
  -b, --escape               print C-style escapes for nongraphic characters
      --block-size=SIZE      with -l, scale sizes by SIZE when printing them;
                               e.g., '--block-size=M'; see SIZE format below
  -B, --ignore-backups       do not list implied entries ending with ~
  -c                         with -lt: sort by, and show, ctime (time of last
                               modification of file status information);
                               with -l: show ctime and sort by name;
                               otherwise: sort by ctime, newest first
  -C                         list entries by columns
_truncated_
--help is an generic argument that should give a simple help document for a command.




Linux also provides access to man (manual) pages for the majority of its commands. Man pages at a minimum do the following:

Describe the command

List all of its arguments

The man pages for most commands are available online too. Man page for the LS Command
Running the man command to view the man page for ls
student:~$ man ls 
LS(1)                                           User Commands                                          LS(1)

NAME
       ls - list directory contents

SYNOPSIS
       ls [OPTION]... [FILE]...

DESCRIPTION
       List  information about the FILEs (the current directory by default).  Sort entries alphabetically if
       none of -cftuvSUX nor --sort is specified.

       Mandatory arguments to long options are mandatory for short options too.

       -a, --all
              do not ignore entries starting with .
_truncated_
The man command with ls as an argument.


1.4 Variables and Command substitution
Variables are a string of characters with an assigned value. They are used when automating tasks to reduce the amount of time needed to do something. Variables as a concept are easy to explain, but their application is dependent on that task that needs to be done.

BASH Variables are always accessed with $ then the variable name, but they are created without a $ character.
Assigning a Single Value to a Variable
student:~$ echo $a 
                   
student:~$ a="100" 
student:~$ echo $a 
100 
echo the value of the variable a. Notice that it has no value.
Nothing is returned.
Setting the value of a equals to 100.
echo the value of a.
Notice that the new value is 100.


Variables can also be assigned the output of a command using a technique called Command substitution. Command substitution is done with $(command) instead of the traditional $.

Command Substitution in Bash
student:~$ directories=$(ls /) 
student:~$ echo $directories 
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  vmlinuz
Assign the variable directories to the output of the ls / command. Note the $().
Execute the echo command the contents of the variable directories.


1.5 Redirection
Success and Failure Output from commands by default is sent to the terminal, but it can be redirected to other locations as well. Output from commands are assigned to a stream. There are three types of streams by default:

standard input 0 ←--- the default for a command arguments

standard output 1 ←--- the default for successful command output

standard error 2 ←--- the default for failed commands or errors

Redirection is done with the > character and a file name or a numbered stream.

Using a 1> redirect output to a file in bash
student:~$ directories=$(ls /) 
workstation21:$ echo $directories 1> thisisanewfile 
workstation21:$ cat thisisanewfile 
Creates the directories variable if you haven’t done so already.
Send the standard output from the $directories variable into a file named thisisanewfile.
Read the contents of thisisanewfile.


Using a 2> redirect errors to a location in bash
student:~$ ls bacon 
ls: cannot access 'bacon': No such file or directory

workstation21:$ ls bacon 2> errorfile 
workstation21:$ cat errorfile 
ls: cannot access 'bacon': No such file or directory
Try to list the contents of a directory that does not exist.
Send the standard error from the command to errorfile.
cat errorfile.


Append to a File using the Redirection Operator ( >> ) Redirection allows you to capture the output from a command and send it as input to another command or file.

The >> redirection operator appends the output to a given file.

1.6 Piping
Piping redirects standardoutput or 1 to standardinput or 0 to be processed as an argument to another command using the | character.

Using piping filter command output using grep
student:~$ ls -Rlisa /etc | grep syslog 
1378 4 -rw-r--r--   1 root root 1358 Jan 30  2018 rsyslog.conf
1379 4 drwxr-xr-x   2 root root 4096 Feb  2 14:28 rsyslog.d
566  4 -rw-r--r--   1 root root 1550 Apr 24  2018 usr.sbin.rsyslogd
527  0 lrwxrwxrwx   1 root root   33 Jan 31  2020 usr.sbin.rsyslogd -> /etc/apparmor.d/usr.sbin.rsyslogd
535  0 -rw-r--r--   1 root root    0 Jan 31  2020 usr.sbin.rsyslogd
768  4 -rw-r--r--   1 root root  124 Jan 14  2018 rsyslog
958  4 -rwxr-xr-x   1 root root 2864 Jan 14  2018 rsyslog
1043 4 -rw-r--r--   1 root root  804 Jan 14  2018 rsyslog
1054 4 -rw-r--r--   1 root root  501 Jan 14  2018 rsyslog
ls: cannot open directory '/etc/polkit-1/localauthority': Permission denied 
Execute ls with arguments, then send the output to grep command using a pipe | to filter for the string syslog.
Standard error saying Permissions denied.
To remove all errors from your output, consider utilizing standard error redirection. ls -Rlisa /etc 2> /dev/null | grep syslog
###############################END###############################
###############################BLANK###############################
. Automation and Logic
The primary benefit of terminals is the automation of repetitive tasks and processing logical statements. These statements and loops execute automatically using pre-programmed conditions that control how and even if they execute. They are invaluable to understand and their usefulness is limited to ones imagination and patience.

If Statements, For Loops, and While Loops don’t have good man page entries because they are built into the bash man page. Highly recommend using online resources.
2.1 For Loops
For Loops go by many names such as Counting Loops and Interactive Loops, but they all do the same thing - execute a command or commands multiple times with a changing variable as an argument. A complete for loop will have the following:

a collection of objects assigned to a variable

a variable that represents the value in the collection correctly being worked on

a command or commands that will execute with each value in the collection of variables

Making a Collection of objects
student:~$ objects=$(ls -d /etc/*) 
student:~$ echo $objects 
/etc/NetworkManager /etc/PackageKit /etc/UPower /etc/X11 /etc/acpi /etc/adduser.conf /etc/alternatives /etc/anacrontab /etc/apg.conf /etc/apm /etc/apparmor /etc/apparmor.d /etc/apport /etc/apt /etc/at.deny /etc/bash.bashrc /etc/bash_completion /etc/bash_completion.d /etc/bindresvport.blacklist /etc/binfmt.d /etc/byobu /etc/ca-certificates /etc/

_truncated_
Using command substitution to make a variable containing all the files and folders in /etc.
Reading the content of the variable $objects. Warning it is ugly.


Making a For Loop to iterate on Objects in the collection of Objects
student:~$ for item in $objects; do echo $item; done 
/etc/NetworkManager
/etc/PackageKit
/etc/UPower
/etc/X11
/etc/acpi
/etc/adduser.conf
/etc/alternatives
/etc/anacrontab
/etc/apg.conf
/etc/apm
_truncated_
For each item in located in the objects variable, echo the value of item as the loop executes.
The $item variable is will contain each entry in $objects delimited by a space as the loop executes.
For Loops TLDP



2.2 If Statements
If statements are logical expressions that compare objects against various tests to see if they evaluate as true or false. They are understood in a sentence form like this:

If this comparison is true, then do this

or

Else If this comparison is true, then do this

or

If nothing is true, do this

Making an If Statement to evaluate a series of objects Copy each line one at a time
student:~$ for object in $objects; \ 
do if [ -d $object ]; then echo "$object is a directory"; \ 
else echo "$object is file" ; \ 
fi ; \ 
done 

/etc/X11 is a directory
/etc/acpi is a directory
/etc/adduser.conf is a file
/etc/alternatives is a directory
/etc/anacrontab is a file
/etc/apg.conf is a file
/etc/apm is a directory
/etc/apparmor is a directory

student:~$ for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done 
The beginning of the for loop like in section 2.1.
if $object is a directory AND it exists, then run echo "$object is a directory".
else echo "$object is a file".
ends the if statements.
ends the for loop started in 1.
One liner version of the if statement.


One Line For Loop and If Statement for the student’s notes
for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done
If Statements TLDP

2.3 While Loops
While statements execute a command or series of commands while a condition is true. Unlike for loops which will eventually run out of objects, While Loops will run forever if their condition never evaluates as false. While loops are great for making things run for a specific amount of time instead of a exact amount of iterations. They are understood in sentence form as follows:

While this condition is true, do this thing or series of things, then re-evaluate the condition to see if it is false. Repeat until condition is false.



Making an Basic While Loop
while [ 1 -eq 1 ]; do echo "To Infinity and Beyond!"; done 
While 1 equals 1, run the command echo ""To Infinity and Beyond!".
Yes, this script will run forever.
This While loop will run forever, unless the condition is re-evaluated as false.


Practical While Loop Example
curtime=$(date +"%s") 
echo $curtime

exittime=$(expr $curtime + 3) 
echo $exittime

while [ $exittime -ge $curtime ]; do echo "To Infinity and Beyond?" ; curtime=$(date +"%s") ; done 
To Infinity and Beyond?
To Infinity and Beyond?
To Infinity and Beyond?
To Infinity and Beyond?
_Truncated_ #It goes for three seconds
Use command substitution to set the value of curtime equal to the current time in Epoch time. "%s" = in seconds
Use command substitution to set the value of exittime equal to 3 seconds in the future Epoch Time.
While exittime is greater than curtime, do echo "To Infinity and Beyond?", then update the curtime variable and check if exittime is still greater or equal to curtime.

###############################END###############################
###############################BLANK###############################
3. Linux Filesystems
A file system is how a computer stores, categorizes, and retrieves data from physical media devices for use in various applications on the system.

There are multiple types of file systems, but they all follow a common layout described below:

Physical Media contains

A Partition that is a formatted section of memory, which contains

A File System mounted on a drive, which contains

A Hierarchical Format of Objects and their supporting Data and Metadata

File systems are a broad topic that range from understand hexadecimal layouts of hard drives to Forensics Techniques to reassemble deleted files. However, the important take away for this course is the understanding of what is located where and what a user can do with it on a Linux Filesystem



3.1 Linux Filesystem Hierarchy
Every *Nix system from Ubuntu to Debian has a defined file system layout which is known as the Linux FSH (File System Hierarchy). It is a standard which defines the directory structure on all Linux distributions. What does that mean? Well, by default it defines:

The root directory of the file system /

Everything starts from this directory. Think of it as the doorway to the Linux Filesystem

Essential user commands in /bin

Contains commands like ls and echo which every user can use.

User Directories in /home

Contains directories for every non-root user on the system (with a home directory and login shell)

Host specific system configurations in /etc

Stands for everything configurable

Contains network configurations, system services(daemons), firewall configurations, etc.

Variable data files in /var

Contains all of the system logs by default

Linux Filesystem Hierarchy Standard Wiki

Linux Filesystem Hierarchy Standard Detailed



3.2 Files and Folders
In a file system, there are two types of objects - files and folders. Folders are a container for files, whilst files are containers for data. Everything without exception falls into one of those two categories.

Showing / directories
student@linux-opstation-kspt:~$ cd / 
student@linux-opstation-kspt:/$ 
student@linux-opstation-kspt:/$ls -l $PWD/* 
drwxr-xr-x   2 root root  4096 Feb  4  2020 /bin
drwxr-xr-x   3 root root  4096 Feb  4  2020 /boot
drwxr-xr-x  19 root root  3840 Jan 23 12:29 /dev
drwxr-xr-x 117 root root  4096 Feb 12 16:49 /etc
drwxr-xr-x   4 root root  4096 Jan 23 12:25 /home
execute the command cd into the root directory of /.
The directory changed to /.
Execute ls in long list format with absolute path.


Showing files in /bin
student@linux-opstation-kspt:/$ cd /bin 

student@linux-opstation-kspt:/bin$ ls -ld $PWD/* 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 /bin/btrfs

student@linux-opstation-kspt:/bin$ ls -l 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 btrfs
-rwxr-xr-x 1 root root  375952 Mar 12  2018 btrfs-debug-tree
Change directory to /bin.
Execute ls in long list format with absolute paths.
Execute ls in long list format with relative paths.


Remember that there are only two types of objects in Linux - files and folders. Folders can’t be read, but files can. Granted, not every file is human readable. In most computers today, files have subtypes defined by their file signature typically located in the first few bytes of a file. The file signature defines how the operating system will attempt to use the file.

Reading a "file" in /bin
student@linux-opstation-kspt:/bin$ cat ls | head -n 1 
ELF>PX@▒@8      @@@▒888▒ _truncated_ 

student@linux-opstation-kspt:/bin$ xxd ls | head -n 2
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............ 
00000010: 0300 3e00 0100 0000 5058 0000 0000 0000  ..>.....PX......
Execute cat on ls, then send its standard output to the head command and trim output to display a single row.
Aside from the first few characters, that isn’t readable.
Execute xxd on ls, then send its standard output to the head command and trim output to display to the first two rows.
Look at that file signature! This file signature of 7f45 4c46 stands for Linux Executable Linked file format unique to Linux.
File Signature Wikipedia



3.3 Linux Users
Users in Linux systems are defined by an ascending numerical value called a UID. The uid value uniquely identifies a user and is contained in the /etc/passwd file along with an associated username. Every user on a Linux system and has an associated value in /etc/passwd.

Identify what Username you are whoami
student@linux-opstation-kspt:/bin$ whoami 
student 
Execute the whoami command.
The answer to who I am.


Identify what your uid value is with id
student@linux-opstation-kspt:/bin$ id 
uid=1001(student) gid=1001(student) groups=1001(student),27(sudo) 
Execute the id command.
All of my associated ids?
1001 is the UID of student, but its also the GID because it is assigned to the student group.


Looking at who I am in the /etc/passwd file with cat
student@linux-opstation-kspt:/bin$ cat /etc/passwd | grep student 
student:x:1001:1001::/home/student:/bin/bash 
 (1)   (2) (3) (4) (5)   (6)          (7)
cmd line: Execute cat /etc/passwd and pipe it to grep to filter on student.
cmd output: Student entry in the /etc/passwd file.
Sections of output lines
Username
Password. An x character indicates that an encrypted password is stored in /etc/shadow file.
UID Value
GUID Value
User ID Info (GECOS). The comment field
Homeome Directory.
Command/Shell /bin/bash


3.4 Linux Groups
Groups in Linux define a collection of Users and are defined by an ascending GID value. The gid value uniquely identifies a group and is contained in the /etc/group and its associated group name.

Looking at who I am in the /etc/group file with cat
student@linux-opstation-kspt:/bin$ cat /etc/group | grep student 
sudo:x:27:ubuntu,student 
student:x:1001: 
Execute cat /etc/group and pipe it to grep to filter on student.
Shows the sudo group, its gid value, its two members student and ubuntu.
Shows the student group, its gid value, and no additional members.
By default every user is a member of their own group; therefore, it will not show in /etc/groups. /etc/groups/ shows what is called supplementary group membership


3.5 Permissions
Access to objects in Linux by is controlled via strict file permissions metadata. It is formatted as:

U The object’s User/Owner

G The object’s owning Group

O Any subject that is not the owning user or group, AKA: "Others"

Each U.G.O permission group has three corresponding permissions of Read, Write, and Execute. Any combination of permissions can be applied to any permissions group. These permissions also have numeric representations of 4, 2, and 1. Permissions when represented by letters, as in rwx, are referred to as Relative, and permissions when represented by numbers, as in 421 are referred to as Octal.

It’s also important to understand that file permissions do not overrule directory permissions. If a user does not have read rights to a directory, it also cannot read any of its files even if the file’s permissions allow it

Table 1. Linux Permissions broken out
Perm	Relative	Octal	On a File	On a Directory
read

r

4

Read the contents of the file

List the contents of the directory

write

w

2

Write content into a file

Create/delete in the directory

exe

x

1

Run the file as an executable

Move into the directory



Showing Linux Permissions with ls -lisa
student@linux-opstation-kspt:/bin$ ls -lisa /bin/dd 
student@linux-opstation-kspt:/bin$ 130341 76 -rwx r-x r-x 1 root root 76000 Jan 18  2018 /bin/dd
                                             (2)  (3) (4)   (5)   (6)
Showing permissions.
The Owner has Read, Write, and Execute permissions.
The Group has Read and Execute permissions.
Anyone who is not the User/Owner or belonging to the Group has Read and Execute permissions.
The file’s Owner.
The files' Group.


File and Folder Permissions Demo
student@linux-opstation-kspt:/home/student$ sudo su
root@linux-opstation-kspt:/home/student$  mkdir testdir
root@linux-opstation-kspt:/home/student$  chmod 750 testdir
root@linux-opstation-kspt:/home/student$  echo "Can you read me?" > testdir/file
root@linux-opstation-kspt:/home/student$  ls -lisa testdir/
1020551 4 drwxr-x---  2 root   root   4096 Feb 17 19:00 .
1016881 4 drwxr-xr-x 24 student student 4096 Feb 17 18:59 ..
1022450 4 -rw-r--r--  1 root   root     16 Feb 17 19:00 canttouchthis

root@linux-opstation-kspt:/home/student$  exit
student@linux-opstation-kspt:/home/student$ cat testdir/canttouchthis
cat: testtest/canyouread: Permission denied
Change to the root user.
make a directory named testdir.
change the permissions on the directory to 750 or RWX,R-X,---.
Echo some text into a file in the created directory.
Show the permissions of the Directory and the file. . represents the directories permissions.
Exit root.
Try to cat the file as student and get Permission denied.


3.5.1 Special Permissions : Sticky Bit
If a user has write access to a directory, they can delete any file from it. That may cause problems though in some directories like /var/tmp. To address this Linux has what is known as the sticky bit. The sticky bit removes the ability to delete files unless the user attempting is the owner of the file.

The root account can still delete the file if it wants to.


3.5.2 Special Permissions : SUID and SGID
When an executable is ran in Linux, it runs with the permissions of the user who started it. However, SUID and SGID change that to force the executable to run as the owning user or group. These permissions are represented as s in the User or Group field of ls- l.

SUID and SGID Demo
student@linux-opstation-kspt:~$ ls -l /bin/ping 
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping 
Execute ls -l on /bin/ping.
Notice the s in the users field? What permissions does this executable effectively have?

###############################END###############################
###############################BLANK###############################
4. String Manipulation
In Linux all output is some kind of text, regardless of whether it was meant to be read by humans or not. You could scroll and use your finger to find data, or you can use one of pattern matching or text manipulation tools to make life easier.

4.1 Grep
Grep is a program that searches data given to it from standard input for patterns of strings specified with regular expressions. Grep is invaluable in Linux because most of the time it is to only way to quickly filter output to find exactly what is needed.

grep uses a generic wildcard regular expression match by default. It accepts custom regular expressions too with arguments.
Use grep to filter standard output from another command
student@linux-opstation-kspt:~$ ls -Rlisa /etc | grep password 
 1137 4 -rw-r--r--   1 root root 1440 Jan 31  2020 common-password
 1156 4 -rw-r--r--   1 root root 1160 Oct  9  2018 gdm-password
ls: cannot open directory '/etc/polkit-1/localauthority': Permission denied 
ls: cannot open directory '/etc/ssl/private': Permission denied
ls: cannot open directory '/etc/sudoers.d': Permission denied
Execute ls -Rlisa then send its standard out to grep to filter for the string password.


Use grep to search through a directory for text
student@linux-opstation-kspt:~$ grep -R 'network' /etc/ 
Execute grep -R 'network' /etc/ then send it’s standard out to grep to filter for the string network.
The -R is recursive.
Grep is a command that looks for a string of characters then presents the results to your screen. Grep is commonly used in conjunction with piping outputs from previous commands. But can also be used as a standalone command, with it’s own options/switches.


4.2 Awk
awk is yet another important string manipulation tool. Unlike grep which searches for strings of text, awk allows you to reformat or select sections of text based on delimiters on the fly. Awk is commonly used to create tabular data sets from command output in Bash. However, it is a very flexible tool and its functionality does not end there.

Reformat output from a command to create a comma delimited file with awk
student@linux-opstation-kspt:~$ ls -l /etc 
drwxr-xr-x  7 root root       4096 Feb  4  2020 NetworkManager
drwxr-xr-x  2 root root       4096 Feb  4  2020 PackageKit
drwxr-xr-x  2 root root       4096 Feb  4  2020 UPower
_truncated_

student@linux-opstation-kspt:~$ ls -l /etc | awk -F " " '{print$3","$4","$9}' > files.csv 
student@linux-opstation-kspt:~$ cat files.csv
root,root,NetworkManager
root,root,PackageKit
root,root,UPower
_truncated_
The output from ls -l is verbose, maybe all of that information isn’t needed?
Lets send the output from ls -l into awk, then set the delimiter to blank space, then tell it to print fields $3,$4,$9, finally send them to a csv file.


Crate a variable of all the news articles on https://dailymail.co.uk`
student@linux-opstation-kspt:~$ articles=$(curl -L https://www.dailymail.co.uk/ushome/index.html --output - | grep itemprop | grep href | awk -F "\"" '{print$4}'|  awk -F "/" '{print$4}')

student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
Congress-holds-hearing-reparations-slavery-time-BLM-protests-rocked-nation.html
Kendall-Jenner-accused-cultural-appropriation-launching-tequila-brand.html
MGM-Resorts-resume-24-7-operations-Mandalay-Bay-Park-MGM-Mirage-resorts-Las-Vegas.html
_truncated_
Perform a http GET request and filter all the HTML to get to the specific articles by grepping on itemprop, then grep on href, next use awk to cut output into fields separated by \ characters and select column 4, finally cut output into fields separated by / characters and select column 4.
Read the variable articles with a for loop.
What you can do with these commands is limited by your imagination and knowledge. Go out and learn new ways to use them. Have fun!
4.3 Sed
Sed is yet another string manipulation tool, but it edits text instead of filtering or formatting it like the other two. Sed is special because it edits text as it is sent to standard output. It is known as a stream editor. Text edited from sed can also be saved assuming the user executing it has the right permissions.

Use sed to change standard out from the cat
student@linux-opstation-kspt:~$ cat /etc/passwd | grep root 
root:x:0:0:root:/root:/bin/bash

student@linux-opstation-kspt:~$ cat /etc/passwd | grep root | sed s/root/bacon/g 
bacon:x:0:0:bacon:/bacon:/bin/bash
Execute cat on /etc/passwd then filter the output with grep to filter for root.
Using sed to change standard any standard input that matches root to bacon, then send the modified output to the screen.
Using sed to clean up the output from the Dailymail Variable in section 4.2
student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done 
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
Congress-holds-hearing-reparations-slavery-time-BLM-protests-rocked-nation.html

for article in $articles; do echo $article |sed -e s/\.html//g -e s/\-/" "/g ; done  
Rush Limbaugh dies aged 70 lung cancer battle
Facebook BANS Australians sharing news war publishers
Police 7 shot near transit station north Philadelphia
The original output described in 4.2. It is messy and could be cleaned up a bit.
Using sed to replace standard input that matches .html with nothing.
Using sed to replace standard input from sed that matches the - (dash) character with a space.
These are very limited examples, designed to show you the basics. With either Sed or Awk, the only limit is your imagination.


4.4 Regular Expressions
Regular expressions, or regex, are a pattern matching language developed in the 1980s with the first use of the Unix operating system. Regex filters on patterns strings that may match multiple permutations. Most internet search engines, online shopping, and really any place there is a search button uses them too.



Showing how regular expressions can match on multiple permutations of strings
student@linux-opstation-kspt:~$ echo -e "Handel\nHändel\nHaendel" > regexfile 
student@linux-opstation-kspt:~$ grep -P "H(ä|ae?)ndel" regexfile >  
Handel
Händel
Haendel
Create a file with 3 similar names in it and save it as regexfile in the current directory.
Use grep with -P to specify Perl regular expressions and look for :
H,ä or a, e is optional, ndel.
Handel Example Reference



Showing how regular expressions can match on multiple permutations of strings in files that are too large to search manually
student@linux-opstation-kspt:~$ cat results.txt 
111-715-255643
(9279815)92-3599127
466-33836614-273
_truncated_

student@linux-opstation-kspt:~$ grep -P '\b\d{3}-\d{2}-\d{4}\b' results.txt
629-75-1985
386-67-7872
478-71-4964

student@linux-opstation-kspt:~$ grep -P '\(\d{3}\)\d{3}-\d{4}\b' results.txt
(267)874-4532
(446)146-8923
(548)985-5415
(199)363-3617
Attempting to cat the a large file isn’t very helpful.
Execute grep to search for the following pattern : nnn-nn-nnnn.
Execute grep to search for the following pattern : (nnn)nnn-nnnn.

###############################END###############################
##############################################################END OF DAY 3##############################################################
```
```
##############################################################DAY 4##############################################################
###############################BLANK###############################
1. Boot Process Overview
600
Figure 1. The Windows Boot Process


The Boot process is a series of automated tasks that take a computer from pushing the power button to logging into the Desktop. It is a lengthy process, but only certain portions of it can be interacted with easily. The process is broken down into the following steps:

Hardware Initialization

Loading the Boot Sector or Boot Manager

Loading the Operating System from the Boot Sector



Why Do we care about the Boot process?

Rootkits are a type of malware that hide themselves and other applications. They typically run in kernel mode, so they have the same privileges as the operating system and can sometimes start before it. Because traditionally, anti-malware software doesn’t load until after the kernel and boot drivers do, rootkits often exploit weaknesses in the startup process:

Firmware Rootkits overwrite the PC’s BIOS or other hardware firmware so the rootkit can start before the OS even loads

Bootkits replace the OS bootloader to load the bootkit before the OS

Kernel rootkits replace a portion of the OS kernel so the rootkit can start when the OS loads

Driver rootkits pretend to be a boot driver that the OS uses to communicate with PC

Avenues of Attack An exposed operating system can be easily used to further Offensive goals such as pivots or compromised to steal data


###############################END###############################
###############################BLANK###############################
2. BIOS and UEFI
BIOS and UEFI are firmware that ensure critical hardware like SATA devices (Hard Drives), Display Adapters, and SDRAM(Synchronous dynamic random-access memory) are functional then, locates the MBR(Master Boot Record) or GPT(GUID Partition Tables).

Firmware is software coded non-volatile memory devices such as:

ROM (Read only memory)

EPROM (Electronically Programmable Read only memory)

EEPROM (Electronically Erasable Programmable read only memory)

Flash memory

BIOS and UEFI do the same thing, but minor differences make UEFI more popular than BIOS in the current day. Without getting into low level specifics some of the benefits of UEFI:

UEFI Boots much faster than BIOS systems, especially for Windows machines.

UEFI Firmware is usually loaded into flash memory or EEPROM, making it easier to update and patch.

UEFI offers SECURED BOOT mode which only allows verified drivers to load.

UEFI offers drive support of up to 9 zettabytes, while BIOS only works with 2 terabytes.

References for UEFI Features



2.1 BIOS Master Boot Record
Once the BIOS checks hardware, it finds the MBR (Master Boot Record). The MBR contains Disk Partitions like /dev/sda1 or DISK 1 C:\

The partition contains code that starts the first stage of loading an Operating System, called a Boot Loader

Boot Loaders

Windows 2003 and older used NTLDR or New Technology Loader

Windows 7 Service Pack 1 and newer uses bootmgr or New Technology Loader

From this point the Boot Loader takes over and starts the Operating System

​

2.2 UEFI Boot Manager
UEFI does the same hardware checks as BIOS, but instead of using the MBR it reads an EFI Partition. The EFI Partition contains UEFI Boot Managers

Windows bootmgfw.efi or Windows Boot Manager

From this point onwards, the UEFI Boot Manager takes over and starts the Operating System



Detecting BIOS or UEFI on Windows

Q: How can I tell if my machine is running BIOS or UEFI?

findstr /C:"Detected boot environment" "C:\Windows\Panther\Setupact.log"
Get-Content C:\Windows\Panther\Setupact.log | Select-String "Detected boot environment"


A2: Use the bcedit command

bcdedit | findstr /i winload
winload.exe = BIOS, winload.efi = UEFI


A: Check the GUI

Msinfo32.exe
Look at BIOS Mode (Legacy means the system is UEFI compatible but running in BIOS mode)​
###############################END###############################
###############################BLANK###############################
3. Windows System Initialization
This is a simplified version of the Windows Boot Process from the kernel (ntoskrnl.exe) to the execution of LogonUi.exe (the process that prompts for user interaction). It is broken into five steps.

Loading the Operating System Kernel

Initializing the Kernel

Starting Subsystems

Starting Session 0

Starting Session 1



3.1 Loading the Operating System Kernel
On UEFI Systems

bootmgfw.efi reads a BCD (Boot Configuration Data) located in the EFI system partition to load the file winload.efi



On BIOS Systems

bootmgr or NTLDR reads the file \Boot\BCD to locate winload.exe

The purpose of both winload programs is to load basic drivers and start the next part of the Windows Boot Process - loading the Kernel.



Winload.exe loads the Windows kernel:

Loads essential drivers required to read data from disk

Loads the windows kernel (ntoskernel.exe) and dependencies

Winresume.exe reads previously saved data from hiberfil.sys (hibernation mode) to restore a previous Windows instance.

On UEFI systems, winresume.exe is named winresume.efi, and is located at \windows\system32\boot.



3.2 Initializing the Kernel
The kernel, as previously discussed, is the heart of the Operating System. Without it, the system cannot function.

In Windows, the kernel is named Ntoskrnl.exe and is a critical system file. It does the following tasks during the boot process:

Loads the Windows Registry

Loads device drivers

Starts the system pagefile located at C:\pagefile.sys

Loads hal.dll

hal.dll provides abstraction between hardware interfaces and Ntoskrnl.exe

Once the kernel is done loading it spawns System which hosts threads that only run in kernel mode responsible things like drivers. System then spawns the session management processes smss.exe and csrss.exe


###############################END###############################
###############################BLANK###############################
4. Starting Subsystems
smss.exe (Session Manager Subsystem) does the following tasks:

Loads environmental variables like %APPDATA% and %COMPUTERNAME%

Populates the pagefile located in C:\pagefile.sys

Starts the kernel and user mode sub systems.

Starts a csrss.exe to manage processes and threads for each User Subsystem.

​

4.1 Kernel Subsystems
The kernel subsystem creates and manages every resource available to Windows by interacting with drivers on the system. It controls things like:

System power state

Process creation and threads

Graphical rendering

Access Control Lists via the Security Reference Monitor

It is important to understand - users cannot interact directly with any kernel-mode process or even see them

​

4.2 User Subsystems
This is the first part of Windows that a user is able to manipulate.
The user subsystem manages all user applications like process creation, internet connectivity, and object access through API calls to hal.dll

User Subsystems run in Session 0 and Session 1

Tree
Figure 2. User Subsession 0 and 1 Process Tree
4.2.1 User Subsystem Session 0
Session 0 is for security and high privilege processes such as services. They are run in a separate session to isolate them from individual user’s processes.




smss.exe installs the Win32 subsystem kernel and user mode components (win32k.sys - kernel; winsrv.dll - user; and csrss.exe - user.)

csrss.exe - The Client/Server Runtime Subsystem supports process / thread creation and management.

wininit.exe marks itself as critical, initializes the Windows temp directory, loads the rest of the registry, and starts user mode scheduling. It also installs programs that require a reboot to finish the install process. It also starts:

lsm.exe - the Local Session Manager (LSM) handles all sessions of a system (both remote desktop sessions and local system sessions.)

lsass.exe - the Local Security Authority Subsystem (LSASS) provides user authentication services, manages the local security policy, and generates access tokens.

services.exe the Services Control Manager (SCM) loads AutoStart services, using LSASS to authenticate if they run as something other than System.

wininit.exe then waits for system shutdown to undo everything it started.

By why does any of this matter?

Processes in User Subsystem Session 0 are created using the highest permissions available to a User in Windows - SYSTEM

System has more permissions than an administrative account

represents the Windows Operating System

*Can be tricked into executing malicious commands via services

Mitre ATT&CK: System Services

Mitre ATT&CK: Hijack Execution Flow: Services Registry



1. Showing the Spooler Service using SC
sc query spooler

SERVICE_NAME: Spooler
DISPLAY_NAME: Print Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0


2. Showing the Service Control Manager registry key
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services | findstr Spooler

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler


3. Showing the contents of the Spooler Service Registry Key
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler
    DisplayName    REG_SZ    @%systemroot%\system32\spoolsv.exe,-1
    Group    REG_SZ    SpoolerGroup
    ImagePath    REG_EXPAND_SZ    %SystemRoot%\System32\spoolsv.exe 
    Description    REG_SZ    @%systemroot%\system32\spoolsv.exe,-2
    ObjectName    REG_SZ    LocalSystem 
The spooler service executable. What happens if someone changes that to a malicious binary?
The account who runs the Spooler Service!


Showing Services
C:\Windows> tasklist /svc

Image Name                     PID Session Name        Session#
========================= ======== ================ ===========
svchost.exe                   1040 EventSystem, fdPHost, FontCache, netprofm,
                                   nsi, WdiServiceHost
svchost.exe                   1076 AeLookupSvc, Appinfo, AppMgmt, BITS,
                                   CertPropSvc, EapHost, gpsvc, iphlpsvc,
                                   ProfSvc, Schedule, SCPolicySvc, SENS,
                                   ShellHWDetection, Themes, Winmgmt, wuauserv
CTAudSvc.exe                  1216 CTAudSvcService
igfxCUIService.exe            1328 igfxCUIService2.0.0.0
svchost.exe                   1388 CryptSvc, Dnscache, LanmanWorkstation,
                                   NlaSvc, WinRM
spoolsv.exe                   1568 Spooler
svchost.exe                   1604 FDResPub, QWAVE, SCardSvr, SSDPSRV
svchost.exe                   1644 BFE, DPS, MpsSvc
armsvc.exe                    1768 AdobeARMservice


4.2.2 User Subsystem Session 1
Session 1 is for the first interactive user (note: each session gets its own copy of csrss.exe.) Session 1 and up are standard user sessions. This includes everyone from the default Administrator to custom accounts created. It is the entire desktop experience on Windows.

It does the following, in order, for Session 1 and up:

Spawn a Session 1 ( or higher) csrss.exe

Spawn Winlogon.exe which by default prompts for credentials with logonui.exe

Spawn userinit.exe which creates an account token and creates a custom environment

Spawn explorer.exe as the customized graphical environment.

Why does any of this matter?

Hundreds of Processes in User Subsystem Session 1 and up are started automatically as a standard user to include administrative accounts. This potentially opens up the system to vulnerabilities such as:

Mitre ATT&CK: Boot or Logon AutoStart Execution via Registry Keys

Mitre ATT&CK: Boot or Logon Initialization Scripts

Mitre ATT&CK: PowerShell Profile Script Execution

The potential damage of these vulnerabilities is limited to the permissions of the account it executed on.
###############################END###############################
###############################BLANK###############################
5. Windows BCDEdit Demo
Q: What can I do if the Windows boot settings became corrupted?

A: Fix it with the bcdedit command

BCDEdit command help
c:\demo>bcdedit /?
What does a normal bcdedit output look like?

c:\demo>bcdedit

Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=C:
description             Windows Boot Manager
locale                  en-US
inherit                 {globalsettings}
default                 {current}
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
displayorder            {current}
toolsdisplayorder       {memdiag}
timeout                 29

Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \windows\system32\winload.exe
description             Windows 7 - Tiger Paw
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {91061b50-0fa8-11e9-aa6e-00155d49334a}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \windows
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
nx                      OptIn
bootmenupolicy          Standard
DEMO BCDEdit

Backup & Restore Current BCD settings
c:\demo>bcdedit /export C:\Lion_BCD
c:\demo>bcdedit /import C:\Lion_BCD
Whenever you want to make a change to a specific Boot Loader entry use the {Identifier}

Modify Description of Current Boot loader
c:\demo>bcdedit /set {<identifier>} description "Windows 7 - Lion Den" (1)
(1) Point out that the Description is nothing more than a "label"

Create New partition
c:\demo>bcdedit /create {ntldr} /d "Windows XP Pro SP2 - Tiger Paw"
-Specify the Partition
c:\demo>bcdedit /set {ntldr} device partition=C:
-Specify the Path to ntldr
c:\demo>bcdedit /set {ntldr} path \ntldr
-Specify the Display Order
c:\demo>bcdedit /displayorder {ntldr} /addfirst
Now Show the added Partition
c:\demo>bcdedit

Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=C:
description             Windows Boot Manager
locale                  en-US
inherit                 {globalsettings}
default                 {current}
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
displayorder            {ntldr}
                        {current}
toolsdisplayorder       {memdiag}
timeout                 29

Windows Legacy OS Loader
------------------------
identifier              {ntldr}
device                  partition=C:
path                    \ntldr
description             Windows XP Pro SP2 - Tiger Paw

Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \windows\system32\winload.exe
description             Windows 7 - Lion Den
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {91061b50-0fa8-11e9-aa6e-00155d49334a}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \windows
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
nx                      OptIn
bootmenupolicy          Standard
Delete the Legacy Operating System ( /f = force)
bcdedit /delete {ntldr} /f
Add, Remove & Change Additional Options
Add Safeboot Value

_Output_Truncated_
Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \windows\system32\winload.exe
description             Windows 7 - Tiger Paw
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {91061b50-0fa8-11e9-aa6e-00155d49334a}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \windows
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
nx                      OptIn
safeboot                Minimal
bootmenupolicy          Standard
bcdedit /deletevalue {current} safeboot (1)
bcdedit /set {bootmgr} timeout 29 (2)
(1) Will delete the Safeboot value

(2) Will change the Timeout Value
###############################END###############################
##############################################################END OF DAY 4##############################################################
```
# Day 5
## Linux Boot

# ##############################################################DAY 5 LINUX BOOT##############################################################
# ###############################BOOT PROCESS OVERVIEW###############################
  
  ###############################END###############################
# ###############################BIOS AND UEFI###############################
## 2. BIOS and UEFI
  BIOS and UEFI are firmware that ensure critical hardware like SATA devices (Hard Drives), Display Adapters, and SDRAM(Synchronous dynamic random-access memory) are functional then, locates the MBR(Master Boot Record) or GPT(GUID Partition Tables).
  
  The BIOS runs and exits before the Linux system even starts. Flash memory on the motherboard contains the BIOS. Remember that firmware is different from software.
  Firmware is software coded non-volatile memory devices such as: . ROM (Read only memory) . EPROM (Electronically Programmable Read only memory) . EEPROM (Electronically Erasable Programmable read only memory) . Flash memory
  
  Non-volatile memory does not clear itself after a restart, while volatile memory does.

### 2.1 Differences between BIOS and UEFI Firmware
  Someone is going to ask about the difference between BIOS and UEFI.
  BIOS and UEFI do the same thing, but minor differences make UEFI more popular than BIOS in the current day. Without getting into low level specifics some of the benefits of UEFI:
  
  UEFI Boots much faster than BIOS systems, especially for Windows machines.
  
  UEFI Firmware is usually loaded into flash memory or EEPROM, making it easier to update and patch.
  
  UEFI offers SECURED BOOT mode which only allows verified drivers to load.
  
  UEFI offers drive support of up to 9 zettabytes', while BIOS only works with 2 terabytes.
  
  ###############################END###############################
# ###############################1st STAGE BOOTLOADERS###############################
## 3. 1st Stage Bootloaders
  1st Stage Bootloaders are the Master Boot Records(MBR) and the GUID Partition Tables (GPT) because they are the first part of loading an operating system. They locate and finish loading the 2nd stage bootloader known as GRUB



### 3.1 Master Boot Record (MBR)
  The Master Boot Record contains information on partitions locations on the hard drive. Partitions contain the 2nd stage bootloader known as the GRUB(Grand Unified Bootloader).
  
  Boot Sector and MBR are the same thing. The MBR is a Boot Sector.
  Once the BIOS loads the bootstrap in the MBR. The bootstrap is the initial section of code that contains a bootloader known as GRUB broken into two stages. The first stage is GRUB stage 1, which loads Grub Stage 2 from the selected active partition. Grub Stage 2 is not located in the MBR, but further in the hard drive.



### 3.1.1 Master Boot Record Layout
  The first 512 bytes of a hard drive contains the Master Boot Record. It contains the following information:
  
  Bootstrap Code
  
  Partition entry 1
  
  Partition entry 2
  
  Partition entry 3
  
  Partition entry 4
  
  Boot signature
  
  Table 1. MBR Layout
  Address	Description	Size (bytes)
  0x0000 (0)
  
  Bootstrap Code Area
  
  446
  
   
  
   
  
   
  
  0x01BE (446)
  
  Partition Entry #1
  
  Partition table(for primary partitions)
  
  16
  
  0x01CE (462)
  
  Partition Entry #2
  
  16
  
  0x01DE (478)
  
  Partition Entry #3
  
  16
  
  0x01EE (494)
  
  Partition Entry #4
  
  16
  
  0x01FF (510)
  
  0x55
  
  Boot signature
  
  2
  
  Total=512 bytes
  
  
  
  Locate the hard drive and partition in Linux
  student@linux-opstation-kspt:~$ lsblk 
  
  NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
  loop0    7:0    0 31.1M  1 loop /snap/snapd/10707
  loop1    7:1    0 55.4M  1 loop /snap/core18/1944
  loop2    7:2    0 44.7M  1 loop /snap/openstackclients/38
  loop3    7:3    0 55.5M  1 loop /snap/core18/1988
  loop4    7:4    0 31.1M  1 loop /snap/snapd/11036
  sr0     11:0    1  514K  0 rom  /media/student/config-2
  vda    252:0    0  128G  0 disk 
  └─vda1 252:1    0  128G  0 part / 
  List block devices currently in use by Linux
  Shows disk vda virtual disk A
  Shows virtual disk A partition 1 is mounted as the / or root drive in Linux
  a block device is a special file that refers to a device.
  
  
  Examining the contents of the MBR with xxd
  student@linux-opstation-kspt:~$ sudo xxd -l 512 -g 1 /dev/vda 
  
  00000000: eb 63 90 00 00 00 00 00 00 00 00 00 00 00 00 00  .c.............. 
  00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  _truncated_
  000001b0: cd 10 ac 3c 00 75 f4 c3 fa b7 12 e6 00 00 80 00  ...<.u.......... 
  000001c0: 21 02 83 0f 2e 40 00 08 00 00 df f7 ff 0f 00 00  !....@.......... 
  000001d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  000001e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  000001f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 aa  ..............U.
  Execute xxd to hexdump 512 bytes in separated by 1 byte from /dev/vda to the screen
  The start of the hard drive shown by the code eb 63. File signature for an MBR.
  The first partition of the hard drive in 0x01be shown as 80
  The second partition entry is blank!
  MBR Layout Forensics Reference
  
  Wikipedia Entry on MBR Disk Layouts
  
  
  
  Making a copy of the MBR with dd — Run this on Ops Station
  student@linux-opstation-kspt:~$ dd if=/dev/vda of=MBRcopy bs=512 count=1 
  dd: failed to open '/dev/vda': Permission denied 
  student@linux-opstation-kspt:~$ sudo !! 
  1+0 records in
  1+0 records out
  512 bytes copied, 0.00026952 s, 1.9 MB/s
  student@linux-opstation-kspt:~$ file MBRcopy 
  MBRcopy: DOS/MBR boot sector
  Execute dd which copies 512 bytes once from /dev/vda to a file in my current directory called MBR
  Notice, dd failed to run
  !! represents the previous command. Run it with sudo permissions.
  Execute file to read the file signature from the MBR file
  Linux knows this is a MBR because of the file signature in the first 2 bytes of the file. Its always in hex address 0x00 and 0x01
  Supporting Concept 1: Reading Hexadecimal Addresses
  Understanding the format of a hexadecimal address, or hex, is essential to many Cyber Security fields. Luckily they are easy to understand, it is only a new way of counting! We have all learned to count to 10 in decimal notation, Hexadecimal notation requires us to count by 16 instead.



Table 2. Decimal to Hexadecimal Notation Chart
| Decimal |	Hexadecimal |
| 0 | 0x0 | 
| 1 | 0x1 |
| 2 | 0x2 |
| 3 | 0x3 |
| 4 | 0x4 |
| 5 | 0x5 |
| 6 | 0x6 |
| 7 | 0x7 |
| 8 | 0x8 |
| 9 | 0x9 |
| 10| 0xA |
| 11 | 0xB |
| 12 | 0xC |
| 13 | 0xD |
| 14 | 0xE |
| 15 | 0xF |
| 16 | 0x10 |
| 17 | 0x11 |
  
  Two digit numbers in hexadecimal have a 16ths place. That means the first 1 in 0x11 in hex is actually a 16. To put it in perspective, a two digit number in decimal notation has a max value of 99 whilst in hexadecimal notation a two digit number has a largest value of 255 or 0xFF
  0x0 is usually used in computers to let the system know that this number is in hex format. It also happens to be a handy way to let other humans know that a number is in hex. For example: 0x0000001B is the exact same thing as 0x1B
  
  
  Supporting Concept 2: Reading a Hex dump
  Since its understood that hex numbers are 0-F with a value of 0-15 understanding a hex dump is easy! Hex dumps are the raw form of a file dumped to a screen or file for us to browse. They begin from the start of the file or hex 0x00 (same thing as 0). From there, they break into 16 byte lines. Each byte represents the contents of a single hexadecimal address.
  
  10101100 (8 bits or 1 byte in Binary)
  
  AC (The above converted into hex form as 1 byte)
  
  AC 3C (Two 1 byte hex numbers)
  
  
  
  Sample Hex Dump
  00000000: cd 10 ac 3c 00 75 f4 c3 fa b7 12 e6 00 00 80 00 
  00000010: 21 02 83 0f 2e 40 00 08 00 00 df f7 ff 0f 00 00 
  16 Bytes from hex address 0x00 - 0x0F (Decimal 0 - 15)
  16 Bytes from hex address 0x10 - 0x1F (Decimal 16 - 31)
  In the example above: the hex position of 0x00 contains cd and 0x02 contains ac



### 3.2 GUID Partition Tables (GPT)
  Much like UEFI is a newer version of BIOS, GPT(Guid Partition Tables) is a new version of MBR. Once again they do the exact same thing. Yet, GPT has quite a few advantages compared to an MBR.
  
  GPT Only works with UEFI Firmware
  
  GPT has many boot sectors stored around the disk as redundancy so an issue in one will not deadline the entire machine
  
  GPT supports 128(and more depending on Operating System) separate physical partitions, while MBR supports only 4
  
  GPT Supports partitions up to 9 zettabytes. Which is ridiculous.
  ###############################END###############################
# ###############################GRUB###############################
## 4. 2nd Stage Bootloader (GRUB)
  The MBR in Grub Stage 1 loads the 2nd stage bootloader, named Grub Stage 2 or GRUB. GRUB Stage 2 rests inside the selected active partition mounted in /boot or in a completely separate partition.

### 4.1 GRUB
  GRUB(Grand Unified Bootloader) has one purpose - to load the Linux Kernel a user choses from a location in the hard drive. The GRUB has two stages which load it from two separate locations.
  
  On BIOS Systems using MBR
  Stage 1 : boot.img located in the first 440 bytes of the MBR loads…​
  Stage 1.5 : core.img located in the MBR between the bootstrap and first partition. It loads…​
  Stage 2 : /boot/grub/i386-pc/normal.mod which loads the grub menu and then reads
  
  /boot/grub/grub.cfg Which displays a list of Linux kernels available to load on the system
  
  MBR is a legacy standard. Most machines don’t use it any more. Yet, it is still used every now and then in fringe situations.
  On UEFI Systems using GPT
  Stage 1 : grubx64.efi Located on an EFI partition or in /boot loads…​
  Stage 2 : /boot/grub/x86_64-efi/normal.mod
    /boot/grub/grub.cfg Which displays a list of Linux kernels available to load on the system
    GRUB 2 Chain Loading Process Resource 1
    GRUB Deep Dive at GNU.org
  
  > Looking at Grub configuration in Linux to find the Kernel
  '''
  student@linux-opstation-kspt:/$ cat /boot/grub/grub.cfg 
  _truncated_
  set linux_gfx_mode=auto
  export linux_gfx_mode
  menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-LABEL=cloudimg-rootfs' {
          recordfail
          load_video
          gfxmode $linux_gfx_mode
          insmod gzio
          if [ x$grub_platform = xxen ]; then insmod xzio; insmod lzopio; fi
          insmod part_msdos
          insmod ext2
          if [ x$feature_platform_search_hint = xy ]; then
            search --no-floppy --fs-uuid --set=root  6c0fba3b-b236-4b3a-b999-db7359c5d220
          else
            search --no-floppy --fs-uuid --set=root 6c0fba3b-b236-4b3a-b999-db7359c5d220
          fi
          linux   /boot/vmlinuz-4.15.0-76-generic root=LABEL=cloudimg-rootfs ro  console=tty1 console=ttyS0 
          initrd  /boot/initrd.img-4.15.0-76-generic
  _truncated_
  '''
  Concatenate the contents of /boot/grub/grub.cfg to the screen.
  The kernel is loaded with the command linux. The file /boot/vmlinuz-4.15.0-76-generic contains the Linux Kernel.
  This entry in /boot/grub/grub.cfg should be around line 107.
  Do not change this file. If you do, your system may to fail to boot.
  ###############################END###############################
# ###############################BLANK###############################
## 5. Linux Kernel
  The Kernel is the heart of a Operating System. It has complete control on everything within it such as memory management, device management, Input/output Device request control, and managing process scheduling with the Central processing unit.
  
  The Linux Kernel originated from the Unix kernel and is unique from Windows in that it is :
  
  1. A Monolithic Kernel
  System calls all functionality to the user such as CPU scheduling, memory management, and file management. A systemcall is a way in which a program requests services from the kernel. Everything that occurs on the system occurs through a systemcall
  
  
  
  Showing System calls in Linux
  student@linux-opstation-kspt:/$ ltrace -S cat /etc/passwd 
  _truncated_
  open("/etc/passwd", 0, 037777402000 <unfinished ...>  
  SYS_openat(0xffffff9c, 0x7ffcbb66d68c, 0, 0)       = 3
  <... open resumed> )                               = 3
  __fxstat(1, 3, 0x7ffcbb66be40 <unfinished ...>
  SYS_fstat(3, 0x7ffcbb66be40)                       = 0
  <... __fxstat resumed> )                           = 0
  posix_fadvise(3, 0, 0, 2 <unfinished ...>
  SYS_fadvise64(3, 0, 0, 2)                          = 0
  <... posix_fadvise resumed> )                      = 0
  malloc(135167 <unfinished ...>
  SYS_mmap(0, 0x22000, 3, 34)                        = 0x7f0b09df0000
  <... malloc resumed> )                             = 0x7f0b09df0010
  read(3 <unfinished ...>
  SYS_read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 131072) = 1875
  <... read resumed> , "root:x:0:0:root:/root:/bin/bash\n"..., 131072) = 1875 
  write(1, "root:x:0:0:root:/root:/bin/bash\n"..., 1875 <unfinished ...> 
  Execute ltrace to track the systemcalls occurring when running cat /etc/passwd.
  open systemcall on /etc/passwd returns a file descriptor of 3.
  read systemcall on file descriptor of 3 returns the amount of bytes in the file.
  write systemcall to write all the 1875 bytes from /etc/passwd to stdout.
  ltrace is showing library calls from the GNU C++ Library Shared Object. The truncated section is all the system calls for memory management. This is normal because systemcalls are usually made by functions in C libraries.
  Linux System Calls



  2. Modular
  Modules are extensions to base functionality of the Linux Operating System. This modularity allows for modifications baseline system functionality without rebuilding the kernel and failures will not stop the machine from starting.
  
  Modules in Linux
  student@linux-opstation-kspt:/$ ltrace -S lsmod  
  
  Module                  Size  Used by
  aesni_intel           188416  0
  aes_x86_64             20480  1 aesni_intel 
  crypto_simd            16384  1 aesni_intel
  glue_helper            16384  1 aesni_intel
  cryptd                 24576  3 crypto_simd,ghash_clmulni_intel,aesni_intel
  psmouse               151552  0
  ip_tables              28672  0
  virtio_blk             20480  2 
  virtio_net             49152  0
  virtio_rng             16384  0
  virtio_gpu             53248  3
  Execute lsmod to list modules in Linux
  Module required to use AES Encryption
  Modules for Virtual Input / Output Devices used in Openstack instances.
  Any functionality that relies on the module will stop. But, the system will still function.
  ################################END###############################
# ###############################INIT###############################
## 6. Init
  The kernel, once loaded, is hard coded to reach out and execute /sbin/init. This starts the process of bringing the system to a desired level of functionality using Initialization Daemons. There are two main initialization daemons now : Systemd and SysV.
  
  Stack Overflow article on how the kernel knows to load /sbin/init
  
  See Line 798 for hard coded /sbin/init
  
  A term used in Init is a Run Level. A Run Level defines the state of a machine after it has completed booting and is prompting for a user login. Run levels numbered from zero(0) to six(6) have special meaning, but they are not rigid in definition.
  
  Table 3. Run Level meanings

|  RunLevel  |  Meaning  |  Description  |
|------------|-----------|---------------|
|  0  |  Halt  |  Shutdown the system  |
|  1  |  Single User  |  Allow a single user to login session with No network functionality. Used to troubleshoot.  |
|  2  |  Multi-user mode  |  Allow multiple user to login sessions with No network functionality.  |
|  3  |  Multi-user mode with networking  |  Allow multiple user to login sessions with complete networking functionality  |
|  4  |  Not used/user-definable  |  Nothing, can be set to anything  |
|  5  |  Multi-user mode with networking and GUI Desktop  |  Allow multiple user to login sessions with complete networking functionality and a graphical desktop instead of a Bash terminal  |
|  6  |  Reboot  |  Restart the system  |


### 6.1 SysV
  SysV initialization is a legacy system initialization method, but it is still used today in many older systems Linux systems or Unix machines like Oracle’s Solaris. It starts with the kernel executing the first process on the machine, or the Initialization daemon. In SysV machines it is the /etc/init program. Then, init reads /etc/inittab to start creating processes in groups called Run Levels. The processes that each Run Level starts are defined in /etc/rc*.d



### 6.1.1 SysV Init Daemon
  The program /etc/init is the first process to start in SysV Linux machines. The kernel spawns /sbin/init. Its role is to initialize the system to a target run level specified in /etc/inittab.
  
  The file /etc/inittab is a text file that contains Run Level entries as variables read by /etc/init. Entries numbered 0-6 specify a directory with scripts to start at the specified Run Level. By default the system will try to start the initdefault run level. If that fails to start, the machine will display an error, then execute the scripts in the 0(halt) run level.
  
  Oracle Documentation on the Inittab File
  
  
  
  Sample of /etc/initab on a SysV machine
  ```
  cat /etc/inittab
  
  is:5:initdefault: 
  
  
  l0:0:wait:/etc/rc0.d
  l1:1:wait:/etc/rc1.d
  l2:2:wait:/etc/rc2.d
  l3:3:wait:/etc/rc3.d
  l4:4:wait:/etc/rc4.d 
  l5:5:wait:/etc/rc5.d
  l6:6:wait:/etc/rc6.d
```
  >The run level 5 is the default run level in /etc/inittab
  >Another non-default run level is in /etc/rc4.d


### 6.1.2 Run Levels
  Run Levels in SysV are a series of scripts that start or kill background processes on Linux at specific run levels. The scripts have a specific naming scheme that determine how the init process interacts with them.
  
  The first letter K or S means Kill or Start the process that that script handles
  
  The two digit number that follows K or S dictates the order the scripts execute
  
  Another name for background processes (or services) in Linux is a daemon. Daemons run in the background and maintain user mode functionality such as DHCP or enabling SSH.
  
  Sample contents of a /etc/rc#.d directory
  
  ```
  student@linux-opstation-kspt:/etc/rc3.d$ ls -l /etc/rc3.d/ 
  lrwxrwxrwx 1 root root 15 Jan 31  2020 S01acpid -> ../init.d/acpid 
  lrwxrwxrwx 1 root root 17 Feb  4  2020 S01anacron -> ../init.d/anacron
  lrwxrwxrwx 1 root root 16 Jan 31  2020 S01apport -> ../init.d/apport
  lrwxrwxrwx 1 root root 13 Jan 31  2020 S01atd -> ../init.d/atd
  lrwxrwxrwx 1 root root 26 Jan 31  2020 S01console-setup.sh -> ../init.d/console-setup.sh
  lrwxrwxrwx 1 root root 14 Jan 31  2020 S01cron -> ../init.d/cron
  lrwxrwxrwx 1 root root 14 Jan 31  2020 S01dbus -> ../init.d/dbus
  lrwxrwxrwx 1 root root 14 Feb  4  2020 S01gdm3 -> ../init.d/gdm3
  ```
  ```
  student@linux-opstation-kspt:/etc/rc3.d$ ls -l /etc/rc1.d/ 
  
  lrwxrwxrwx 1 root root 20 Feb  4  2020 K01alsa-utils -> ../init.d/alsa-utils
  lrwxrwxrwx 1 root root 13 Jan 31  2020 K01atd -> ../init.d/atd
  lrwxrwxrwx 1 root root 20 Jan 31  2020 K01cryptdisks -> ../init.d/cryptdisks
  lrwxrwxrwx 1 root root 26 Jan 31  2020 K01cryptdisks-early -> ../init.d/cryptdisks-early
  lrwxrwxrwx 1 root root 18 Jan 31  2020 K01ebtables -> ../init.d/ebtables
  lrwxrwxrwx 1 root root 14 Feb  4  2020 K01gdm3 -> ../init.d/gdm3 
  ```
  List the contents of the /etc/rc3.d/ directory
  S01acpid is *symbolically linked to ../init.d/acpid
  List the contents of the /etc/rc1.d/ directory
  Notice how the S is a K now? What run level is this?
  These files are Symbolically linked to scripts in the init.d directory.
  
  ```
  Looking at an bash script in /etc/init.d/gdm3
  #! /bin/sh 
  ### BEGIN INIT INFO
  
  _truncated_
  
  PATH=/sbin:/bin:/usr/sbin:/usr/bin
  DAEMON=/usr/sbin/gdm3 
  PIDFILE=/var/run/gdm3.pid
  
  test -x $DAEMON || exit 0
  the #!/bin/bash shows that this is a bash script.
  /usr/sbin/gdm3 is the program run for this daemon.
  The last thing to start is the login program. init spawns a login to each of the Linux virtual consoles. The getty command specified in the inittab displays this login. When given a login name, getty invokes /bin/login, which prompts the user for a password, authentication to the system takes place, and brings a terminal back.
  ```
  

### 6.2 Systemd
  Systemd is the modern initialization method. It starts with the kernel spawning /sbin/init which is symbolically linked to /lib/systemd/system. systemd interacts with flat configuration files called units. There are many types, but the target and service units determine system initialization.

​

### 6.2.1 Systemd Init target.units
  The kernel spawns /usr/lib/systemd/system as the first process on the system. It then executes configurations starting at mounting the local file system to bringing the system to a desired state specified in the default target unit. Targets in systemd are like runlevels in SysV. The name of the default target is default.target and located in /lib/systemd/system.
  
  Table 4. Translating between Run Levels and Systemd Targets
  Run Level	Meaning	Systemd Target
  0
  
  Halt
  
  poweroff.target
  
  1
  
  Single User
  
  rescue.target
  
  2
  
  Multi-user mode
  
  multi-user.target
  
  3
  
  Multi-user mode with networking
  
  multi-user.target
  
  4
  
  Not used/user-definable
  
  multi-user.target
  
  5
  
  Multi-user mode with networking and GUI Desktop
  
  graphical.target
  
  6
  
  Reboot
  
  reboot.target
  
  Systemd Target Unit to Runlevel Translate Source
  
  ​
  
  Showing the default target unit
  student@linux-opstation-kspt:/$ ls -lisa /lib/systemd/system/default.target
  
  lrwxrwxrwx 1 root root 16 May  3 11:30 default.target -> graphical.target 
  Symbolically linked default.target to graphical.target unit.
  The system will, by default, try to run the system to the specifics set by graphical.target.
  ​

### 6.2.2 Target units
  Systemd target units are a set of value=data pairs to create processes in a set order on the system. But, they are simple to understand at a functional level by understanding the value=data fields within each.
  
  Examining the Contents of the graphical.target
  cat /lib/systemd/system/default.target | tail -n 8
  
  Description=Graphical Interface
  Documentation=man:systemd.special(7)
  Requires=multi-user.target
  Wants=display-manager.service 
  Conflicts=rescue.service rescue.target
  After=multi-user.target rescue.service rescue.target display-manager.service 
  AllowIsolate=yes
  wants=display-manager.service attempts to start other units. If they fail to start, the calling target unit will still execute.
  requires=multi-server.target attempts to start other units. If they fail to start, the calling target unit will fail to execute.
  ​
  
  Yet, wants and requires statements can also come from other locations on the file system. Target units search for dependencies in eleven other locations around the file system.
  
  Target.unit want and requires dependencies search locations
  /etc/systemd/system/*
  
  /lib/systemd/system/*
  
  /run/systemd/generator/*
  
  More found in System Unit Man Page
  
  Showing more wants and requires to graphical.target — Run on Ops Station
  student@linux-opstation-kspt:/$ ls -l /etc/systemd/system/ | grep graphical
  drwxr-xr-x 2 root root 4096 Feb  4  2020 graphical.target.wants 
  
  student@linux-opstation-kspt:/$ ls -l /etc/systemd/system/graphical.target.wants/
  total 0
  lrwxrwxrwx 1 root root 43 Jan 31  2020 accounts-daemon.service -> /lib/systemd/system/accounts-daemon.service  
  lrwxrwxrwx 1 root root 35 Feb  4  2020 udisks2.service -> /lib/systemd/system/udisks2.service 
  
  student@linux-opstation-kspt:/$ ls -l /lib/systemd/system | grep graphical
  lrwxrwxrwx 1 root root   16 Nov 15  2019 default.target -> graphical.target
  -rw-r--r-- 1 root root  598 Jan 28  2018 graphical.target
  drwxr-xr-x 2 root root 4096 Jan 31  2020 graphical.target.wants 
  lrwxrwxrwx 1 root root   16 Nov 15  2019 runlevel5.target -> graphical.target
  
  student@linux-opstation-kspt:/$ ls -l /lib/systemd/system/graphical.target.wants/
  total 0
  lrwxrwxrwx 1 root root 39 Nov 15  2019 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service 
  A graphical.target wants directory in /etc/systemd/system/
  graphical.target also target wants udisks2.service and accounts-daemon.service
  Yet another graphical.target wants directory in /lib/systemd/system/
  graphical.target also wants systemd-update-utmp-runlevel.service
  ​
  
  Breaking it down into steps brings the following conclusion:
  
  This means that the default.target is actually graphical.target
  
  The graphical.target unit wants to start:
  
  display-manager.service
  
  udisks2.service
  
  accounts-daemon.service
  
  systemd-update-utmp-runlevel.service
  
  But, the graphical.target requires the multi-user.target to execute.
  
  Understanding systemd.units
  
  That is not every the wants statement to graphical.target. Remember, it searches 11 different directories for these.
  ​

### 6.2.3 Service units
  Service units create processes when called by target units. They, much like target units, have value=data pairs that determine what the unit does.

  
  Examining the Contents of the display-manager.service
  ```
  cat /etc/systemd/system/display-manager.service | tail -n 13
  
  [Service]
  ExecStartPre=/usr/share/gdm/generate-config
  ExecStart=/usr/sbin/gdm3 
  KillMode=mixed
  Restart=always 
  RestartSec=1s
  IgnoreSIGPIPE=no
  BusName=org.gnome.DisplayManager
  StandardOutput=syslog
  StandardError=inherit
  EnvironmentFile=-/etc/default/locale
  ExecReload=/usr/share/gdm/generate-config
  ExecReload=/bin/kill -SIGHUP $MAINPID
  ExecStart=/usr/sbin/gdm3 causes the systemd process to execute the command specified along with any arguments.
  Restart=always tells systemd to attempt to restart the command in ExecStart.
  Understanding systemd service units
  ```
  ​

### 6.2.4 Systemd putting it all together
  Systemd is a complex initialization method with interweaving dependencies, hundreds' of files across the system, and unique file types. It is possible to query each file and use the find command to locate dependencies, but there is a much easier way. The systemctl command comes with every systemd machine to query and manage details relating to its dependencies.
  
  By default, systemctl shows every unit file currently visible by systemd. However, it takes arguments to:
  
  1. List unit dependencies in a tree form
  systemctl list-dependencies graphical.target
  ```
  graphical.target
  ● ├─accounts-daemon.service
  ● ├─apport.service
  ● ├─gdm.service 
  ● ├─grub-common.service
  ● ├─qemu-guest-agent.service
  ● ├─systemd-update-utmp-runlevel.service
  ● ├─udisks2.service 
  ● ├─ureadahead.service
  ● └─multi-user.target 
  ●   ├─anacron.service
  Wants statements to graphical.target
  Requires statements to graphical.target
  ```
  
  2. Show wants to individual units.
  ```
  systemctl show -p Wants graphical.target
  
  Wants=ureadahead.service qemu-guest-agent.service gdm.service systemd-update-utmp-runlevel.service grub-common.service accounts-daemon.service udisks2.service apport.service 
```
> That is a lot more wants statements than found in the 2 directories we searched in 6.2.2.
  ​
  
  3. List every individual unit file.
  ```
  systemctl list-unit-files
  
  UNIT FILE                                  STATE
  spice-vdagent.service                      enabled
  spice-vdagentd.service                     enabled
  ssh.service                                enabled 
  ssh@.service                               static
  sshd.service                               enabled
  stop-bootlogd-single.service               masked
  
  _truncated_
  339 unit files listed. 
  A unit file for ssh.service
  Total number of unit files seen by systemd
  ```
  
  4. Concatenate the contents of a unit file to the screen.
  ```
  systemctl cat graphical.target
  
  # /lib/systemd/system/graphical.target
  #  SPDX-License-Identifier: LGPL-2.1+
  #
  #  This file is part of systemd.
  #
  #  systemd is free software; you can redistribute it and/or modify it
  #  under the terms of the GNU Lesser General Public License as published by
  #  the Free Software Foundation; either version 2.1 of the License, or
  #  (at your option) any later version.
  
  [Unit]
  Description=Graphical Interface
  Documentation=man:systemd.special(7)
  Requires=multi-user.target
  Wants=display-manager.service
  Conflicts=rescue.service rescue.target
  After=multi-user.target rescue.service rescue.target display-manager.service
  AllowIsolate=yes
  The file sent to the screen will not every wants or requires dependency within it. Ensure that you check all the locations and use systemctl to locate dependencies.
```
  ###############################END###############################
# ###############################POST BOOT###############################
## 7. Post Boot
  Actions in the post boot stage encompass user shell environment customization with scripts and text files read by other programs. Each file is read at specific point when users log in. Each locate presented in the post boot process is easily changeable unlike earlier stages of the boot process. Adversaries can take advantage of this flexibility to run any script they want. Be mindful of that when evaluating a Linux system.

​

### 7.1 The /etc/environment file
  The /etc/environment file sets Global Variables. Global Variables are accessible by every user or process on the system. It is read once when the machine completes Init. Any changes to the file require a system restart for them to apply.
  
  In the example below, /etc/`environment is setting the PATH variable. This variable is the search path for executables from the command line. It allows a user to type ls instead of /bin/ls when they want to use it.
  
  The /etc/environment file is part of PAM(Pluggable Authentication Modules) 6.6.1 used to authenticate users in Linux. That is why it isn’t a bash script like everything else.
  Looking at /etc/environment
  cat /etc/environment
  
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games" 
  The path variable contains all default locations to executables in Linux delimited by :.
  Executables not located in the path can not be executed by typing in the name of the executable, unless it is located in the same directory. Instead, the absolute or relative path to the executable must be given.
  Ubuntu Help: Persistent environment variables
  
  ​

### 7.2 The /etc/profile file
  /etc/profile is a script that executes whenever a user logs into an interactive shell on Linux. its functionality depends entirely on the version of Linux being used. Ubuntu Linux uses it to set the BASH shell prompt by executing /etc/bash.bashrc and execute any script named *.sh in /etc/profile.d.
  
  Unlike /etc/environment it executes every time a user logs in interactively; therefore, when the file is modified logging out then in again will apply the changes.
  
  Interactive Logins accept user input from a tty or commandline. Non-Interactive logins, such as the ones used by services or ssh remote commands, will not execute /etc/profile
  Examining /etc/profile
  student@linux-opstation-kspt:~$ cat /etc/profile
  ```
  # /etc/profile: system-wide .profile file for the Bourne shell (sh(1))
  # and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).
  
  if [ "${PS1-}" ]; then
    if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then 
      # The file bash.bashrc already sets the default PS1.
      # PS1='\h:\w\$ '
      if [ -f /etc/bash.bashrc ]; then 
        . /etc/bash.bashrc  
      fi
  _truncated_
  if [ -d /etc/profile.d ]; then
    for i in /etc/profile.d/*.sh; do
      if [ -r $i ]; then
        . $i 
      fi
    done
    unset i
  fi

  If the variable $BASH is set and does not equal /bin/sh then execute
  if the /etc/bash.bashrc exists, execute it.
  /etc/bash.bashrc creates the bash prompt student@linux-opstation-kspt:~$
  If the directory /etc/profile.d exists, execute any script named *.sh in that directory.
```
### 7.3 The .bash_profile and .bashrc files
  Unique to BASH(Bourne Again Shell) are .bash_profile and .bashrc. They execute on a per user basis for interactive logins only. Both files are located every user’s /home directory. They are user specific configurations and freely editable by the owning user or root.
  
  .bash_profile is a bash script that executes when a user invokes an interactive login shell on the system. Interactive login shells only occur when prompted for a password while logging in like when using ssh or telnet to access a system. .bash_profile is also called .profile on many systems as well.
  
  .bashrc on the other hand, executes when interactive non-login shell is invoked. Non-Login interactive shells occur when not prompted for credentials.
  ```
  Demonstrate the difference between interactive login shells and Non-Login interactive shells
  student@linux-opstation-kspt:~$ cd $HOME
  student@linux-opstation-kspt:~$ echo "echo 'Im in `~/.profile`'" >> .profile 
  student@linux-opstation-kspt:~$ echo "echo 'Im in ~/.bashrc'" >> .bashrc 
  
  student@linux-opstation-kspt:~$ bash
  student@linux-opstation-kspt:~$ Im in ~/.bashrc
  student@linux-opstation-kspt:~$ exit 
  student@linux-opstation-kspt:~$ exit 
  
  #Log back into same Linux machine
  Last login: Fri Feb 26 12:55:13 2021 from 10.250.0.20
  Im in ~/.bashrc
  Im in /etc/profile 
  student@linux-opstation-kspt:~$
  Echo a phrase into .profile and .bashrc
  Create a Non-Login interactive shell by spawning a new bash session
  Exit the new session AND logout of the machine
  Logins create an interactive login shell; therefore,
  
  ###############################END###############################
  ##############################################################END OF DAY 5##############################################################
```

# Day 6
# Windows Process Validity
##############################################################DAY 6##############################################################
###############################BLANK###############################
## 1. What is Process Validity and Why it Matters


### 1.1 What is Process Validity?
  Being able to distinguish a Process as a known good from a possible bad from its attributes and characteristics.
  
  Today’s Malware typically use their stealth and obfuscation abilities in order to hide in various artifacts such as:
  
  processes
  
  files
  
  registry keys
  
  drivers
  
  etc.
  
  They try to leave as little evidence of their presence as possible by mimicking or by hooking onto legitimate processes or services.
  


### 1.2 Why is Process Validity Important?
  OCO - Offensive Operations
  
  We need to protect our toolset (malware we’ve created).
  
  Find any other types of malware on the box that could compromise our tools.
  
  DCO - Defensive Operations
  
  Find malware and defend our networks
  
  Make sure we are not compromised or have sensitive information stolen from us.
  
  Could be the difference between life and death for soldiers on mission.
  ###############################END###############################
###############################Processes, DLLS, and Services###############################
## 2. Processes, DLLs, and Services
### 2.1 What are they?
  What is a process?
  
  A program running on your computer, whether executed by the user or running in the background.
  
  Examples include:
  
  Background tasks like spell checker
  
  Executables like Google Chrome and Notepad
  
  
  
  What is a DLL?
  
  Dynamic Link Library
  
  A non-standalone program that can be run by (linked to) multiple programs at the same time.
  
  Cannot be directly executed. Dependent on an exe to use as an entry point, such as RUNDLL.EXE (a process that calls on the functionality of the DLL)
  
  Allows developers to make minor changes without affecting other parts of the program.
  
  Some Examples Include:
  
  Comdlg32 - Performs common dialog box related functions.
  
  Device drivers
  
  ActiveX Controls
  
  If you want to dig deeper: Ask Microsoft
  
  
  
  What is a Service?
  
  Long-running executables that run in their own Windows sessions (i.e. in the background)
  
  Can be set to auto start when the computer boots or a user logs on.
  
  Can be paused and restarted.
  
  Do not interact with/show any user interface.
  
  If you want to dig deeper: Ask Microsoft
  
  Processes, Services, and Daemons are all the same thing
  

### 2.2 How to view Processes and DLLs
  Q: Which Windows commands let us view processes?
  
  PowerShell: Get-Process - Microsoft Reference
  
  CMD: tasklist
  


### 2.2.1 View Processes In PowerShell


  View all Processes, not sorted.
  
  Get-Process
  
  ```
  PS C:\Users\student> Get-Process
  
  Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
  -------  ------    -----      -----     ------     --  -- -----------
      278      18     9420      18984       3.61   6304   1 ApplicationFrameHost
      342      19     4516       3988              4624   0 armsvc
      958      57   127900     202620      51.38    632   1 atom
      572      82   182356     266836     117.64   3148   1 atom
      321      33    92760     164644       0.56   7864   1 atom
      222      15     6884      28916       0.03   8024   1 atom
      733      27   143268     172480      38.33  13980   1 atom
       68       5     2040       4128       0.02   7504   1 cmd
  ```
  View all Processes, sort them by PID.
  
  Get-Process | Sort -Property Id | more
  
  ```
  PS C:\Users\student> Get-Process | Sort -Property Id | more
  
  Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
  -------  ------    -----      -----     ------     --  -- -----------
        0       0       60          8                 0   0 Idle
     4240       0      192         96                 4   0 System
        0       0      184      22332                72   0 Secure System
        0      17     6552      28656               132   0 Registry
      168      11     1432       3484               452   0 wininit
       53       3     1056        940               504   0 smss
  
  -- More --
  ```
  View all processes, but sort by PID and only show the properties I define.
  
  Get-Process | Select Name, Id, Description | Sort -Property Id | more
  
  ```
  PS C:\Users\student> Get-Process | Select Name, Id, Description | Sort -Property Id | more
  
  Name                       Id Description
  ----                       -- -----------
  Idle                        0
  System                      4
  Secure System              72
  Registry                  132
  wininit                   452
  smss                      504
  LsaIso                    572
  csrss                     576
  svchost                   624
  atom                      632 Atom
  svchost                   852
  rundll32                 1616 Windows host process (Rundll32)
  CompPkgSrv               1788 Component Package Support Server
  Slack                    1816 Slack
  
  -- More --
  ```
  View only the processes I define and sort by PID
  
  Get-Process SMSS,CSRSS,LSASS | Sort -Property Id
  ```
  PS C:\Users\student> Get-Process SMSS,CSRSS,LSASS | Sort -Property Id
  
  Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
  -------  ------    -----      -----     ------     --  -- -----------
       53       3     1056        940               504   0 smss
      717      33     3684       3688               576   1 csrss
      784      24     1928       2788               876   0 csrss
     1612      39    10352      18076              1028   0 lsass
  ```
  
  View modules/DLLs used by defined process and their file locations.
  
  Get-Process chrome | foreach {$_.modules} | more
  
  Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more
  ```
  PS C:\Users\student> Get-Process chrome | foreach {$_.modules} | more
  
     Size(K) ModuleName                                         FileName
     ------- ----------                                         --------
        2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
        2008 ntdll.dll                                          C:\WINDOWS\SYSTEM32\ntdll.dll
         756 KERNEL32.DLL                                       C:\WINDOWS\System32\KERNEL32.DLL
        2852 KERNELBASE.dll                                     C:\WINDOWS\System32\KERNELBASE.dll
        1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
          40 VERSION.dll                                        C:\WINDOWS\SYSTEM32\VERSION.dll
  
  -- More --
  ```
  
  View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.
  
  Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '*chrome*' | more
  
  Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more
  
  Pipe in a ft -wrap to see full file name/path.
  
  PS C:\Users\student> Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '\*chrome*' | more
  
  ```
     Size(K) ModuleName                                         FileName
     ------- ----------                                         --------
        2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
        1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
        2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
        1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
      152776 chrome.dll                                         C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
  
  -- More --
  ```
  
  Use the Get-Ciminstance Win32_Process cmdlet to veiw processes with PPID
  
  1) View Process instances with Win32 process.
  
  Get-Ciminstance Win32_Process
  
  PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process
  ```
  ProcessId Name                        HandleCount WorkingSetSize VirtualSize
  --------- ----                        ----------- -------------- -----------
  0         System Idle Process         0           8192           4096
  4         System                      4114        36864          3997696
  108       Registry                    0           34344960       93061120
  372       smss.exe                    59          425984         2203359731712
  476       csrss.exe                   583         2076672        2203413258240
  552       wininit.exe                 165         1449984        2203387731968
  560       csrss.exe                   360         1101824        2203404800000
  /---OUTPUT TRUNCATED---/
  ```
  
  2) View the additional Properties with Get-Member
  ```
  PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process | Get-Member
     TypeName:
  Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process
  
  Name                       MemberType     Definition
  ----                       ----------     ----------
  /---OUTPUT TRUNCATED---/
  ParentProcessId            Property       uint32 ParentProcessId {get;}
  /---OUTPUT TRUNCATED---/
  3) View the processes with PID and PPID sorted by PID
  
  PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process | select name,ProcessId,ParentProcessId | sort processid
  
  name                        ProcessId ParentProcessId
  ----                        --------- ---------------
  System Idle Process                 0               0
  System                              4               0
  msedge.exe                         32            9744
  Registry                          108               4
  smss.exe                          372               4
  svchost.exe                       396             696
  dwm.exe                           408             612
  csrss.exe                         476             468
  notepad.exe                       488            7524
  /---OUTPUT TRUNCATED---/
  ```
  
  View an instance of all Win32 (system) services.
  
  Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
  
  Pipe in ft -wrap to see full file name/path
  ```
  PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | ft -wrap | more
  
  Name                                                   Processid Pathname
  ----                                                   --------- --------
  AdobeARMservice                                             4624 "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"
  AJRouter                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
  ALG                                                            0 C:\WINDOWS\System32\alg.exe
  AppIDSvc                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
  Appinfo                                                     7752 C:\WINDOWS\system32\svchost.exe -k netsvcs -p
  AppReadiness                                                   0 C:\WINDOWS\System32\svchost.exe -k AppReadiness -p
  AppXSvc                                                    13292 C:\WINDOWS\system32\svchost.exe -k wsappx -p
  AudioEndpointBuilder                                        3168 C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
  Audiosrv                                                    3920 C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
  autotimesvc                                                    0 C:\WINDOWS\system32\svchost.exe -k autoTimeSvc
  AxInstSV                                                       0 C:\WINDOWS\system32\svchost.exe -k AxInstSVGroup
  BDESVC                                                      1628 C:\WINDOWS\System32\svchost.exe -k netsvcs -p
  BFE                                                         3908 C:\WINDOWS\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
  BITS                                                           0 C:\WINDOWS\System32\svchost.exe -k netsvcs -p
  BrokerInfrastructure                                        1172 C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p
  
  -- More --
  ```

### 2.2.2 View Processes in Command Prompt


  View all processes
  
  tasklist
  ```
  C:\Users\student> tasklist | more
  
  Image Name                     PID Session Name        Session#    Mem Usage
  ========================= ======== ================ =========== ============
  System Idle Process              0 Services                   0          8 K
  System                           4 Services                   0         96 K
  Secure System                   72 Services                   0     22,332 K
  Registry                       132 Services                   0     28,948 K
  smss.exe                       504 Services                   0        940 K
  csrss.exe                      876 Services                   0      2,800 K
  wininit.exe                    452 Services                   0      3,484 K
  csrss.exe                      576 Console                    1      3,648 K
  winlogon.exe                   916 Console                    1      6,204 K
  services.exe                   976 Services                   0      6,996 K
  
  -- More --
  ```
  
  Display verbose task information in the output
  
  tasklist /v
  ```
  C:\Users\student> tasklist /v | more
  svchost.exe                   3012 Services                   0      5,364 K Unknown         N/A
  Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                      CPU Time Window Title
  ========================= ======== ================ =========== ============ =============== ========================   ===============================
  System Idle Process              0 Services                   0          8 K Unknown         NT AUTHORITY\SYSTEM              1628:26:24 N/A
  System                           4 Services                   0         96 K Unknown         N/A                              0:44:21 N/A
  Secure System                   72 Services                   0     22,332 K Unknown         N/A                              0:00:00 N/A
  Registry                       132 Services                   0     37,948 K Unknown         N/A                              0:00:12 N/A
  smss.exe                       504 Services                   0        940 K Unknown         N/A                              0:00:00 N/A
  csrss.exe                      876 Services                   0      2,908 K Unknown         N/A                              0:00:06 N/A
  wininit.exe                    452 Services                   0      3,488 K Unknown         N/A                              0:00:00 N/A
  
  -- More --
  ```
  
  Display service information for each process without truncation
  
  tasklist /svc
  ```
  C:\Users\student> tasklist /svc
  
  Image Name                     PID Services
  ========================= ======== ============================================
  System Idle Process              0 N/A
  System                           4 N/A
  Secure System                   72 N/A
  Registry                       132 N/A
  smss.exe                       504 N/A
  csrss.exe                      876 N/A
  wininit.exe                    452 N/A
  csrss.exe                      576 N/A
  winlogon.exe                   916 N/A
  services.exe                   976 N/A
  LsaIso.exe                     572 N/A
  lsass.exe                     1028 EFS, KeyIso, SamSs, VaultSvc
  svchost.exe                   1172 BrokerInfrastructure, DcomLaunch, PlugPlay,
                                     Power, SystemEventsBroker
  
  -- More --
  ```
  
  Display modules/dlls associated to all processes.
  
  tasklist /m | more
  ```
  C:\Users\student> tasklist /m | more
  
  Image Name                     PID Modules
  ========================= ======== ============================================
  System Idle Process              0 N/A
  System                           4 N/A
  Secure System                   72 N/A
  Registry                       132 N/A
  smss.exe                       504 N/A
  csrss.exe                      876 N/A
  wininit.exe                    452 N/A
  csrss.exe                      576 N/A
  winlogon.exe                   916 N/A
  services.exe                   976 N/A
  LsaIso.exe                     572 N/A
  lsass.exe                     1028 N/A
  svchost.exe                   1160 N/A
  sihost.exe                    4720 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                     msvcp_win.dll, ucrtbase.dll, combase.dll,
                                     RPCRT4.dll, sechost.dll, advapi32.dll,
                                     msvcrt.dll, CoreMessaging.dll, WS2_32.dll,
                                     ntmarta.dll, kernel.appcore.dll,
  -- More --
  ```
  
  Display modules/dlls associated to a specific process.
  
  tasklist /m /fi "IMAGENAME eq chrome.exe"
  ```
  C:\Users\student> tasklist /m /fi "IMAGENAME eq chrome.exe" | more
  
  Image Name                     PID Modules
  ========================= ======== ============================================
  chrome.exe                    8260 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                     chrome_elf.dll, VERSION.dll, msvcrt.dll,
                                     ADVAPI32.dll, sechost.dll, RPCRT4.dll,
                                     CRYPTBASE.DLL, bcryptPrimitives.dll,
                                     ntmarta.dll, ucrtbase.dll, user32.dll,
                                     win32u.dll, GDI32.dll, gdi32full.dll,
                                     msvcp_win.dll, IMM32.DLL, SHELL32.dll,
                                     windows.storage.dll, combase.dll, Wldp.dll,
                                     SHCORE.dll, shlwapi.dll, chrome.dll,
  
  -- More  --
  ```
  
  Formating options
  
  tasklist /fo:{table|list|csv}`
  ```
  C:\Users\student> tasklist /fo:table | more
  
  Image Name                     PID Session Name        Session#    Mem Usage
  ========================= ======== ================ =========== ============
  System Idle Process              0 Services                   0          8 K
  System                           4 Services                   0         96 K
  Secure System                   72 Services                   0     22,332 K
  Registry                       132 Services                   0     37,876 K
  smss.exe                       504 Services                   0        964 K
  csrss.exe                      876 Services                   0      2,940 K
  wininit.exe                    452 Services                   0      3,712 K
  
  -- More --
  C:\Users\student> tasklist /fo:list | more
  
  Image Name:   System Idle Process
  PID:          0
  Session Name: Services
  Session#:     0
  Mem Usage:    8 K
  
  Image Name:   System
  PID:          4
  Session Name: Services
  Session#:     0
  Mem Usage:    96 K
  
  Image Name:   Secure System
  PID:          72
  Session Name: Services
  Session#:     0
  Mem Usage:    22,332 K
  
  -- More --
  C:\Users\student> tasklist /fo:csv | more
  
  "Image Name","PID","Session Name","Session#","Mem Usage"
  "System Idle Process","0","Services","0","8 K"
  "System","4","Services","0","96 K"
  "Secure System","72","Services","0","22,332 K"
  "Registry","132","Services","0","37,876 K"
  "smss.exe","504","Services","0","964 K"
  "csrss.exe","876","Services","0","2,940 K"
  "wininit.exe","452","Services","0","3,712 K"
  "csrss.exe","576","Console","1","4,948 K"
  "winlogon.exe","916","Console","1","6,600 K"
  "services.exe","976","Services","0","7,636 K"
  
  -- More --
  
  
  Filtering for specific string/process
  
  tasklist /fi "IMAGENAME eq lsass.exe"
  
  C:\Users\student>tasklist /fi "IMAGENAME eq lsass.exe
  
  Image Name                     PID Session Name        Session#    Mem Usage
  ========================= ======== ================ =========== ============
  lsass.exe                     1028 Services                   0     17,984 K
  
  ```
### 2.2.3 View Processes in the GUI
  Task Manager
  
  Microsoft Default
  
  Procexp.exe
  
  We’ll go over it in Sysinternal Tools Lesson
  
  Microsoft Reference
  


### 2.3 How to View Services


  Q: Which Windows commands let us view information on services?
  
  In Powershell:
  
  Get-Ciminstance - Microsoft Reference
  
  Get-Service - Microsoft Reference
  
  In Command Prompt:
  
  net start - Shows currently running services
  
  sc query - Microsoft Reference



### 2.3.1 View Services in PowerShell


  View only system services and display Name, PID, and the path they are initiated from.
  
  Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
  
  Pipe in a ft -wrap to see full pathname.
  ```
  PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
  
  Name                                                   Processid Pathname
  ----                                                   --------- --------
  AdobeARMservice                                             4624 "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"
  AJRouter                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestri...
  ALG                                                            0 C:\WINDOWS\System32\alg.exe
  AppIDSvc                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestri...
  Appinfo                                                     7752 C:\WINDOWS\system32\svchost.exe -k netsvcs -p
  AppReadiness                                                   0 C:\WINDOWS\System32\svchost.exe -k AppReadiness -p
  AppXSvc                                                        0 C:\WINDOWS\system32\svchost.exe -k wsappx -p
  AudioEndpointBuilder                                        3168 C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestric...
  Audiosrv                                                    3920 C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestri...
  
  -- More --
  ```
  
  View all services.
  
  Get-service
  ```
  PS C:\Users\student> get-service | more
  
  Status   Name               DisplayName
  ------   ----               -----------
  Stopped  AarSvc_5d854       Agent Activation Runtime_5d854
  Running  AdobeARMservice    Adobe Acrobat Update Service
  Stopped  AJRouter           AllJoyn Router Service
  Stopped  ALG                Application Layer Gateway Service
  Stopped  AppIDSvc           Application Identity
  
  -- More  --
  ```
  
  View a defined service, showing all properties in list format.
  
  get-service ALG | format-list *
  ```
  PS C:\Users\student> get-service ALG | format-list *
  
  
  Name                : ALG
  RequiredServices    : {}
  CanPauseAndContinue : False
  CanShutdown         : False
  CanStop             : False
  DisplayName         : Application Layer Gateway Service
  DependentServices   : {}
  MachineName         : .
  ServiceName         : ALG
  ServicesDependedOn  : {}
  ServiceHandle       :
  Status              : Stopped
  ServiceType         : Win32OwnProcess
  StartType           : Manual
  Site                :
  Container           :
  ```
  
  View only currently running services.
  
  Get-Service | Where-Object {$_.Status -eq "Running"}
  ```
  PS C:\Users\student> Get-Service | Where-Object {$_.Status -eq "Running"} | more
  
  Status   Name               DisplayName
  ------   ----               -----------
  Running  AdobeARMservice    Adobe Acrobat Update Service
  Running  Appinfo            Application Information
  Running  AppXSvc            AppX Deployment Service (AppXSVC)
  Running  AudioEndpointBu... Windows Audio Endpoint Builder
  Running  Audiosrv           Windows Audio
  Running  BDESVC             BitLocker Drive Encryption Service
  Running  BFE                Base Filtering Engine
  
  -- More  --
  ```

### 2.3.2 View Services in Command Prompt


  View Services
  
  sc query
  ```
  C:\Users\student>sc query | more
  
  SERVICE_NAME: AdobeARMservice
  DISPLAY_NAME: Adobe Acrobat Update Service
          TYPE               : 10  WIN32_OWN_PROCESS
          STATE              : 4  RUNNING
                                  (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
          WIN32_EXIT_CODE    : 0  (0x0)
          SERVICE_EXIT_CODE  : 0  (0x0)
          CHECKPOINT         : 0x0
          WAIT_HINT          : 0x0
  
  SERVICE_NAME: Appinfo
  DISPLAY_NAME: Application Information
  
  -- More --
  ```
  View extended information for all services.
  
  sc queryex type=service
  ```
  C:\Users\student>sc queryex type=service | more
  
  SERVICE_NAME: AdobeARMservice
  DISPLAY_NAME: Adobe Acrobat Update Service
          TYPE               : 10  WIN32_OWN_PROCESS
          STATE              : 4  RUNNING
                                  (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
          WIN32_EXIT_CODE    : 0  (0x0)
          SERVICE_EXIT_CODE  : 0  (0x0)
          CHECKPOINT         : 0x0
          WAIT_HINT          : 0x0
          PID                : 4624
          FLAGS              :
  
  SERVICE_NAME: Appinfo
  DISPLAY_NAME: Application Information
  
  -- More  --
  ```
  
  View extended information for all inactive services.
  
  sc queryex type=service state=inactive
  ```
  C:\Users\student>sc queryex type=service state=inactive | more
  
  SERVICE_NAME: AJRouter
  DISPLAY_NAME: AllJoyn Router Service
          TYPE               : 20  WIN32_SHARE_PROCESS
          STATE              : 1  STOPPED
          WIN32_EXIT_CODE    : 1077  (0x435)
          SERVICE_EXIT_CODE  : 0  (0x0)
          CHECKPOINT         : 0x0
          WAIT_HINT          : 0x0
          PID                : 0
          FLAGS              :
  
  SERVICE_NAME: ALG
  DISPLAY_NAME: Application Layer Gateway Service
          TYPE               : 10  WIN32_OWN_PROCESS
  
  -- More  --
  ```
  ```
  Additional examples of the SC command
  
  C:\sc /?                           # Basic service enumeration
  C:\sc qc                           # Configuration information for a service
  C:\sc queryex eventlog             # Information for the eventlog service including pid
  C:\sc qdescription eventlog        # Query eventlog service description
  C:\sc qc eventlog                  # Show the binary command that loads the service
  C:\sc showsid eventlog             # Displays the service SID and status
  c:\sc enmudepend                   # Lists the services that cannot run unless the specified service is running
  ```
  
  View all currently running services.
  
  net start
  ```
  C:\Users\student>net start | more
  These Windows services are started:
  
     Adobe Acrobat Update Service
     Application Information
     AppX Deployment Service (AppXSVC)
     AVCTP service
     Background Tasks Infrastructure Service
     Base Filtering Engine
  
  -- More  --
  ```

### 2.3.3 View Services in the GUI


  services.msc
  
  Pull it up in the Windows search bar and show them around if you’d like.
  
  PsService
  
  Sysinternal Tool
  
  Microsoft Reference
  
  
  
  ###############################END###############################
## ###############################Scheduled Tasks###############################
## 3. Scheduled Tasks


### 3.1 What are Scheduled Tasks?
  Schedule the launch of programs or scripts when defined conditions are met, such as:
  
  Pre-set time (ex. 0900 on Sundays)
  
  When the local machine boots up.
  
  When a user logs on.
  
  Easy way to hide Malware and have itself set to execute at set times.
  
  Separate files can be run from schedule tasks that calls the malware, like a script
  
  Good way to establish Persistence.
  


## 3.2 How to view Scheduled tasks


### 3.2.1 View Scheduled Tasks In PowerShell


  View all properties of the first scheduled task.
  
  Get-ScheduledTask | Select * | select -First 1
  ```
  PS C:\Users\student> Get-ScheduledTask | Select * | select -First 1
  
  
  State                 : Ready
  Actions               : {MSFT_TaskExecAction}
  Author                : Adobe Systems Incorporated
  Date                  :
  Description           : This task keeps your Adobe Reader and Acrobat applications up to date with the latest enhancements and security fixes
  Documentation         :
  Principal             : MSFT_TaskPrincipal2
  SecurityDescriptor    :
  Settings              : MSFT_TaskSettings3
  Source                :
  TaskName              : Adobe Acrobat Update Task
  TaskPath              : \
  Triggers              : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
  URI                   : \Adobe Acrobat Update Task
  Version               :
  PSComputerName        :
  CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
  CimInstanceProperties : {Actions, Author, Date, Description...}
  CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties
  ```
  Unfortunately, the above command doesn’t show you what the scheduled task is actually doing because the Settings are obscured and so are the Triggers. However, this command will show you more:

### 3.2.2 View Scheduled Tasks In Command Prompt
  ```
  schtasks /query /tn "IchBinBosh" /v /fo list
  
  Folder: \
  HostName:                             ADMIN-STATION
  TaskName:                             \IchBinBosh
  Next Run Time:                        6/1/2021 5:02:00 PM
  Status:                               Ready
  Logon Mode:                           Interactive only
  Last Run Time:                        6/1/2021 4:47:00 PM
  Last Result:                          0
  Author:                               ADMIN-STATION\andy.dwyer
  Task To Run:                          powershell.exe -win hidden -encode JABMAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAATABpAHMAdABlAG4AZQByACgANgA2ADYANgApADsAJABMAC4AUwB0AGEAcgB0ACgAKQA7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AcwAgADYAMAA=
  Start In:                             N/A
  Comment:                              N/A
  Scheduled Task State:                 Enabled
  Idle Time:                            Disabled
  Power Management:                     Stop On Battery Mode, No Start On Batteries
  Run As User:                          andy.dwyer
  Delete Task If Not Rescheduled:       Disabled
  Stop Task If Runs X Hours and X Mins: 72:00:00
  Schedule:                             Scheduling data is not available in this format.
  Schedule Type:                        One Time Only, Minute
  Start Time:                           4:02:00 PM
  Start Date:                           6/1/2021
  End Date:                             N/A
  Days:                                 N/A
  Months:                               N/A
  Repeat: Every:                        0 Hour(s), 15 Minute(s)
  Repeat: Until: Time:                  None
  Repeat: Until: Duration:              Disabled
  Repeat: Stop If Still Running:        Disabled
  ```
  Q: What odd command do we see occurring in the output above?
  
  A: Powershell is running encoded strings
  
  Q: How do we decode encoded strings?
  
  A: Cyberchef website
  
  Note: Demo Cyberchef
  


### 3.2.3 View Scheduled Tasks in the GUI
  Windows Default
  
  Task Scheduler
  
  Sysinternal tool
  
  Autoruns.
  
  We’ll go over this more in Sysinternal Tools.
  
  Microsoft Reference



### 3.2.4 Autorun Registry Locations


  Q: What are some Registry keys that can be used for autoruns?
  
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
  


## 3.3 DEMO: Create Task to open listening Port via the PowerShell Process.


### 3.3.1 Create IchBinBosh task
  Opens port listening on port 6666 every 15 minutes.
  
  1. In CMD, run the following.
  
  schtasks /Create /TN IchBinBosh /SC MINUTE /MO 15 /TR "powershell.exe -win hidden -encode JABMAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAATABpAHMAdABlAG4AZQByACgANgA2ADYANgApADsAJABMAC4AUwB0AGEAcgB0ACgAKQA7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AcwAgADYAMAA="
  
  
  ----- OR -----
  
  
  2. *If the script stops working* - run the following commands instead in Powershell to create a listening port:
  
  $command = '$L=New-Object System.Net.Sockets.TcpListener(6666);$L.Start();Start-Sleep -s 60'
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $encodedCommand = [Convert]::ToBase64String($bytes)
  powershell.exe -encodedCommand $encodedCommand


### 3.3.2 Confirm IchBinBosh exists and View Properties


  In Command Prompt
  
  schtasks /query | select-string -pattern IchBinBosh -Context 2,4
  
  
  
  In PowerShell
  
  Get-ScheduledTask | Select * | select-string -pattern IchBinBosh -Context 2,4
  
  
  
  In GUI
  
  Show in either Task Scheduler or AutoRuns.
  
  
  ###############################END###############################
## ###############################Network Connections###############################
## 4. Network Connections


### 4.1 View Network Connections In PowerShell
  
  
  Show all Connections in the "Established" state.
  
  Get-NetTCPConnection -State Established
  ```
  PS C:\Users\andy.dwyer> Get-NetTCPConnection -State Established
  
  LocalAddress        LocalPort RemoteAddress      RemotePort State       AppliedSetting OwningProcess
  ------------        --------- -------------      ---------- -----       -------------- -------------
  10.23.0.2           49701     52.177.165.30      443        Established Internet       2988
  10.23.0.2           22        10.250.0.15        59038      Established Internet       2944
  ```

### 4.2 View Network Connections in Command Prompt
  Show netstat help and point out the following:
  
  netstat /?
  ```
  -a   Displays all connections and listening ports
  -n   Displays addresses and port numbers in numerical form
  -o   Displays the owning process ID (PID) associated with each connection
  -b   Displays the executable involved in creating each connection (must have admin rights)
  ```
  
  Displays all TCP/UDP connections with ports in numerical form with PID and executable associated to the connections
  
  netstat -anob | more
  ```
  andy.dwyer@ADMIN-STATION C:\Users\andy.dwyer>netstat -anob | more
  
  Active Connections
  
    Proto  Local Address          Foreign Address        State           PID
    TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2944
   [sshd.exe]
    TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       832
    RpcSs
   [svchost.exe]
    TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
   Can not obtain ownership information
    TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       304
    TermService
   [svchost.exe]
    TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       4456
    CDPSvc
  
  -- More --
  ```

### 4.3 View Network Connections in the GUI

  
  TCPView
  
  We will go over this in Sysinternal tools
  
  If you want to dig deeper: Microsoft Reference
  ###############################END###############################

## ###############################Identifying Abnormalities###############################
## 5. Identifying Abnormalities/Suspicious Activity
  
  
  Q: What are some Abnormal things we could see in a process list?
  
  Misspelling of process names and descriptions.
  
  Ex. scvhost instead of svchost
  
  Directory the process is running out of.
  Q: Which directory are windows executables typically run out of?
  
  System Processes run from C:\Windows\System32
  
  Third party processes will run elsewhere.
  
  Ex. Chrome runs from C:\Program Files
  
  Processes that have non-standard listening ports open or ports with SYN/SENT.
  
  Like HTTP being used on any port other than 80. (ex. HTTP over port 808 or 880)
  
  Multiple processes with the same name that should be unique such as LSASS, SMSS
  
  System process with a high PID.
  
  Handles or DLLs a process is using.
  
  Dig Deeper into DLLs:
  
  Microsoft Compromised DLLs
  
  DLL Hijacking
  
  Q: Where’s Waldo??? Using what we’ve learned so far, what stands out about this Task List?
  ```
  System Idle Process              0 Services       0          8 K Unknown         NT AUTHORITY\SYSTEM        368:23:24 N/A
  System                           4 Services       0         24 K Unknown         N/A                        0:13:27 N/A
  Registry                        88 Services       0     46,944 K Unknown         N/A                        0:00:11 N/A
  smss.exe                       288 Services       0        344 K Unknown         N/A                        0:00:00 N/A
  csrss.exe                      392 Services       0      1,768 K Unknown         N/A                        0:00:06 N/A
  wininit.exe                    464 Services       0        876 K Unknown         N/A                        0:00:00 N/A
  csrss.exe                      476 Console        1      1,872 K Running         N/A                        0:00:16 N/A
  winlogon.exe                   560 Console        1      3,772 K Unknown         N/A                        0:00:00 N/A
  services.exe                   576 Services       0      8,756 K Unknown         N/A                        0:02:28 N/A
  lsass.exe                      604 Services       0     11,980 K Unknown         N/A                        0:14:15 N/A
  svchost.exe                    716 Services       0        908 K Unknown         N/A                        0:00:00 N/A
  fontdrvhost.exe                724 Console        1      2,572 K Unknown         N/A                        0:00:01 N/A
  fontdrvhost.exe                736 Services       0        680 K Unknown         N/A                        0:00:00 N/A
  svchost.exe                    800 Services       0     20,396 K Unknown         N/A                        0:04:37 N/A
  svchost.exe                    848 Services       0     10,804 K Unknown         N/A                        0:01:42 N/A
  svchost.exe                    896 Services       0      4,144 K Unknown         N/A                        0:01:05 N/A
  dwm.exe                        992 Console
  firefox.exe                   2396 Console        1     53,008 K Running         ARMY\andy.dwyer         0:00:01 OleMainThreadWndName
  cmd.exe                       4372 Console        1      3,132 K Running         ARMY\andy.dwyer         0:00:00 Command Prompt - tasklist  /v
  conhost.exe                   4128 Console        1     19,536 K Running         ARMY\andy.dwyer         0:00:18 N/A
  firefox.exe                   6952 Console        1     36,340 K Not Responding  ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
  dllhost.exe                   6324 Console        1     16,084 K Running         ARMY\andy.dwyer         0:00:00 N/A
  cmd.exe                       5788 Console        1      3,204 K Running         ARMY\andy.dwyer         0:00:00 C:\windows\system32\cmd.exe
  conhost.exe                   6240 Console        1     15,956 K Running         ARMY\andy.dwyer         0:00:00 N/A
  SecHealthUI.exe               1828 Console        1     54,808 K Running         ARMY\andy.dwyer         0:00:03 CicMarshalWnd
  dllhost.exe                   7316 Console        1      9,532 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
  bad.exe                       3648 Services       0      6,680 K Unknown         N/A                        0:00:00 N/A
  conhost.exe                   8604 Console        1     17,832 K Running         ARMY\andy.dwyer         0:00:00 N/A
  smartscreen.exe               5916 Console        1     20,268 K Unknown         ARMY\andy.dwyer         0:00:00 N/A
  smss.exe                      8972 Console        1     14,412 K Running         ARMY\andy.dwyer         0:00:00 Installer Language
  svchost.exe                   8976 Services       0      5,632 K Unknown         N/A                        0:00:00 N/A
  WmiPrvSE.exe                  9212 Services       0      8,824 K Unknown         N/A                        0:00:00 N/A
  reqedit.exe                   8760 Console        1     12,556 K Running         ARMY\andy.dwyer         0:00:00 PuTTY Configuration
  tasklist.exe                  8308 Console
  SystemSettingsBroker.exe      5600 Console        1      2,536 K Unknown         ARMY\andy.dwyer         0:00:00 N/A
  explorer.exe                  5416 Console        1     19,276 K Running         ARMY\andy.dwyer         0:00:30 N/A
  MsMpEng.exe                   6616 Services       0     88,688 K Unknown         N/A                        0:09:55 N/A
  regedit.exe                   2624 Console        1      3,200 K Running         ARMY\andy.dwyer         0:00:00 Registry Editor
  mmc.exe                       3352 Console        1      5,380 K Running         ARMY\andy.dwyer         0:00:02 OLEChannelWnd
  svchost.exe                   4200 Services       0      8,716 K Unknown         N/A                        0:00:01 N/A
  dllhost.exe                   4868 Console        1      6,236 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
  powershell_ise.exe            4940 Console        1    406,740 K Running         ARMY\andy.dwyer         0:01:20 Windows PowerShell ISE
  taskhostw.exe                 5864 Console        1      7,524 K Running         ARMY\andy.dwyer         0:00:00 Task Host Window
  MicrosoftEdge.exe             6928 Console        1        712 K Running         ARMY\andy.dwyer         0:00:00 Microsoft Edge
  browser_broker.exe            1108 Console        1        972 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
  svchost.exe
  ```
  A: High PID duplicate, unfamiliar process name, and misspelling.
  
  Two smss.exe, one with a high PID of 8972
  
  bad.exe
  
  reqedit.exe
  
  ###############################END###############################
# User Account Control
## ###############################UAC###############################
## 1.1 What is UAC and what does it do
  Most Windows installers create a single user account, which is an administrative account, when setting up Windows and then move on. Because of this, most users perform tasks on their Windows machine as an admin, and that allows malware to run as admin. UAC was created to protect users from themselves.
  
  Stands for User Account Control
  UAC limits the privileges of user run applications, even when run as Administrator, to prevent the modification of system files, resources, or settings.
  
  Requesting elevated privileges requires explicit, interactive acknowledgement from the user. [6]
  
  If the user is in the local administrators group, they can click through the prompt, or if not in the Administrator group, can enter the administrator password to complete the action
  
  Registry key is located at "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  
  UAC is the Windows equivalent to Linux sudo


## 1.2 What do UAC prompts look like
  See UAC Slide 9 for images Public Antora Page
  Demo: Attempt to install Immunity Debugger from a non-admin cmd shell. Point out that UAC prompts for action
  
  Immunity Debugger Download
  
  Multiple color-coded consent prompts
  Red - Application or publisher blocked by group policy
  
  Blue & gold - Administrative application
  
  Blue - Trusted and Authenticode signed application
  
  Yellow - Unsigned or signed but not trusted application
  
  960
  


## 1.3 How does UAC know how to act
  When an application is run, UAC checks that file’s manifest for instructions
  
  What is a file Manifest?
  
  A manifest file on Windows holds Metadata and tells Windows how the file should be executed.
  
  There are three types of execution levels in a file’s manifest.
  asInvoker - The application will run with the same permissions as the process that started it. The application can be elevated to a higher permission level by selecting Run as Administrator.
  
  Ex: C:\Windows\System32\cmd.exe
  
  requireAdministrator - The application will run with administrator permissions. The user who starts the application must be a member of the Administrators group. If the opening process is not running with administrative permissions, the system will prompt for credentials.
  
  highestAvailable - The application will run with the highest permission level that it can. If the user who starts the application is a member of the Administrators group, this option is the same as requireAdministrator. If the highest available permission level is higher than the level of the opening process, the system will prompt for credentials.
  
  Ex: C:\Windows\regedit.exe

### 1.3.1 Autoelevate setting
  Some Windows executables can "auto elevate" without a prompt.
  
  Files that have "auto elevate" in their permissions will not prompt UAC
  


## 1.4 View file manifest settings
  The Sysinternals Tool sigcheck will allow the viewing of these settings.
  
  Map the Sysinternals Command in Powershell
  ```
  PS C:\Users\student> net use * http://live.sysinternals.com
  PS C:\Users\student> z:
  ```
  View the autoelevate setting of slui
  ```
  PS Z:\> ./sigcheck -m C:\Windows\System32\slui.exe
  ```
  View the highest available setting of regedit
  ```
  PS Z:\> ./sigcheck -m C:\windows\regedit.exe
  ```
  How to locate Windows executables that have autoelevate in the manifest
  ```
  PS Z:\> ./strings –s c:\windows\system32\*.exe | findstr /i autoelevate
  ```
## 1.5 DEMO: Bypass UAC with fodhelper.exe
  What is fodhelper?
  
  Fodhelper - Introduced in Windows 10 to manage optional features like region-specific keyboard settings. Fodhelper.exe is located in the C:\Windows\System32 folder
  
  Explain how the UAC Bypass fodhelper exploit was found.
  
  Researcher used Procmon to find the registry keys being called that do not exist.
  
  Show the registry hives on screen and ask the students which hive can be edited as a non-admin user and ask why this is important to us? (Non-admin users can edit the HKCU keys and manipulate the behavior of the system)
  
  HKCU:\Software\Classes\ms-settings\shell\open\command
  
  Demo using Procmon to find registry keys called by autoelevate applications
  Open Procmon
  
  Run fodhelper.exe
  
  Stop Capture
  
  Create Filter ProcessName is fodhelper.exe
  
  Create Filter Operation is RegOpenKey Action Include
  
  Look for Registry Keys HKCU\software\classes
  
  Look fro Registry Keys HKCU\ms-settings\shell\open\command
  
  Explain the Registry Key HKCU is writable by the user and that ms-settings\shell\open\command doesn’t exist so we can exploit this key to perform what behavior we want
  What does this key allow us to do?
  
  PS C:\Users\Student> HKCU:\Software\Classes\ms-settings\shell\open\command
  Enables us to provide to the program additional instructions on what to do when the program opens.
  
  What does the DelegateExecute string value do?
  
  Tells the program to execute what is in the default value of the registry key.
  
  Demo via GUI so students can do Activity via PowerShell and demonstrate command-line knowledge.
  
  Look at autoElevate & requestedExecutionLevel
  PS C:\Users\Student> ./sigcheck -m C:\windows\system32\fodhelper.exe
  Open the registry editor
  PS C:\Users\Student> regedit.exe
  Create the key
  Right click on HKCU:\Software\Classes and select New > Key
  
  Name it ms-settings
  
  Then add New > Key shell
  
  Then add New > Key open
  
  Then add New > Key command
  
  Create the String Value
  Right click in the whitespace on the right side of pane Create New > String Value DelegateExecute
  
  Right Click on (Default) String value
  Add C:\windows\system32\cmd.exe
  
  From command-line execute
  C:\windows\system32\fodhelper.exe
  NOTE:A new window will pop up with Administrator privileges
  
  Activity: UAC Bypass
  
  
  ###############################END###############################
## Windows SysInternals FG
## ###############################SysInternals###############################
## 1. Sysinternals Introduction
Windows Sysinternals is a collection of advanced system utilities that were established to help users manage,troubleshhot and diagnose Windows systems and applications. The sysinternals tools are housed on the website https://live.sysinternals.com/ to be readily available to run directly from the site. We will have the tools downloaded on our box(es) for ease of use.

These are a few commands/instructions to have the tools on your local Windows box.
```
PS C:\windows\system32> net use * http://live.sysinternals.com 
Drive Z: is now connected to http://live.sysinternals.com.

The command completed successfully.
```
The 'net use' command can be used to create a connection to the Live Sysinternals website. (can be persistent with parameter set)

```
PS C:\windows\system32> New-PSDrive -Name "SysInt" -PSProvider FileSystem -Root "\\live.sysinternals.com\Tools" 

Name           Used (GB)     Free (GB) Provider      Root                                                    CurrentLocation
----           ---------     --------- --------      ----                                                    ---------------
SysInt                                 FileSystem    \\live.sysinternals.com\Tools
```
'New-PSDrive' is a PowerShell command used to create a temporary or persistent connection to the Live Sysinternals website.
```
PS C:\Users\andy.dwyer\Desktop> $wc = new-object System.Net.WebClient 

PS C:\Users\andy.dwyer\Desktop> $wc.DownloadFile("https://download.sysinternals.com/files/SysinternalsSuite.zip",
"$pwd\SysinternalsSuite.zip") 

PS C:\Users\andy.dwyer\Desktop> Expand-Archive SysinternalsSuite.zip 
```
Location may be different on your box The webclient provides common methods for sending and receiving data to/from a URI (Uniform Resource Identifier)
Download the .zip file from the website
Unzip the file, creates a folder on the desktop


## 2. Procmon
Using PROCMON to monitor the Windows Boot Process



Q: What is Process Monitor?

Process Monitor is an advanced monitoring tool for Windows that shows real-time File System, Registry and Process/Thread activity. It combines the features of two legacy Sysinternals utilities, Filemon and Regmon.

It also has an option to Log at boot and we are going to go over a demo and analyze the Windows Boot Process.



Q: What does Procmon capture?

Registry - Anything from creating, reading, deleting, or querying keys

File System - File creation, writing, deleting, etc and this includes both local and network drives

Network - This only shows source and destination TCP/UDP traffic

Process - These events are for processes and threads where a process starts, a thread starts or exits, etc. Probably better in ProcExp

Profiling - Checks the amount of processor time and memory use of each process



Tabs

File - Has the save feature which allows exporting to CSV and CML as well as the native PML format, backup up files in virtual memory or in previous PMLs, import and export your Procmon configurations, and turn on and off Capture Events.

Edit - Has features for ease of access: Copy, Find, Find highlight, Find Bookmark, an Auto-scroll, and Clear Display.

Event - Options for the currently selected event as if you right clicked. You can view Properties, Stack, Toggle Bookmark, Jump To, Search Online, Filter Include/Exclude, and Highlight options.

Filter - For advanced search options it has Enabled Advanced Output, Filter, Reset Filter, Load (saved) Filters, Save Filters, Organize (saved) Filters, Drop Filtered Events (will not capture events that you are filtering) and highlight filters (or things that you have highlighted).

Tools - Summary outputs and information cheat sheets. System Details, Process Tree, Process Activity Summary, File Summary, Registry Summary, Stack Summary, Network Summary, Cross Reference Summary (paths that are written and read between differing processes)

Options - Configuration of the GUI, Has Always on Top, Font, Highlight Colors, Configure Symbols (for the stack tab), Select Columns, History Depth (how many events it will hold), Profiling Events (if you want it changed to milliseconds), Enable Boot Logging, Show Resolved Network Addresses, Hex Offsets and Length, Hex Process and Thread IDs.

Help - Help Manual, Command Line Options, About



Default Columns

Time - Shows the exact time the event occurred

Process Name - The name of the process that generated the event. It doesn’t show the full path by default, but if you hover over it then the full path is displayed.

PID - Process ID

Operation - Name of the operation being logged, with corresponding icon (registry, file, network, process)

Path - The path of the event that was being touched (the affected) and not the event of the process (the instigator)

Result - This shows the result of the operation in codes like SUCCESS or ACCESS DENIED

Detail - additional information for troubleshooting



Demo for Using PPROCMON to Monitor the Windows Boot Process


Looking at Processes on Boot



Start up the Admin-Station Host and log in as Army\andy.dwyer and open REGEDIT from their Search Bar and Go to HKLM\Software\Microsoft\Windows\CurrentVersion\Run.

Create a New String Value Called RunME and modify it with c:\windows\notepad.exe.

`Go to C:\SysinternalsSuite <Location may be different>

Double-Click Procmon.exe. Accept Eula. Go to the File Tab and uncheck Capture Events. Go to the Options tab and Click on Enable Boot Logging.

This will enable logging on System Boot. Select Every Second. Restart the System.

Once the System restarts, open and minimize notepad and then navigate to and double-click Procmon.exe to start it. It will ask to Save the log file.

Save the log file to the Desktop. Once all of the Bootlog.pml files are saved, return to Procmon.

If the .pml file does not automatically load, go to the File tab and click on OPEN and browse to our Desktop and select the ".pml" file to load.

Click on the Tools tab and click on Process Tree.

Explain the Process Tree and how it’s formed (hierarchically) and why things are grayed out (They are no longer running).

Discuss why the description and path are important in identifying malware and also the digital signature, the process owner, and the command line syntax and what that could indicate as abnormal. If there is no description it’s a good indicator of malware

Processes starting from odd locations

Digital signitures are a good indicator of malware if it’s missing but they can be falsified

This is where we would look for our malicious boot and pre-windows start malware. We could also look for system diagnostic things such as any programs that are taking to long to load or hang that could indicate malware.



Find notepad.exe and have a discussion about things to look for like programs that shouldn’t run at start or unknown programs and services. Continue onto the next part.



Learning PROCMON Filtering



Once notepad.exe is found, right-click and select Go to Event to show the functionality.



Right-Click and go over the list of options focusing on the Include and Exclude for the filtering and the highlight option and the properties.



Right-Click and select Include and select PID and Discuss the results (Everything is blown away except the notepad).

Select the Filter tab and select Filter…​ and explain the "Include" and "Exclude" at the bottom.

Remove the "PID is ???? (whatever the PID is for notepad.exe) include" and add an entry for "Process Name is notepad.exe" then include then remove it and add the same one but "Process Name is notepad.exe then exclude".

Exit the Filter and do a Ctrl-F and search for notepad.exe. It is gone.



Go back to the Filter Tab and remove the "Process Name in notepad.exe then exclude" and exit the Filter and do a Ctrl-F and search for notepad.exe, you should see it now.

Discuss some other filtering techniques. Discuss the advantages and disadvantages and what use they believe they can get out of the tool.



Explain any further questions or gaps about filtering or analyzing processes at boot. END DEMO.


## 3. Autoruns
Analyze the Windows startup environment using AUTORUNS

Q: What is AUTORUNS?
Autoruns shows applications automatically started on during system boot or login as well as the Registry and file system locations for auto-start configurations. Examples: AppInit, Winlogon, Scheduled Tasks, Services, Logon, etc.

The External Interface
Highlighted items that are colors notate special meanings

Pink - Means no publisher information was found or the digital signature doesn’t exist or match.
Green - Used when comparing previous set of Autorun data to indicate an item wasn’t there last time.
Yellow - The startup entry is there, but the file or job it points to doesn’t exist anymore.
Highlight a task - Right-Clicking or Entry Tab - Allows you to Jump to where the entry resides in the File System, Search Online, Open in Process Explorer, Go to it’s Registry Key or Task Scheduler.
User Tab - Allows you to analyze different user accounts autoruns (must be administrator to view other accounts).
Options Tab- Allows you to hide certain entries and also allows font changes and scan options. The Scan Option allows you to choose to scan Per-User Locations, Verify code signatures, and Check Virustotal.com.
File Tab - Allows you to Analyze Offline systems and compare files from other systems or yours, Very handy.



Q: Where are some of the places that AUTORUNS look?
The Internal Tabs

Everything - Shows all of the outputs from the other tabs together on this one tab. One stop Shop, Not as messy as you might think.
Explorer - This tab list add-on components that load themselves into Windows Explorer. Mostly context menu add-ons and the sort.
Logon - Checks the normal locations for things to be automatically loaded, including registry keys Run and RunOnce keys, the Start Menu, up to 43 locations.
Internet Explorer - This tab list all of the browser extensions, toolbars, browser helper objects that are used by malware to either spy or show you ads.
Scheduled Tasks - This tab shows Tasks that are scheduled. Malware uses it to install, reinstall, and do all types of nefarious things with this.
Services - This tab list auto-start services. Malware sometimes hides itself as a service by creating it’s own service that helps make sure that other malware processes are running.
Drivers - .Sys files. Used to call a bunch of system and svchost executables. Malware can hide in here, look at the path.
Codecs - Libraries of code that handle media playback for videos and audio. Used by malware to automatically start on systems.
Boot Execute - Things that can’t happen when windows is loaded like a hard drive check.
Image Hijacks - Will let you know if a program has been replaced with another, ex: when you run notepad.exe it runs calc.exe instead.
AppInit - Settings where RequireSignedAppInit_DLLs key is set to 0 and any DLLs that were loaded with that setting will be showed.
KnownDLLs - Listed to make sure you can verify and that they are all verified and published DLLs.
Winlogon - Shows DLLs that register for Winlogon notification of logon events.
Winsock Providers - Networking, shows registered winsock providers. Malware often installs itself as these because there are few tools that can remove them.
Print Monitors - Third party printer applications, Drivers and Dlls that load into the print spooling service. Malware uses this support to autostart itself.
LSA Providers - Shows registered LSA authentication notification and security packages.
Network Providers - Third party network providers.
WMI - Views WMI related persistence (Ex: If a powershell script was using a get-wmiobject, it would show up).
Office - Shows Office related material. If excel scripts or power points were infected and opening at start they would show here.



Demo for Analyzing the Startup Environment with Autoruns

Have students log into their Admin-Station as Army/andy.dwyer.

Have students go to C:\SysinternalsSuite <Location may be different> and open up Autoruns.exe go to the Options tab and make sure that Hide Windows Entries is unchecked.



The entry created from the PROCMON demo "RunME Notepad (Verified) c:\windows\notepad.exe" under the HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run section in the Everything tab and the Logon tab should be visible.

Side note: Unchecking the Hide Windows Entries can create a lot of unneeded clutter. Go to the Options tab and check Hide Windows Entries.

Notate that anything (Verified) Microsoft Windows as a Publisher is removed to the class.



Discuss what we are looking at and what we are looking for using our notepad.exe as an example such things as registry keys, path, names, digital signatures, etc.

Click on the Logon tab, it gives a chunk of information that the Everything tab gave us but gives us only where autoruns checks for "normal" autorun locations. Discuss the locations that malware might hide. (ex: Run, RunOnce, etc)

Click on the Scheduled tasks tab. Discuss what ways malware might use schedule tasks and what ways we could mitigate it. (ex: create schedule task to install itself, to set a callback at a certain time/ group policy)

Click on the Services tab. Discuss ways that malware can take advantage of services and ways to mitigate it. (ex: create a service that auto starts at boot that runs a malware process, group policy)

Discuss the advantages and disadvantages if any and what use do they believe if any they can get out of the tool.

Clarify any Questions or gaps in learning. END DEMO





## 4. Procexp
Analyze Windows running processes using PROCEXP



Q: What is Process Explorer
Process Explorer is a task manager and system monitor which collects information on running processes with such features as Hierarchical view of processes, live CPU activity, ability to kill and suspend processes, display DLLs loaded, create process dumps, display handles and much more.

There will be a lot of similarities in the options and results that both Task Manager and Process Explorer give.

Process Explorer should be run as administrator to get it’s full usage.

Process Explorer has a powerful search capability that can show processes and their respective DLLs and handles.



Default Interface Columns

Process - Processes are listed according to their parent child relationship. Processes listed as a sub row are child processes of the upper process.

CPU - Shows general CPU usage percentage of this process.

Private Bytes - Shows the size of memory only used by this process and not shared with other processes and DLL’s.

PID - Shows the process identifier given by the operating system and used to easily identify the process.

Description - Shows process information (what it is).

Company Name - Shows the application publisher company.



Interface Tabs

File - Allows you to run applications as if from the "Run window" and if you are administrator you can run as a limited user (lower credentials), save functions, and the ability to shutdown, restart, lock, etc the system.

Options - Allows you to the option to run Process Explorer at logon, the ability the verify Image (digital) signatures, check virus total, to replace task manager with process explorer, and configure graphical options such as colors/fonts/thread symbols/tray icons/highlight duration.

View - Shows system information (resource monitor in task manager), manipulate how you view the processes such as speed/refresh rate, allows column manipulation such as adding and removing columns.

Process - Is for individual clicked on processes. It shows windows which allows selected processes to be brought to front or maximized or minimized, set affinity which allocated CPU usage, sets priority for it’s placement in the pool, can kill/kill tree/restart/suspend, create a process dump, search the selected process on virustotal, the select the process’s properties and search it online.

Find - Used for finding Handles and DLLs.

Handle - If split window is selected this will appear. Select a handle on the lower panel and you are able to close the handle or select it’s properties. It is interchangeable with a DLL tab depending on what you select to look at in the lower panel. The DLL tab shows properties, search online, and check virus total.

Users - Used for controlling users on host if you are admin. Can connect, disconnect, logoff, remote control, send messages, and view some brief properties about the user’s status.

Help - Help manual and an about



Colors (Selected by default)

Green - New Objects - Briefly flashes "Green" before changing into one of the 9 other colors.

Red - Deleted Objects - Dead.

Lavender - Own Processes - Processes owned by the current logged in user.

Salmon - Services

Gray - Suspended Processes

Purple - Packed Images -Processes might contain compressed code hidden inside them. Malware uses it because it obfuscates the contents of the file.

Cyan - Immersive Process - Windows Store App related, Uses Windows 8+ new APIs



Demo on Analyzing Windows Running Processes with Process Explorer


Have students open up their Admin-Station and log in as Army\andy.dwyer.



Once logged on they will need to go to C:\SysinternalsSuite <Location may be different> and Right-Click on Procexp.exe and select Run as Administrator and Maximize it.

Press "spacebar" to pause ProcExp from refreshing any further so it will be easier to continue (hitting spacebar again will un-pause it).



Find notepad.exe (If the process tree is not already in Tree form then go to the View tab and click on Process Tree) and discuss the lay out and columns reinforcing the FG.

Once notepad.exe is found, double-click it. The data returned is PATH, CMDLINE, AUTOSTART, TCP/IP, STRINGS, and much more. Discuss why this is important.



Close the window. Go to the Options tab, click on VirusTotal.com and click on Check VirusTotal.com and discuss VirusTotal and it’s effects. Agree to the Terms of service to continue.

A new column populates on the far right called VirusTotal and everything now has a score (or almost everything).



Click on the Options" tab again and click Verify Image Signatures to check that everything has verified publisher digital signatures (discuss why this is important).

The Verified Signer column and Company name are now listed (what are we looking for?).



Click on View and click on Select Columns, Select Auto Start Location and retouch on autoruns briefly in the Process Image tab and Receives and Sends from the Process Network tab.

Explain what we are looking for from these Three tabs are autorun locations and network traffic.



Between the View and Process tabs there is a Show Lower Pane button, click that button and it will bring up a list of Handles or DLLs, we want Handles (Handles in Windows refer to an integer value that is used to uniquely identify a resource in memory like a window, an open file, a process, etc).

To change between the two, you would click on the View tab and click on Lower Pane View and there are two options DLLs and Handles.

We can see any Files, Processes, Registry keys associated with our selected process and discuss some of the things we might be looking for.



Switch to DLLs by repeating the previous step. Discuss what we are looking for and why we are looking at DLLs. Unsigned, not in C:\Windows\System32, No description, weird names, anything that looks abnormal.



Double click on notepad.exe, click on the Image tab and to click the Explore option for Path information.

The first thing to look for is if there are any DLLs in the folder that are not listed in Process Explorer. Discuss rogue DLLs and files.

Malware sometimes has associated DLLs that come packaged with it or is itself a DLL that plugs into legitimate processes or other DLLs, Discuss ways Malware injects.

Look at time stamps at the files in the folder and at the files themselves, but at this point we would start to move onto other tools and methods.



Discuss the advantages and disadvantages if any and what use do they believe if any they can get out of the tool.

## 5. TCPView
Analyze Windows network connections using TCPVIEW

Q: What is TCPVIEW?
TCPView is a Windows program that will show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections.[1]

It’s a more informative Graphical (GUI) representation of the NETSTAT command

Shows network connections

Open TCPView

If you see any Red Rows

That indicates when a network connection terminates

If you see any Green Rows

That indicates when a connection is made

If the colors are disappearing to quickly, you can modify the Update Speed

View → Update Speed → 5 seconds

Keeps colors longer to see what is stopping or starting

Column Sorting

Allows you to see lines grouped by State or Process

Q: What are some known malicious ports?

1337 Leet Port = 1337 means "elite" in hacker/cracker spelling (1=L, 3=E, 7=T, "LEET"="ELITE"). Because of the reference, it may be used by some backdoors.

31337 Eleet port

4444 Metasploit default listener port

To kill Processes

Right click → End Process


## 6. PsExec
Analyze Windows privileges' using PsExec

Q: What is PsExec?
light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software.

Switches
-s Run as System account
-i interacts with the desktop
-c Copy the specified program to the remote system for execution.

Demo regedit.exe
Open as regular user
Go to HKLM\SAM\SAM
Can’t go deeper

From an admin cmd shell
```
psexec -i -s regedit.exe
```
Can view down to HKLM\SAM\SAM\Domains\Accounts\Users

This function will not work in our current environment but talk about the ability of running the tool across a network. Also, demo a cmd shell back from another system as System
```
PsExec -s \\file-server cmd.exe
whoami
nt authority\system
```

## 7. PsLoggedon
Analyze Windows logons using PsLoggedon

Q: What is PsLoggedon used for?
It can list users that are logged on currently to a system

Q: How can I view the options for PsLoggedon?
psloggedon.exe /? -accepteula

Q: What does the -accepteula do?
Prevents a pop up to accept the End User License Agreement

Show output from running PsLoggedon
```
PS C:\SysinternalsSuite> .\PsLoggedon.exe

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             ADMIN-STATION\cloudbase-init
     5/10/2021 2:02:19 PM       ADMIN-STATION\student
     5/10/2021 2:07:48 PM       ADMIN-STATION\andy.dwyer

No one is logged on via resource shares.
```
The following function will not work in our current environment but talk about the ability of pulling logon information from remote boxes. Set up a Server List for this demo
```
Write-Output File-Server > "$env:HOMEPATH\Desktop\ServerList.txt"
Write-Output Domain-Controll >> "$env:HOMEPATH\Desktop\ServerList.txt"
Write-Output $env:Computername >> "$env:HOMEPATH\Desktop\ServerList.txt"
```
Run PsLoggedon on all the systems in the list
```
Foreach ($system in (gc "$env:HOMEPATH\Desktop\ServerList.txt") ) {.\PsLoggedon.exe \\$system -nobanner}
```

Q: How could this tool be used in Cyber?
Gather a list of every user currently logged on a system
Possibly find for a malicious actor in the network
Look for logged on users who are logging in outside of normal hours


## 8. LogonSessions
  Analyze Windows session using LogonSessions
  
  While Psloggedon shows who is logged on and what time he/she logged on, loggonsessions shows how that user logged on.

  
  Logon type
  Logon title
  Description
  2
  Interactive
  A user logged on to this computer.
  3
  Network
  A user or computer logged on to this computer from the network.
  4
  Batch
  Batch logon type is used by batch servers, where processes may be executing on behalf of a user without their direct intervention.
  5
  Service
  A service was started by the Service Control Manager.
  7
  Unlock
  This workstation was unlocked.
  8
  NetworkCleartext
  A user logged on to this computer from the network. The user’s password was passed to the authentication package in its un-hashed form. The built-in authentication packages all hash credentials before sending them across the network. The credentials do not traverse the network in plaintext (also called cleartext).
  9
  NewCredentials
  A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.
  10
  RemoteInteractive
  A user logged on to this computer remotely using Terminal Services or Remote Desktop.
  11
  CachedInteractive
  A user logged on to this computer with network credentials that were stored locally on the computer. The domain controller was not contacted to verify the credentials.[2]
  
  Demo
  
  List sessions and processes running under each user
  ```
  PS C:\SysinternalsSuite> .\logonsessions.exe -p
  
  LogonSessions v1.41 - Lists logon session information
  Copyright (C) 2004-2020 Mark Russinovich
  Sysinternals - www.sysinternals.com
  
  _Output_Truncated_
  [14] Logon session 00000000:0010d7b1:
      User name:    ADMIN-STATION\andy.dwyer
      Auth package: NTLM
      Logon type:   RemoteInteractive
      Session:      2
      Sid:          S-1-5-21-2352402639-359936040-2003525269-1005
      Logon time:   5/10/2021 2:07:07 PM
      Logon server: ADMIN-STATION
      DNS Domain:
      UPN:
       7580: powershell_ise.exe
       6992: conhost.exe
      10188: powershell.exe
       7628: conhost.exe
      10156: cmd.exe
       6692: conhost.exe
       5856: notepad.exe
       8872: cmd.exe
       9360: conhost.exe
       1808: ssh.exe
       4388: logonsessions.exe
  _Output_Truncated_
  ```
  Q: Why would you ever need to see what processes a logged on user was running?
  
  A: If you are trying to locate a malicious user or if you are trying to identify processes a piece of malware was running
  

## 9. PsList
  Analyze Windows processes using PsList on local or remote systems
  
  Q: What is PsList used for?
  
  Another command line tool for gathering process information
  
  Allows you to refresh the tool for a specified period of time
  
  Q: How do you get the help file for PsList?
  ```
  pslist /?
  ```
  Q: How can I get a process list that updates every 10 seconds for 100 seconds?
  ```
  pslist -s 100 -r 10
  ```
  -s [n] run for this many seconds
  
  -r n refresh every n seconds
  
  Q: Why is this important to Cyber?
  
  To see if a new admin logs in. Can’t refresh this by default with tasklist or get-process
  
  To see when a new process starts that could jeopardize your mission
  
  Q: How can this be run on a remote system?
  ```
  pslist \\file-server 
  ```
  Will not work in current environment
  
  Show the output from running the tool
  ```
  PS C:\SysinternalsSuite> pslist
  
  PsList v1.4 - Process information lister
  Copyright (C) 2000-2016 Mark Russinovich
  Sysinternals - www.sysinternals.com
  
  Process information for ADMIN-STATION:
  
  Name                Pid Pri Thd  Hnd   Priv        CPU Time    Elapsed Time
  Idle                  0   0   4    0     52   115:19:16.046    28:59:33.270
  System                4   8 101 4115    188     0:01:21.687    28:59:33.270
  Registry            104   8   4    0    360     0:00:03.484    28:59:40.221
  smss                324  11   2   59    500     0:00:00.171    28:59:33.264
  csrss               432  13  12  539   1772     0:00:00.921    28:59:09.665
  wininit             508  13   1  168   1356     0:00:00.078    28:59:09.146
  csrss               516  13  10  388   1640     0:00:00.656    28:59:09.139
  winlogon            604  13   3  281   2420     0:00:00.125    28:59:09.097
  services            652   9   5  669   4872     0:00:14.375    28:59:09.056
  lsass               664   9   7 1700   8080     0:00:09.531    28:59:08.760
  _Output_Truncated_
  ```


## 10. PsInfo
  Analyze Windows system information using PsInfo
  
  Gathers key system information from both local and remote systems.
  
  The following function will not work in our current environment but talk about the ability of pulling PsInfo information from remote boxes. Set up a Server List for this demo
  ```
  Write-Output File-Server > "$env:HOMEPATH\Desktop\ServerList.txt"
  Write-Output Domain-Controll >> "$env:HOMEPATH\Desktop\ServerList.txt"
  Write-Output $env:Computername >> "$env:HOMEPATH\Desktop\ServerList.txt"
  ```
  Run PsInfo on all the systems in the list
  ```
  Foreach ($system in (gc "$env:HOMEPATH\Desktop\ServerList.txt") ) {.\Psinfo.exe -hs -nobanner \\$system | out-file $env:homepath\Desktop\psinfo.txt -append}
  ```
  
  Show the output from running the tool
  
  Talk about the importance of identifying the following system information and how it can be used to associate possible exploits by either the network owner or an adversary.
  ```
  PS C:\SysinternalsSuite> psinfo
  
  PsInfo v1.78 - Local and remote system information viewer
  Copyright (C) 2001-2016 Mark Russinovich
  Sysinternals - www.sysinternals.com
  
  System information for \\ADMIN-STATION:
  Uptime:                    1 day 5 hours 9 minutes 14 seconds
  Kernel version:            Windows 10 Enterprise, Multiprocessor Free
  Product type:              Professional
  Product version:           6.3
  Service pack:              0
  Kernel build number:       17763
  Registered organization:
  Registered owner:
  IE version:                9.0000
  System root:               C:\windows
  Processors:                4
  Processor speed:           2.2 GHz
  Processor type:            AMD EPYC-Rome Processor
  Physical memory:           2 MB
  Video driver:              Microsoft Basic Display Adapter
  ```

11. Strings
  Analyze Windows files using Strings
  
  Switches
  
  -a ASCII
  
  Must provide literal file path
  ```
  strings -a C:\users\andy.dwyer\Desktop\<doc>.txt
  ```

## 12. Handle
  Analyze Windows handles process using Handle
  
  Q: What is a handle?
  
  Handles are data structures that represent open instances of basic operating system objects applications interact with, such as files, registry keys, synchronization primitives, and shared memory.
  
  Applications can’t access objects directly, must obtain a handle
  
  Handles for each process are tracked in an internal table known as the Object Manager
  
  Handles allow a common interface to objects, regardless of underlying changes to the object
  
  Handles allow Windows to track ACLs for objects during handle creation time
  
  DEMO: Killing a handle using Sysinternal handle.exe
  Step one: Open Powershell.exe and start-transcript
  ```
  PS C:\windows\system32> Start-Transcript 
  Transcript started, output file is C:\Users\andy.dwyer\Documents\PowerShell_transcript.ADMIN-STATION.x9xkJMAJ.20210510184103.txt
  ```
  Note the file name and location
  Step two: Locate the PID number of powershell.exe, we will run tasklist and scroll down until you find powershell
  ```
  tasklist
  ```
  Step three: In a different cmd prompt, use the following command to show the handles in use with powershell.exe
  ```
  C:\windows\system32>handle.exe -p <pid of powershell> -accepteula
  
  Nthandle v4.22 - Handle viewer
  Copyright (C) 1997-2019 Mark Russinovich
  Sysinternals - www.sysinternals.com
  
     40: File  (RW-)   C:\Windows\System32
     C4: File  (R-D)   C:\Windows\System32\WindowsPowerShell\v1.0\en-US\powershell.exe.mui
    174: Section       \BaseNamedObjects\__ComCatalogCache__
    1C4: Section       \BaseNamedObjects\windows_shell_global_counters
    1F4: Section       \...\Cor_SxSPublic_IPCBlock
    1F8: Section       \BaseNamedObjects\Cor_Private_IPCBlock_v4_10188
    208: Section       \Sessions\2\BaseNamedObjects\windows_shell_global_counters
    _Output_Truncated_
  ```
  Step four: Show that the start-transcript log file cannot be altered. Open in notepad and type anything then try to save it
  
  Step five: Run the following command
  ```
  C:\windows\system32>handle.exe -p 10188 -c c:\Users\andy.dwyer\Documents\PowerShell_transcript.ADMIN-STATION.x9xkJMAJ.20210510184103.txt
  
  Nthandle v4.22 - Handle viewer
  Copyright (C) 1997-2019 Mark Russinovich
  Sysinternals - www.sysinternals.com
  
      C: WaitCompletionPacket
  Close handle C in powershell.exe (PID 10188)? (y/n)
  ```
  After the handle is closed reopen the log file back in notepad and show the file can now be edited.
  
  Q: Why are handles important to Cyber?
  
  Looking at handles to DLLs will help understand what malware could be doing as well as killing handles to logs could prevent behavior on systems from being recorded.
  
  ###############################END###############################
  ##############################################################END OF DAY 6##############################################################
# Day 7
##############################################################DAY 7##############################################################
# Linux Process Vailidity FG
###############################Linux Process Validity###############################
## 1 Process Listing
  A process is one of the most important fundamental concepts of the Linux Operating System. A process refers to a program in execution; it is a running instance of a program. It is made up of the program instruction, data read from files and other programs or input from a system user.
  
  Each Linux system has numerous processes running. You may be familiar, or will become familiar, with most of these processes if you regularly use commands like "ps" or "top" to display them.
  


### 1.1 ps command
  The ps command is a native Unix/Linux utility for viewing information concerning a selection of running processes on a system: it reads this information from the virtual files in /proc filesystem
  
  Output of ps command
  ```
  student@linux-opstation-grkv:~$ ps 
    PID TTY          TIME CMD
   7198 pts/1    00:00:00 bash 
   7213 pts/1    00:00:00 ps
```
  ps (report a snapshot of the current processes) command
  the output provides information about the currently running processes, including their process identification numbers (PID).
  

### 1.2 top command
  The top command is used to show the Linux processes. It provides a dynamic real-time view of the running system. Usually, this command shows the summary information of the system and the list of processes or threads which are currently managed by the Linux Kernel. Additional columns, like ppid, can be added by pressing f in the main window. A hierarchical view of the process tree can be displayed by pressing shift + v.
  
  Output of top command
  ```
  student@linux-opstation-grkv:~$ top 
  
  top - 15:30:43 up 2 days, 13:04,  3 users,  load average: 0.00, 0.00, 0.00
  Tasks: 205 total,   1 running, 167 sleeping,   0 stopped,   0 zombie
  %Cpu(s):  0.3 us,  0.7 sy,  0.0 ni, 99.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
  KiB Mem :  4039312 total,  2133660 free,  1070632 used,   835020 buff/cache
  KiB Swap:        0 total,        0 free,        0 used.  2642820 avail Mem
  
    PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND 
   1572 gdm       20   0  802524  50388  37608 S  0.3  1.2   0:53.50 gsd-color
   7239 student   20   0   44540   4028   3392 R  0.3  0.1   0:00.16 top
      1 root      20   0  159928   9144   6728 S  0.0  0.2   0:08.14 systemd
  -- Truncated
  ```
  top command provides a dynamic real-time view of a running system
  the output displays the summary information for the system and a dynamic list of processes currently managed by the Linux kernel


### 1.3 htop command
  Similar to top, htop is a utility used to display various information about Linux processes dynamically, but in a more human friendly way. Also like top it can be configured to show an operator exactly the set of information needed for the task at hand. At the bottom of the htop window there is a bar with some available actions, namely F5 to present the process listing in a hierarchicall tree view, and F2 to add or remove columns such as ppid.
  


## 2. Startup Processes
  The startup process follows the boot process and brings the Linux computer to an operational state in which it is usable for productive work. It is highly important that a demarcation is established in virtual memory to prevent programs running in user space to directly interact with the kernel.
  
  Executing the ps command with the -elf argument will do a full format listing of all running processes on the system in long format
  
  *Output of ps -elf command
  ```
  student@linux-opstation-grkv:~$ ps -elf | head 
  F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD         
  4 S root         1     0  0  80   0 - 39982 -      Feb25 ?        00:00:08 /sbin/init  
  1 S root         2     0  0  80   0 -     0 -      Feb25 ?        00:00:00 [kthreadd]  
  
  --Truncated
  ```
  ps -elf command will do a full format listing of all processes. Snapshot above shows the two primary processes after startup
  shows the fields
  F:      Field Table
  S:      Current status of the process
  UID:    The effective user ID of the process's owner
  PID:    Process ID
  PPID:   The parent process's ID
  C:      The processor utilization for scheduling. This field is not displayed when the -c option is used
  PRI:    The kernel thread's scheduling priority. Higher numbers mean higher priority
  NI:     The process's nice number, which contributes to its scheduling priority. Making a process "nicer" means lowering its priority
  ADDR:   The address of the proc structure
  SZ:     The virtual address size of the process
  WCHAN:  The address of an event or lock for which the process is sleeping
  STIME:  The starting time of the process (in hours, minutes, and seconds)
  TTY:    The terminal from which the process (or its parent) was started. A question mark indicates there is no controlling terminal
  TIME:   The total amount of CPU time used by the process since it began
  CMD:    The command that generated the process
  init (/sbin/init) has a process ID of 1; and its parent, the Kernel has a PID of 0. The kernel starts /sbin/init which is the parent/grandparent of all user mode processes.
  Modern Linux kernels/distros also have [kthreadd] which is a kernel thread daemon which is second after init so it will have a PID of 2 and will also have no parent.
  The STIME column in a "ps" output displays the time the process started, or the starting date if it started more than 24 hours ago. The STIME changing to 0 is further evidence that a process is no longer running, as the start time is no longer being monitored, and was reset to 0.
  
  
  Key Points
  
  All kernel processes are fork()ed from [kthreadd] and all user processes are fork()ed from /sbin/init or direct ancestor.
  
  Kernel processes are typically used to manage hardware, are directly handled by the kernel, have their own memory space, and have a high priority.
  
  They can be identified by the name enclosed in square brackets [ ] (using the ps -f option). kthreadd -spawned processes will have a PPID of 2.
  
  
  
  Q: What are the primary parent processes of all running processes on the system?
  
  A: There are two primary processes after startup:
  
  For user-space processes /sbin/init ( PID = 1 )
  
  For kernel-space processes [kthreadd] ( PID = 2 )
  
  Operational Value
  
  The Linux OS is at it’s core the sum of all running processes.
  
  Understanding the difference between User and Kernel mode processes, as well as the Parent/Child relationship of processes, is fundamental to understanding how a Linux machine works.
  
  

## 3. Concepts of Virtual Memory
  Virtual memory is divided into kernel space and user space



### 3.1 Kernel Space
  Kernel space is that area of virtual memory where kernel processes will run. This division is required for memory access protections. Code running in kernel mode has unrestricted access to the processor and main memory. This is a powerful but dangerous privilege that allows a kernel process to easily crash the entire system. The kernel is the core of the operating system. It normally has full access to all memory and machine hardware (and everything else on the machine). To keep the machine as stable as possible, you normally want only the most trusted, well-tested code to run in kernel mode/kernel space.
  
  Executing code in kernel space will give it unrestricted access to any of the memory address space and to any underlying hardware. Kernel space is reserved for the highest of trusted functions within a system. Kernel mode is generally reserved for the lowest-level (ring 0), most trusted functions of the operating system. Due to the amount of access the kernel have, any instability within the kernel’s executing code can result in complete system failure.
  
  Kernel space can be accessed by user processes only through the use of system calls.
  


### 3.2 User Space
  User mode, in comparison, restricts access to a (usually quite small) subset of memory and safe CPU operations. User space refers to the parts of main memory that the user processes can access. If a process makes a mistake and crashes, the consequences are limited and can be cleaned up by the kernel. This means that if your web browser crashes, it won’t take down the whole system. Think of it as a form of sand-boxing — it restricts user programs so they can’t mess with memory (and other resources) owned by other programs or by the OS kernel. This limits (but usually doesn’t entirely eliminate) their ability to do bad things like crashing the machine. Because of the restricted access, malfunctions within user mode are limited only to the system space they are operating within.
  
  An API (Application Programming Interface - set of protocols, routines, and, functions that allow the exchange of data among various applications and devices) and/or System calls (method that allows a program to request services from the kernel) are made by user mode processes to the kernel to request memory and physical hardware access.
  

### 3.3 OS Protection
  In Computer Science, the ordered protection domains are referred to as Protection Rings. These mechanisms help in improving fault tolerance and provide Computer Security. Operating Systems provide different levels to access resources. Rings are hierarchically arranged from most privileged to least privileged.
  
  [insert image](https://git.cybbh.space/os/public/-/raw/master/os/modules/010_linux_process_validity/pages/OS_Protection_Ring.png)
  
  Use of Protection Rings provides logical space for the levels of permissions and execution. Two important uses of Protection Rings are:
  
  Improving Fault Tolerance
  
  Provide Computer Security
  
  There are basically 4 levels ranging from 0 which is the most privileged to 3 which is least privileged. Most Operating Systems use level 0 as the kernel or executive and use level 3 for application programs.
  
  Rings 1-2 cannot run privileged instructions but this is the only real limit; otherwise they are as privileged as ring 0. The intent by Intel in having rings 1 and 2 is for the OS to put device drivers at that level, so they are privileged, but somewhat separated from the rest of the kernel code.
  
  Operational Value
  
  The goal in most, if not all, exploitative exercises is to be able to manipulate kernel mode processes and memory.
  
  In doing so, an adversary can gain complete control over the OS and obfuscate their methodology.
  
  

## 4. Process Ownership, Effective User ID (EUID), Real User ID (RUID), User ID (UID)
  The Linux kernel supports the traditional concept of a Unix user. A user is an entity that can run processes and own files. A user is also associated with a username.

### 4.1 Process Ownership
  A Linux process is nothing but running instance of a program. For example, when you start Firefox to browse Internet, you can create a new process. In Linux, each process is given a unique number called as a process identification (PID). Linux kernel makes sure that each process gets a unique PID. /sbin/init or /lib/systemd/systemd on modern Linux distros always has a PID of 1 because it is eternally the first process on the Linux based system.
  
  A user is an entity that can run processes and own files. Users exist primarily to support permissions and boundaries. Every user-space process has a user owner, and processes are said to run as the owner. A user may terminate or modify the behavior of its own processes (within certain limits), but it cannot interfere with other users’ processes. In addition, users may own files and choose whether they share them with other users.
  
  Users of the system may be:
  
  Human Users = people who log into the system; or
  
  System Users = used to start non-interactive background services such as databases
  
  From the perspective of the operating system, there is no distinction between human users and system users and all the information is stored in the same file. However, there is a range of user IDs reserved for human users and another range for system users. To view this range, execute the following command and point out that the system UID’s range from 100 - 999 and the user range is 1000 - 60000.
  
  Show range of User IDs for system and human users
  ```
    student@linux-opstation-grkv:~$ grep UID /etc/login.defs                  
  
  	UID_MIN:                1000        
  	UID_MAX:                60000       
  	#SYS_UID_MIN:           100         
  	#SYS_UID_MAX:           999
```
  grep for UID from the shadow password suite configuration file login.defs
  minimum userid assigned to a regular user
  maximum userid assigned to a regular user
  minimum userid assigned to a system user
  maximum userid assigned to a system user
  

### 4.2 Effective User ID (EUID)
  Effective user ID (EUID) defines the access rights for a process. In layman’s term it describes the user whose file access permissions are used by the process.



### 4.3 Real User ID (RUID)
  The real user ID is who you really are (the one who owns the process). It also defines the user that can interact with the running process—most significantly, which user can kill and send signals to a process.
  
  Users can only modify / interact with files /processes that they own or that have been shared with them.
  
  The distinction between a real and an effective user id is made because you may have the need to temporarily take another user’s identity (most of the time, that would be root, but it could be any user).
  EUID and RUID are mostly always the same. They can be different when special permissions (like SUID bits) are set on files.
  Viewing special permissions on passwd executables
  ```
  student@linux-opstation-grkv:~$ ls -l /usr/bin/passwd         
  -rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
     ^          ^
    <2>
  ```
  command list permissions of the passwd executables
  depicts that the SUID bit is set on the executable
  shows that the SUID bit is set by the user root
  In the example above; the SUID bit is set on the passwd executable so that when a normal user (non-root user) attempts to change their password, the executable is run with effective permissions of root. In this instance the real user is the non-root user and effective user is root.
  Operational Value
  
  The "context" that a program runs in is something that is very important to keep track of. For Example:
  
  The /usr/bin/passwd command runs with an EUID of root no matter who runs it.
  
  ls -l /usr/bin/passwd
  
  This is done, because when a user updates their password, the /etc/shadow file is overwritten, which can only be done by root.
  
  However, the passwd command tracks the RUID ensuring that a normal user can’t change another user’s password
  


## 5. System Calls
  
  
  Starting a new process
  [image](https://git.cybbh.space/os/public/-/raw/master/os/modules/010_linux_process_validity/pages/linproc1.png)
  
  original process
  original process asking the kernel to create another process must perform a fork() system call
  original process after fork() system call
  identical copy of original process after fork() system call
  identical copy of original process performs exec(ls) system call
  kernel replaces identical copy of original process with that of the new process
  
  
  Q: What exactly is a system call?
  
  A: A system call is an interaction between a process and the kernel, a programmatic way in which a computer program requests a service from the kernel of the operating system it is executed on. For example, the acts of opening, reading, and writing files all involve system calls.
  


### 5.1 Fork() and Exec() System calls
  Two system calls, fork and exec, are important to understanding how processes startup:
  
  fork - creates a new process by duplicating the calling process. The new process is referred to as the child process. The calling process is referred to as the parent process.
  
  The fork “processes” can be explained as the recreation of a process from system space and duplicated into user space in an attempt restrict user access to system processes/space.
  
  exec - When a process calls exec, the kernel starts program, replacing the current process.
  
  Some popular system calls are open, read, write, close, wait, exec, fork and kill.
  
  
  Table 1. Common System Calls
  Windows
  
  Unix
  
  Process Control
  
  CreateProcess()
  
  fork()
  
  ExitProcess()
  
  exit()
  
  WaitForSingleObject()
  
  wait()
  
  File Manipulation
  
  CreateFile()
  
  open()
  
  ReadFile()
  
  read()
  
  WriteFile()
  
  write()
  
  CloseHandle()
  
  close()
  
  Device Manipulation
  
  SetConsoleMode()
  
  ioctl()
  
  ReadConsole()
  
  read()
  
  WriteConsole()
  
  write()
  
  Information Maintenance
  
  GetCurrentProcessID()
  
  getpid()
  
  SetTimer()
  
  alarm()
  
  Sleep()
  
  sleep()
  
  Communication
  
  CreatePipe()
  
  pipe()
  
  CreateFileMapping()
  
  shmget()
  
  MapViewOfFile()
  
  mmap()
  
  Protection
  
  SetFileSecurity()
  
  chmod()
  
  InitlializeSecurityDescriptor()
  
  umask()
  
  SetSecurityDescriptorGroup()
  
  chown()
  
  Operational Value
  
  An existing executables weakness is that system call instructions are easily identifiable, which makes them potentially vulnerable to scanning attacks. You can make system call instructions harder to identify by disguising them as other, less conspicuous, instructions (e.g., load, store, or div instructions).
  
  It’s beyond the scope of this course to get into all the types of system calls.
  
  Still, it’s important to understand what they are, and a lot of information can be gleaned from monitoring specific ones.
  


### 5.2 Linux - Signals
  Signals are software interrupts sent to a program to indicate that an important event has occurred. The events can vary from user requests to illegal memory access errors. Some signals, such as the interrupt signal, indicate that a user has asked the program to do something that is not in the usual flow of control.
  
  Every signal has a default action associated with it. The default action for a signal is the action that a script or program performs when it receives a signal.
  
  Some of the possible default actions are −
  
  Terminate the process.
  Ignore the signal.
  Dump core. This creates a file called core containing the memory image of the process when it received the signal.
  Stop the process.
  Continue a stopped process
  
  Key Points
  kill -9 <PID> or pkill -9 <process name>
  Stop Process = SIGSTOP(19) (pause signal, let’s you continue later, does not kill process)
  End Process = SIGTERM(15) (termination signal, the right way, the application can intercept this signal and initiate shutdown tasks such as temp file cleanup)
  Kill Process = SIGKILL(9) (kill signal, extreme, only use if SIGTERM doesn’t work, won’t initiate shutdown tasks)
  
  
  
  Table 2. Common Signals in Linux
  Signal
  
  Name
  
  Description
  
  SIGHUP
  
  1
  
  Hangup (POSIX)
  
  SIGINT
  
  2
  
  Terminal interrupt (ANSI)
  
  SIGQUIT
  
  3
  
  Terminal quit (POSIX)
  
  SIGILL
  
  4
  
  Illegal instruction (ANSI)
  
  SIGTRAP
  
  5
  
  Trace trap (POSIX)
  
  SIGIOT
  
  6
  
  IOT Trap (4.2 BSD)
  
  SIGBUS
  
  7
  
  BUS error (4.2 BSD)
  
  SIGFPE
  
  8
  
  Floating point exception (ANSI)
  
  SIGKILL
  
  9
  
  Kill(can’t be caught or ignored) (POSIX)
  
  SIGUSR1
  
  10
  
  User defined signal 1 (POSIX)
  
  SIGSEGV
  
  11
  
  Invalid memory segment access (ANSI)
  
  SIGUSR2
  
  12
  
  User defined signal 2 (POSIX)
  
  SIGPIPE
  
  13
  
  Write on a pipe with no reader, Broken pipe (POSIX)
  
  SIGALRM
  
  14
  
  Alarm clock (POSIX)
  
  SIGTERM
  
  15
  
  Termination (ANSI)
  
  SIGSTKFLT
  
  16
  
  Stack fault
  
  SIGCHLD
  
  17
  
  Child process has stopped or exited, changed (POSIX)
  
  SIGCONTv
  
  18
  
  Continue executing, if stopped (POSIX)
  
  SIGSTOP
  
  19
  
  Stop executing(can’t be caught or ignored) (POSIX)
  
  SIGTSTP
  
  20
  
  Terminal stop signal (POSIX)
  
  SIGTTIN
  
  21
  
  Background process trying to read, from TTY (POSIX)
  
  SIGTTOU
  
  22
  
  Background process trying to write, to TTY (POSIX)
  
  SIGURG
  
  23
  
  Urgent condition on socket (4.2 BSD)
  
  SIGXCPU
  
  24
  
  CPU limit exceeded (4.2 BSD)
  
  SIGXFSZ
  
  25
  
  File size limit exceeded (4.2 BSD)
  
  SIGVTALRM
  
  26
  
  Virtual alarm clock (4.2 BSD)
  
  SIGPROF
  
  27
  
  Profiling alarm clock (4.2 BSD)
  
  SIGWINCH
  
  28
  
  Window size change (4.3 BSD, Sun)
  
  SIGIO
  
  29
  
  I/O now possible (4.2 BSD)
  
  SIGPWR
  
  30
  
  Power failure restart (System V)

  
  
  List Supported signals
  ```
  student@linux-opstation-grkv:~$ kill -l                             
   1) SIGHUP	 2) SIGINT	 3) SIGQUIT	 4) SIGILL	 5) SIGTRAP         
   6) SIGABRT	 7) SIGBUS	 8) SIGFPE	 9) SIGKILL	10) SIGUSR1
  11) SIGSEGV	12) SIGUSR2	13) SIGPIPE	14) SIGALRM	15) SIGTERM
  16) SIGSTKFLT	17) SIGCHLD	18) SIGCONT	19) SIGSTOP	20) SIGTSTP
  21) SIGTTIN	22) SIGTTOU	23) SIGURG	24) SIGXCPU	25) SIGXFSZ
  26) SIGVTALRM	27) SIGPROF	28) SIGWINCH	29) SIGIO	30) SIGPWR
  31) SIGSYS	34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
  38) SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
  43) SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
  48) SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
  53) SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
  58) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
  63) SIGRTMAX-1	64) SIGRTMAX
  
  student@linux-opstation-grkv:~$ kill -19 <PID of Process>               
  
  student@linux-opstation-grkv:~$ kill -18 <PID of Process>               
  
  student@linux-opstation-grkv:~$ kill -9 <PID of Process>                
  The kill command is used to send a signal to a process. kill -l will list signals supported by your system
  supported signals are displayed in output
  kill -19 <PID of process> command will send the pause signal to a process
  kill -18 <PID of process> command will send un-pause/continue executing signal to a process
  kill -9 <PID of process> is used in the most extreme cases to abruptly terminate a process
```

### 5.3 Demonstration - Process Enumeration
  Add the following scripts to your box for demonstrations, located at: https://git.cybbh.space/os/public-old/tree/master/modules/operating-systems/linux/scripts/6_LinuxProcesses
  
  
  Steps to follow when running scripts
  create a file for Each script with the following command nano <name>.sh
  copy and paste the contents of the script, close and save
  run the script with the following command: `source <name>.sh
  using less with the ps -elf command to page through the long output
  ```
  student@linux-opstation-grkv:~$ ps -elf | less 
  F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
  4 S root         1     0  0  80   0 - 40015 -      Feb25 ?        00:00:08 /sbin/init        
  1 S root         2     0  0  80   0 -     0 -      Feb25 ?        00:00:00 [kthreadd]
  1 I root         4     2  0  60 -20 -     0 -      Feb25 ?        00:00:00 [kworker/0:0H]
  
  --Truncated
  ```
  shows the command prior to execution
  shows the output one page view at a time. Can exit out of it by hitting the q key on your keyboard
  
  
  display top five lines of the process table
  ```
  student@linux-opstation-grkv:~$ ps -elf | head -n5   
  F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
  4 S root         1     0  0  80   0 - 56461 ep_pol 18:23 ?        00:00:07 /sbin/init splash     
  1 S root         2     0  0  80   0 -     0 kthrea 18:23 ?        00:00:00 [kthreadd]
  1 I root         3     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_gp]
  1 I root         4     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_par_gp]
  head command will display the top ten listings. When used with -n# will display the number of required listings
  note the top two PID’s and PPID’s
  ```
  
  Show only kthreadd processes
  ```
  student@linux-opstation-grkv:~$ ps --ppid 2 -lf | head              
  F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
  1 I root         3     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_gp]         
  1 I root         4     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_par_gp]
  1 I root         6     2  0  60 -20 -     0 worker 18:23 ?        00:00:00 [kworker/0:0H]
  1 I root         8     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [mm_percpu_wq]
  1 S root         9     2  0  80   0 -     0 smpboo 18:23 ?        00:00:00 [ksoftirqd/0]
  
  --Truncated
  --ppid # will show only the parent process with the stated id
  note that [kthreaded] processes have a PPID of 2 and with enclosed with brackets []
  ```
  
  Show all processes except kthreadd processes
  ```
  student@linux-opstation-grkv:~$ ps --ppid 2 -Nlf | head                 
  F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD          
  4 S root         1     0  0  80   0 - 56461 ep_pol 18:23 ?        00:00:07 /sbin/init splash
  1 S root         2     0  0  80   0 -     0 kthrea 18:23 ?        00:00:00 [kthreadd]
  4 S root       310     1  0  79  -1 - 25836 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-journald
  4 S root       336     1  0  80   0 -  8503 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-udevd
  4 S systemd+   576     1  0  80   0 - 17750 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-resolved
  4 S systemd+   578     1  0  80   0 - 36527 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-timesyncd
  
  --Truncated
  -N is used in connection with --ppid to negate the required ppid
  output will not contain ppid of 2 i.e {kthreaded] processes
  ```
  
  display process output in Ascii art process tree
  ```
  student@linux-opstation-grkv:~$ ps -elf --forest | tail             
  0 S student   3185  3178  0  80   0 - 219853 poll_s Feb25 tty2    00:00:00  \_ /usr/lib/evolution/evolution-addressbook-factory-subprocess --factory all --bus-name org.gnome.evolution.dataserver.Subprocess.Backend.AddressBookx3178x2 --own-path /org/gnome/evolution/dataserver/Subprocess/Backend/AddressBook/3178/2
  0 S student   3243     1  0  80   0 - 175142 poll_s Feb25 tty2    00:00:00 /usr/lib/gnome-terminal/gnome-terminal-server                                                   
  0 S student   3251  3243  0  80   0 -  5774 wait   Feb25 pts/2    00:00:00  \_ bash
  4 S root      3310  3251  0  80   0 - 15870 -      Feb25 pts/2    00:00:00      \_ su root
  4 S root      3311  3310  0  80   0 -  5510 -      Feb25 pts/2    00:00:00          \_ bash
  0 S student   4357     1  0  80   0 -  1159 wait   Feb25 tty2     00:00:00 /bin/sh -c /usr/lib/ubuntu-release-upgrader/check-new-release-gtk
  0 S student   4358  4357  0  80   0 - 127623 poll_s Feb25 tty2    00:00:00  \_ /usr/bin/python3 /usr/lib/ubuntu-release-upgrader/check-new-release-gtk
  
  --Truncated
  --forest will display the output in Ascii tree format. Tail command will output the last ten lines
  output shows a diagrammatic view of the process table
  ```
  
  Key Points
  
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
  
  Operational Value
  
  Excellent command for process enumeration.
  


## 6. Foreground and Background Processes
  Processes that require a user to start them or to interact with them are called foreground processes.
  
  Processes that are run independently of a user are referred to as background processes.
  
  Programs and commands run as foreground processes by default.
  


### 6.1 Orphan Processes
  An orphan process is a running process whose parent process has finished or terminated and is adopted by sbin/init and will have a PPID of 1.
  
  Key Points
  
  disown -a && exit #Close a shell/terminal and force all children to be adopted
  


### 6.1.1 Demonstration - Orphan
  Copy code below and paste into any editor of choice. Give a name to the script. In this instance the script will be called orphan.sh, make file an executable and run twice in succession.
  
  Code for orphan demonstration
  #!/bin/bash
  
  #Print PID of current shell
  echo $$
  
  #Pause  for  NUMBER seconds
  sleep 5 &
  
  #List process table and output PID associated with "sleep"
  ps -elf | grep -v  grep | grep sleep
  #!/bin/bash on the first line, meaning that the script should always be run with bash
  
  
  
  Simple demonstration to show how orphans are created
  ```
  student@linux-opstation-grkv:~$ chmod +x orphan.sh          
  
  student@linux-opstation-grkv:~$ ./orphan.sh                 
  13409                                                       
  0 S student  13410 13409  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5      
  
  student@linux-opstation-grkv:~$ ./orphan.sh             
  13415                                                               
  0 S student  13410     1  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5      
  0 S student  13416 13415  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5
```
  make orphan.sh an executable
  first run of orphan.sh
  13409 is the PID of the shell containing the executable
  PID 13410 is the PID of the sub process created when the file was executed. Its parent PID is 13409
  second run of orphan.sh
  new PID of shell containing the code is now 13415
  running the code a second time terminates the original process with PID 13409 containing the code. Sub process with PID of 13410 will now become an orphan and will be reclaimed by /sbin/init. Its PPID will now be 1
  

### 6.1.2 Resources
  Orphan Exploit Exercise
  
  More about Orphan Processes
  


### 6.2 Zombie (Defunct) Processes
  A zombie process (or defunct process) is a process that has completed execution but hasn’t been reaped by its parent process. As result it holds a process entry in the form of a PID in the process table. Zombies cannot be killed as they are already dead and do not use resources. However, they do take up PIDs in the process table which is a finite resource. Zombie entries can be removed from the process table by killing its parent process.
  
  

### 6.2.1 Demonstration - zombies
  Copy code below and paste into any editor of choice. Give a name to the script. In this instance the script will be called zombie.sh, make file an executable and run once
  ```
  Code for zombie demonstration
  #!/bin/bash
  
  #Print PID of current shell
  echo $$
  
  #Pause  for  NUMBER seconds
  sleep 2 &
  
  #Pause signal
  kill -19 $(echo $$)
  #!/bin/bash on the first line, meaning that the script should always be run with bash
  ```
  
  
  Simple demonstration to show how zombies are created
  ```
  student@linux-opstation-grkv:~$ chmod +x zombie.sh          
  
  student@linux-opstation-grkv:~$ ps -elf | grep -v grep | grep sleep     
  
  student@linux-opstation-grkv:~$ ./zombie.sh         
  13981                                   
  
  [1]+  Stopped                 ./zombie.sh
  
  student@linux-opstation-grkv:~$ ps -elf| grep -v grep | grep sleep          
  0 Z student  13982 13981  0  80   0 -     0 -      00:17 pts/1    00:00:00 [sleep] <defunct>        
  
  student@linux-opstation-grkv:~$ kill -18 13981                  
  [1]+  Done                    ./zombie.sh
  
  student@linux-opstation-grkv:~$ ps -elf| grep -v grep | grep sleep
```    
  make zombie.sh an executable
  List continents of process table and confirm that there is no zombie on process list
  execute file zombie.sh
  PID 13981 is the PID of the shell containing the executable
  After two seconds list contents of the process table containing sleep in the command section
  After the sleep command completes, the process associated with the executable will not be around to reap its return code as it was paused due to the kill -19 command in the code. The process associated with sleep, with PID of 13982 will now become a zombie as its parent with PID 13981 is paused. Note the z and <defunct> in the process list
  kill -18 will send the continue\restart signal to PID 13981 which will clear the zombie entry from the process list
  this command will return no output as the zombie entry has been cleared from the process list
  

### 6.2.2 Resources
  Example - ZombieLoad Attack
  
  Zombie Security Risks



### 6.3 Daemons
  A daemon process is an intentionally orphaned process in order to have a background process.
  
  Key Points
  
  What is a daemon and how are they created?
  
  Program that runs as a background process (Ex. syslogd, sshd, cron)
  
  All daemons are Orphans, but all orphans are not Daemons
  
  A daemons purpose is to manage/monitor a service: {status, start, restart}
  
  man cron - to see an example of a daemon that starts during the boot process
  
  
  
  Operational Value
  
  Persistence - Daemons are services that should run for duration of system operation, since init is parent, would require shutdown for parent to die.
  
  Malicious processes are sometimes orphaned and named to make it look like a daemon process ps --ppid 1 -lf
  


### 6.3.1 Interacting With Linux Services

  
  A service is a program that runs in the background outside the interactive control of system users as they lack an interface. This in order to provide even more security, because some of these services are crucial for the operation of the operating system.
  
  On the other hand, in systems like Unix or Linux, the services are also known as daemons. Sometimes the name of these services or daemons ends with the letter d. For example, sshd is the name of the service that handles SSH.
  
  The commands used to interact with services on a Unix/Linux system differs based on distribution [sysV or systemD]
  
  

### 6.3.1.1 Interacting With Services on a SYSV System

  
  A system that uses the SysV scheme usually comes with the service program used to manage the services while the system is running. You can check on the status of a service, or all services, and start or stop a service, respectively, using the service utility:
  
  
  
  Check status/start/stop/restart a service on sysV
  student@linux-opstation-grkv:~$ service <servicename> status/start/stop/restart
  

### 6.3.1.2 Interacting With Services on a SYSTEMD System
  In recent years, Linux distributions have increasingly transitioned from other init systems to systemd. The systemd suite of tools provides a fast and flexible init model for managing an entire machine from boot onwards
  
  The basic object that systemd manages and acts upon is a “unit”. Units can be of many types, but the most common type is a “service” (indicated by a unit file ending in .service). To manage services on a systemd enabled server, our main tool is the systemctl command.
  

  
  List all unit files that systemd has listed as active
  ```
  student@linux-opstation-grkv:~$ systemctl list-units
  UNIT                                                                                LOAD   ACTIVE SUB       DESCRIPTION
  proc-sys-fs-binfmt_misc.automount                                                   loaded active waiting   Arbitrary Executable File Formats F
  sys-devices-pci0000:00-0000:00:01.1-ata1-host0-target0:0:0-0:0:0:0-block-sr0.device loaded active plugged   QEMU_DVD-ROM config-2
  sys-devices-pci0000:00-0000:00:03.0-virtio1-net-ens3.device                         loaded active plugged   Virtio network device
  
  --Truncated
  ```
  
  List all units that systemd has loaded or attempted to load into memory, including those that are not currently active, add the --all switch:
  ```
  student@linux-opstation-grkv:~$ systemctl list-units --all
    UNIT                                                                                LOAD      ACTIVE   SUB       DESCRIPTION
    proc-sys-fs-binfmt_misc.automount                                                   loaded    active   waiting   Arbitrary Executable File Fo
    dev-cdrom.device                                                                    loaded    active   plugged   QEMU_DVD-ROM config-2
    dev-disk-by\x2did-ata\x2dQEMU_DVD\x2dROM_QM00001.device                             loaded    active   plugged   QEMU_DVD-ROM config-2
  
  --Truncated
  ```
  
  Check status of a service
  ```
  student@linux-opstation-grkv:~$ systemctl status <servicename.service>
  
  student@linux-opstation-grkv:~$ systemctl status <PID of service>
  
  
  Start/stop/restart a service
  
  student@linux-opstation-grkv:~$ systemctl start/stop/restart <servicename.service>
  ```

### 6.4 Job Control
  Job control is the ability to stop/suspend the execution of processes (command) and continue/resume their execution as per your requirements.
  
  The jobs command displays the status of jobs started in the current terminal window. Jobs are numbered starting from 1 for each session. The job ID numbers are used by some programs instead of PIDs (for example, by fg and bg commands).
  


### 6.4.1 Demonstration - Job Control
  
  
  Jobs
  ```
  student@linux-opstation-grkv:~$ ping 8.8.8.8 &          
  [1] 14130                   
  student@linux-opstation-grkv:~$ PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
  64 bytes from 8.8.8.8: icmp_seq=1 ttl=112 time=8.51 ms
  64 bytes from 8.8.8.8: icmp_seq=2 ttl=112 time=8.40 ms
  64 bytes from 8.8.8.8: icmp_seq=3 ttl=112 time=8.31 ms
  fg                              
  ping 8.8.8.8
  64 bytes from 8.8.8.8: icmp_seq=4 ttl=112 time=8.72 ms
  ^Z                              
  [1]+  Stopped                 ping 8.8.8.8
  
  student@linux-opstation-grkv:~$ jobs            
  [1]+  Stopped                 ping 8.8.8.8      
  
  student@linux-opstation-grkv:~$ kill -9 %1      
  
  [1]+  Stopped                 ping 8.8.8.8
  ```
  the command is executed as a background process indicated by & at the end
  value in [] denotes job id and 14130 denotes PID
  fg command is entered on the keyboard to bring job to the foreground
  ctrl+z is used to stop the job
  jobs command will list all jobs and their status
  list that job id 1 is stopped
  job id 1 is abruptly terminated with the kill -9 command. Use the % when terminating jobs by their respective ids
  the bg command can be use to background a job and ctrl+c command can be use to kill an active process


### 6.5 Cron Jobs

  
  The Unix cron service runs programs repeatedly on a fixed schedule. Most experienced administrators consider cron to be vital to the system because it can perform automatic system maintenance.
  
  The cron daemon checks the directories /var/spool/cron, /etc/cron.d and the file /etc/crontab, once a minute and executes any commands specified that match the time.
  
  Two types of cron jobs
  
  System cron jobs
  
  run as root and rigidly scheduled
  
  perform system-wide maintenance tasks (Cleaning out /tmp or rotating logs)
  
  controlled by /etc/crontab
  
  User cron jobs
  
  Use 'crontab’ command to create user cron jobs
  
  stored in /var/spool/cron/crontabs/
  
  One can run any program with cron at whatever time they want the job to execute. The program running through cron is called a cron job.
  
  On Unix-like systems, the crontab command opens the cron table for editing. The cron table is the list of tasks scheduled to run at regular time intervals on the system.
  
  Syntax
  
  crontab -u [user] file This command will load the crontab data from the specified file
  
  crontab -l -u [user] This command will display/list user’s crontab contents
  
  crontab -r -u [user] This Command will remove user’s crontab contents
  
  crontab -e -u [user] This command will edit user’s crontab contents
  
  Crontab jobs will run with the permissions of the owner of the crontab file
  Contents placement of the crontab file
  ```
    ┌───────────── minute (0 - 59)
    │ ┌───────────── hour (0 - 23)
    │ │ ┌───────────── day of the month (1 - 31)
    │ │ │ ┌───────────── month (1 - 12)
    │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
    │ │ │ │ │                           7 is also Sunday on some systems)
    │ │ │ │ │
    │ │ │ │ │
    * * * * * <Time/Day to execute    "Command to Execute"
  ```
  (Mnemonic: Minnie Has Daily Money Worries)
  * The syntax of each line expects a cron expression made of five fields, followed
  by a shell command to execute.
  
  
  Cron Examples
  * Run backup everyday at 0412
  ** `12 4 * * *`    /usr/bin/backup
  
  * Send a message to all logged in users, 0000 hours on 1 Jan
  ** `0 0 1 1 *`     wall "Happy New Year"
  
  Other advanced usage....
  
  * Send a message at minute 15 of each hour to logged in users on Sunday
  ** `15 * * * 0`    wall "Shouldn't you be in church?"
  
  * Run backup on Wed, and Sat at 0515
  ** `15 5 * * 3,6`   /usr/bin/backup
  
  * Save open tcp port listing hourly from 9PM to 5AM every day
  ** `0 0-5,21-23 * * *`    echo $(ss -nltp) >> /home/andy.dwyer/tcplist.context
    
### 6.5.1 Resources
  Cron Schedule Expression Editor

## 7 - Processes and Proc Dir
  The /proc/ directory — also called the proc file system — contains a hierarchy of special files which represent the current state of the kernel, allowing applications and users to peer into the kernel’s view of the system.
  
  Every process accesses files in order to complete its work. These processes keep track of open files using File Descriptors.

### 7.1 File Descriptors
  In Unix and Unix-like computer operating systems, a file descriptor ("FD" or less frequently known as "fildes") is a unique identifier (aka handle) for a file or other input/output resource, such as a pipe or network socket.
  
  When you open a file, the operating system creates an entry to represent that file and store the information about that opened file.
  
  So if there are 100 files opened in your OS then there will be 100 entries in the OS (somewhere in kernel).
  
  These entries are represented by integers like (…​100, 101, 102…​.).
  
  This entry number is the file descriptor. So it is just an integer number that uniquely represents an opened file in the operating system. If your process opens 10 files then your Process table will have 10 entries for file descriptors.
  
### 7.1.1 Viewing File Descriptors
  View File Descriptors using the LSOF command.
  
  List all open files being used by every process.
  ```
  sudo lsof | tail -30
  
  --- Trimmed ---
               <2>                         <1>                                                    
  COMMAND     PID   TID             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
  gdbus     18768 18772          student   12u     unix 0x0000000000000000      0t0    2409093 type=STREAM
  gdbus     18768 18772          student   14r      REG              252,1  1327119      18343 /var/lib/dpkg/status (deleted)
  gdbus     18768 18772          student   15r      CHR                1,9      0t0         11 /dev/urandom
  gdbus     18768 18772          student   16r      CHR                1,8      0t0         10 /dev/random
  --- Trimmed ---
  ```
  File Descriptors and their permissions
  PID and PPID
  Open file being accessed
  
  
  List all open files for a specific process.
  ```
  sudo lsof -c sshd
  
  sshd    14139 student    2u   CHR                1,3      0t0       6 /dev/null
  sshd    14139 student    3u  IPv4            2761262      0t0     TCP linux-opstation-mikh:ssh->192.168.249.87:43044 (ESTABLISHED)
  sshd    14139 student    4u  unix 0xffff917eb0205000      0t0 2761302 type=DGRAM
  sshd    14139 student    5u  unix 0xffff917ec7a51000      0t0 2761519 type=STREAM
  sshd    14139 student    6r  FIFO               0,12      0t0 2761523 pipe
  sshd    14139 student    7w  FIFO               0,24      0t0     289 /run/systemd/sessions/6101.ref
  sshd    14139 student    8w  FIFO               0,12      0t0 2761523 pipe
  sshd    14139 student    9u   CHR                5,2      0t0      87 /dev/ptmx
  sshd    14139 student   11u   CHR                5,2      0t0      87 /dev/ptmx
  sshd    14139 student   12u   CHR                5,2      0t0      87 /dev/ptmx
```
### 7.1.2 Interpretting File Descriptors
  This information and more available in the lsof man page.
  
  # - The number in front of flag(s) is the file descriptor number used by the process associated with the file
  u - File open with Read and Write permission
  r - File open with Read permission
  w - File open with Write permission
  W - File open with Write permission and with Write Lock on entire file
  mem - Memory mapped file, usually for share library
  
### 7.2 - Navigating Proc Directory
  List all the proc directories.
  ```
  ls -l /proc/
  
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 10
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 100
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1018
  dr-xr-xr-x  9 xrdp             xrdp                           0 Feb  9  2021 1081
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1085
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 11
  dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1104
  Grab the PID of a process.
  
  ps -elf | grep sshd
  
  4 S root      1107     1  0  80   0 - 18077 -      Feb09 ?        00:00:00 /usr/sbin/sshd -D
  4 S root     14035  1107  0  80   0 - 26424 -      14:21 ?        00:00:00 sshd: student [priv]
  5 S student  14139 14035  0  80   0 - 27031 -      14:22 ?        00:00:00 sshd: student@pts/0
```
  List contents for that PID directory.
 ``` 
  sudo ls -l /proc/14139
  
  total 0
  dr-xr-xr-x 2 student student 0 Aug 27 17:14 attr
  -rw-r--r-- 1 root    root    0 Aug 27 17:14 autogroup
  -r-------- 1 root    root    0 Aug 27 17:14 auxv
  -r--r--r-- 1 root    root    0 Aug 27 17:14 cgroup
  --w------- 1 root    root    0 Aug 27 17:14 clear_refs
  -r--r--r-- 1 root    root    0 Aug 27 17:12 cmdline
  -rw-r--r-- 1 root    root    0 Aug 27 17:14 comm
  -rw-r--r-- 1 root    root    0 Aug 27 17:14 coredump_filter
  -r--r--r-- 1 root    root    0 Aug 27 17:14 cpuset
  lrwxrwxrwx 1 root    root    0 Aug 27 14:22 cwd -> /
  -r-------- 1 root    root    0 Aug 27 17:14 environ
  lrwxrwxrwx 1 root    root    0 Aug 27 14:22 exe -> /usr/sbin/sshd
``` 
  The exe link to actual binary file being executed.

  ###############################END###############################

###############################BLANK###############################

###############################END###############################
##############################################################END OF DAY 7##############################################################



```








###############################QUESTIONS###############################



###############################BLANK###############################
###############################END###############################

###############################BLANK###############################
###############################END###############################





##############################################################DAY 1##############################################################
##############################################################END OF DAY 1##############################################################
