# Capture The Flag Threat Hunt Report: Assistance (11/8/25)
<img width="777" height="520" alt="image" src="https://github.com/user-attachments/assets/9d54faaa-0606-4fae-a122-c963ae8f5382" />

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- Log Analytics workspaces
- Kusto Query Language (KQL)

##  Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

---

## Steps Taken

### Starting Point

Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given:

1. Multiple machines in the department started spawning processes originating from the **download** folders. This unexpected scenario occurred during the **first half** of **October.**
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included **“desk,” “help,” “support,”** and **“tool.”**
4. Intern operated machines seem to be affected to certain degree.

**Question:**
Identify the most suspicious machine based on the given conditions

**My Actions and Thought Process:**
Based on the initial information I have, I searched within DeviceFileEvents between the time range of October 1st to October 15th for any devices with any activity relegated to "helpdesk" naming in terms of files with such a filename or directory locations that could have the name as well. I remembered the details from intel that this target device might be under the ownership of an intern end user. With this in mind, I had no doubt when I quickly narrowed down my search to a device with name `"gab-intern-vm"`.

**Query used to locate events:**

```kql
DeviceFileEvents    
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where FileName contains "helpdesk"
| where FolderPath contains "helpdesk"
```
<img width="1151" height="237" alt="image" src="https://github.com/user-attachments/assets/1e0ab9b7-3164-4c58-b68a-fe7efa97f385" />

**Answer:**
`gab-intern-vm`

---

### Flag #1 - Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:**
Look for atypical script or interactive command activity that deviates from normal user behavior or baseline patterns.

**Thought:**
Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.

**Hint:**

**1.** Downloads

**2.** Two


**Question:**
What was the first CLI parameter name used during the execution of the suspicious program?

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between 10/1/25 to 10/15/25 under the device name of "gab-intern-vm" (I will be using this device name and time range frequently for KQL queries going forward to maintain a precise and isolated view to the events that took place). With the information I have so far, I narrowed down further to potential inclusions of the "Downloads" folder in the command execution to investigate. I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Note:** The "tolower" line in the query below makes a case-insensitive search for a provided string. This is to capture all results regardless on whether Downloads folder was named "Downloads", "downloads", "DOWNLOADS" and etc...

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`-ExecutionPolicy`

---

### Flag #2 - Defense Disabling

**Objective:**
Identify indicators that suggest attempts to imply or simulate changing security posture.

**What to Hunt:**
Search for artifact creation or short-lived process activity that contains tamper-related content or hints, without assuming an actual configuration change occurred.

**Thought:**
A planted or staged tamper indicator is a signal of intent — treat it as intent, not proof of actual mitigation changes.

**Hint:**

**1.** File was manually accessed


**Question:**
What was the name of the file related to this exploit?

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between 10/1/25 to 10/15/25 under the device name of "gab-intern-vm" (I will be using this device name and time range frequently for KQL queries going forward to maintain a focused view to the events that took place). I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`DefenderTamperArtifact.lnk`

---

### Flag #3 - Quick Data Probe

**Objective:**
Spot brief, opportunistic checks for readily available sensitive content.

**What to Hunt:**
Find short-lived actions that attempt to read transient data sources common on endpoints.

**Thought:**
Attackers look for low-effort wins first; these quick probes often precede broader reconnaissance.

**Hint:**

**1.** Clip

**Side Note: 1/2**

**1.** has query


**Question:**
Provide the command value tied to this particular exploit

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

---


### Flag #4 - Host Context Recon

**Objective:**
Find activity that gathers basic host and user context to inform follow-up actions.

**What to Hunt:**
Telemetry that shows the actor collecting environment or account details without modifying them.

**Thought:**
Context-gathering shapes attacker decisions — who, what, and where to target next.

**Hint:**

**1.** qwi


**Question:**
Point out when the last recon attempt was

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`2025-10-09T12:51:44.3425653Z`

---


### Flag #5 - Storage Surface Mapping

**Objective:**
Detect discovery of local or network storage locations that might hold interesting data.

**What to Hunt:**
Look for enumeration of filesystem or share surfaces and lightweight checks of available storage.

**Thought:**
Mapping where data lives is a preparatory step for collection and staging.

**Hint:**

**1.** Storage assessment


**Question:**
What was the first CLI parameter name used during the execution of the suspicious program?

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`"cmd.exe" /c wmic logicaldisk get name,freespace,size`

---



### Flag #6 - Connectivity & Name Resolution Check

**Objective:**
Identify checks that validate network reachability and name resolution.

**What to Hunt:**
Network or process events indicating DNS or interface queries and simple outward connectivity probes.

**Thought:**
Confirming egress is a necessary precondition before any attempt to move data off-host.

**Side Note: 2/2**

**1.** session


**Question:**
Provide the File Name of the initiating parent process

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`RuntimeBroker.exe`

---



### Flag #7 - Interactive Session Discovery

**Objective:**
Reveal attempts to detect interactive or active user sessions on the host.

**What to Hunt:**
Signals that enumerate current session state or logged-in sessions without initiating a takeover.

**Thought:**
Knowing which sessions are active helps an actor decide whether to act immediately or wait.



**Question:**
What is the unique ID of the initiating process

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`2533274790397065`

---



### Flag #8 - Runtime Application Inventory

**Objective:**
Detect enumeration of running applications and services to inform risk and opportunity.

**What to Hunt:**
Events that capture broad process/process-list snapshots or queries of running services.

**Thought:**
A process inventory shows what’s present and what to avoid or target for collection.

**Hint:**

**1.** Task

**2.** List

**3.** Last


**Question:**
Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host.

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`tasklist.exe`

---



### Flag #9 - Privilege Surface Check

**Objective:**
Detect attempts to understand privileges available to the current actor.

**What to Hunt:**
Telemetry that reflects queries of group membership, token properties, or privilege listings.

**Thought:**
Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

**Hint:**

**1.** Who


**Question:**
Identify the timestamp of the very first attempt

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`2025-10-09T12:52:14.3135459Z`

---



### Flag #10 - Proof-of-Access & Egress Validation

**Objective:**
Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**What to Hunt:**
Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data.

**Thought:**
This step demonstrates both access and the potential to move meaningful data off the host…

**Side Note: 1/3**

**1.** support


**Question:**
Which outbound destination was contacted first?

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`www.msftconnecttest.com`

---



### Flag #11 - Bundling / Staging Artifacts

**Objective:**
Detect consolidation of artifacts into a single location or package for transfer.

**What to Hunt:**
File system events or operations that show grouping, consolidation, or packaging of gathered items.

**Thought:**
Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

**Hint:**

**1.** Include the file value


**Question:**
Provide the full folder path value where the artifact was first dropped into

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`C:\Users\Public\ReconArtifacts.zip`

---



### Flag #12 - Outbound Transfer Attempt (Simulated)

**Objective:**
Identify attempts to move data off-host or test upload capability.

**What to Hunt:**
Network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**Thought:**
Succeeded or not, attempt is still proof of intent — and it reveals egress paths or block points.

**Side Note: 2/3**

**1.** chat


**Question:**
Provide the IP of the last unusual outbound connection

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`100.29.147.161`

---



### Flag #13 - Scheduled Re-Execution Persistence

**Objective:**
Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**What to Hunt:**
Process or scheduler-related events that create recurring or logon-triggered executions tied to the same actor pattern.

**Thought:**
Re-execution mechanisms are the actor’s way of surviving beyond a single session — interrupting them reduces risk.


**Question:**
Provide the value of the task name down below

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`SupportToolUpdater`

---



### Flag #14 - Autorun Fallback Persistence

**Objective:**
Spot lightweight autorun entries placed as backup persistence in user scope.

**What to Hunt:**
Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:**
Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

**Side Note: 3/3**

**1.** log

⚠️ If table returned nothing: **RemoteAssistUpdater**

DM the CTF admin should you wish to see how it would normally look like


**Question:**
What was the name of the registry value

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`RemoteAssistUpdater`

---



### Flag #15 - Planted Narrative / Cover Artifact

**Objective:**
Identify a narrative or explanatory artifact intended to justify the activity.

**What to Hunt:**
Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

**Thought:**
A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself.

**Hint:**

**1.** The actor opened it for some reason


**Question:**
Identify the file name of the artifact left behind

**Actions and Thought Process:**
I searched within DeviceProcessEvents for any suspicious commands that were ran between October 1st to October 15th under the device name of "gab-intern-vm". I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))  
| where tolower(ProcessCommandLine) has "\\downloads\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1155" height="292" alt="image" src="https://github.com/user-attachments/assets/5cbcdd77-8fe0-43d7-8c48-b00b834e59d1" />

**Answer:**
`SupportChat_log.lnk`

---






## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-27T06:18:48.8183897Z`
- **Event:** The user "mikeylab" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\mikeylab\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-27T06:22:42.9937103Z`
- **Event:** The user "mikeylab" executed the file `tor-browser-windows-x86_64-portable-14.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\mikeylab\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-27T06:23:55.1381116Z`
- **Event:** User "mikeylab" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\mikeylab\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Proxy Usage

- **Timestamp:** `2025-02-27T06:24:20.5898172Z`
- **Event:** The Tor Browser (firefox.exe) established a successful connection to `127.0.0.1` on port `9150` by user “mikeylab”, indicating the activation of the Tor proxy.
- **Action:** Connection detected.
- **Remote IP:** 127.0.0.1
- **Remote Port:** 9150

### 5. Network Connection - Web Traffic Over Tor

- **Timestamp:** `2025-02-27T06:24:20.5898172Z`
- **Event:** The Tor Browser (tor.exe) established connections to external sites over port `443`, indicating possible internet browsing through the Tor network.
- **Action:** Connection detected.
- **Remote IP:** 104.152.111.1
- **Remote Port:** 443

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-27T06:41:56.0186683Z`
- **Event:** The user "mikeylab" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\mikeylab\Desktop\tor-shopping-list.txt`

---

## Summary

The user "mikeylab" on the "mikey-win10-vla" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mikey-win10-vla` by the user `mikeylab`. The device was isolated, and the user's direct manager was notified.

---
