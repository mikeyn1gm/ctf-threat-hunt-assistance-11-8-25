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

**Actions and Thought Process:**
Based on the initial information I have, I searched within DeviceFileEvents between the time range of October 1st to October 15th for any devices with any activity relegated to "helpdesk" naming in terms of files with such a filename or directory locations that could have the name as well. I remembered the details from intel that this target device might be under the ownership of an intern end user. With this in mind, I had no doubt when I quickly narrowed down my search to a device with the name `"gab-intern-vm"`.

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
I searched within DeviceProcessEvents for any suspicious commands that were ran between 10/1/25 to 10/15/25 under the device name of "gab-intern-vm" (I will be using this device name frequently for KQL queries going forward along with this time range or a tighter one to maintain a focused view to the events that took place). With the information I have so far, I narrowed down further to potential inclusions of the "Downloads" folder in the command execution to investigate. I sorted the results to find the earliest strange execution that stood out to me. I noticed `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1` which caught my attention.

**Note:** The "tolower" line in the query below makes a case-insensitive search for a provided string by making all results lowercase. This is to capture all results regardless on whether a "Downloads" folder was named "Downloads", "downloads", "DOWNLOADS" and etc...

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
With this information, I initially thought about searching within DeviceFileEvents but opted for checking DeviceProcessEvents for any executions involving any files with "tamper" in the filename. I also decided to tighten up the time range down to 10/9 to 10/15 since the previous event occurred on 10/9 at 12:22PM. I found `DefenderTamperArtifact.lnk` immediately as a file involved with an execution from the suspected device.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:22:27Z) .. datetime(2025-10-15T00:00:00Z))  
| where FileName contains "tamper"
| order by TimeGenerated desc 

```
<img width="1616" height="395" alt="image" src="https://github.com/user-attachments/assets/71a63541-84cb-4e0e-b54f-d5ed2a04c42c" />

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
With the information provided, I figured this was probably related to clipboard access. I searched DeviceProcessEvents and filtered for commands that included “clip,” “Get-Clipboard,” or anything similar. That quickly surfaced a single PowerShell one-liner trying to read the clipboard. It stood out because it was a quick, low-effort probe that didn’t match normal activity.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:22:27Z) .. datetime(2025-10-15T00:00:00Z))  
| where ProcessCommandLine has_any ("clip", "Get-Clipboard", "clipboard")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1632" height="406" alt="image" src="https://github.com/user-attachments/assets/a1d835f9-e684-48cc-82a3-d976064f84bc" />

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
I searched DeviceProcessEvents for anything in the command line containing “qwi” during the main activity window. I sorted the results by time so I could see when the recon actually happened. The last execution of `qwinsta.exe` stood out immediately, giving me the timestamp of the final recon attempt which occurred on 10/9/25 at 12:51PM. I right clicked the date and time for this result and clicked on "Copy value" so I can copy the desired format for submission which was `2025-10-09T12:51:44.3425653Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:22:27Z) .. datetime(2025-10-15T00:00:00Z))  
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1632" height="402" alt="image" src="https://github.com/user-attachments/assets/7befc4c8-c70e-4806-ac63-d8d5122a8854" />

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
For this one I focused on any commands that looked like the attacker was checking storage or shares. With the mention of “storage assessment” in the information provided, I filtered DeviceProcessEvents for things like net view, net use, Get-PSDrive, and wmic logicaldisk, then tightened the time window to the activity on 10/9. Two commands popped up back-to-back, but the earliest one performing actual storage enumeration was the wmic call. It seems to show the attacker pulling disk names, free space, and size, which lines up perfectly with a storage-mapping step. This gave me the first CLI parameter used which was `"cmd.exe" /c wmic logicaldisk get name,freespace,size`.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:40:00Z) .. datetime(2025-10-09T13:00:00Z))  
| where ProcessCommandLine has_any ("net view","net use","Get-PSDrive","wmic logicaldisk","Get-SmbShare","dir \\\\")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1616" height="391" alt="image" src="https://github.com/user-attachments/assets/99342cac-e772-41d2-9c2d-e961800131e2" />

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
The details stated “session,” so I figured something like nslookup or a quick interface query was involved. I filtered DeviceProcessEvents by the host and narrowed the time window to when the earlier flags took place. Then I searched for commands containing things like "ping", "nslookup", "Test-NetConnection", or "curl" to catch any basic network validation. Only two events showed up with both of them making a bogus nslookup call. I checked the initiating parent process and saw that the suspicious lookup ultimately came from `RuntimeBroker.exe`, which stood out immediately since that’s not normal for nslookup activity.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:51:00Z) .. datetime(2025-10-09T12:55:00Z))  
| where ProcessCommandLine has_any ("ping","nslookup","Test-NetConnection","curl")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc 

```
<img width="1473" height="375" alt="image" src="https://github.com/user-attachments/assets/69c238d6-ee0f-473e-8e21-a5a93e8fa2b2" />

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
This portion of the investigation was about finding any recon attempts that checked for active user sessions, so I focused on commands like qwinsta, quser, or query user. I filtered DeviceProcessEvents for anything containing those keywords within the same tight time window as the previous findings. Once the results showed up, I just looked for the event that matched the recon behavior and checked the InitiatingProcessUniqueId column. The earliest one tied to the suspicious activity stood out immediately, so I grabbed that value.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T12:55:00Z))  
| where ProcessCommandLine has_any ("qwinsta", "query user", "quser")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc 

```
<img width="1633" height="407" alt="image" src="https://github.com/user-attachments/assets/76bcf2f7-5c9a-464a-b46c-8b2feaf54626" />

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
I figured the new details pointed straight at the use of something like tasklist, so I narrowed my search in DeviceProcessEvents to anything with "task" in the command line. I continue to keep the same time window as the previous findings to stay consistent with the attacker’s activity timeline. Once the results popped up, `tasklist.exe` stood out immediately as the clearest example of a full process-enumeration event. It matched the suspected details perfectly and was tied to suspicious parent processes, so that confirmed it was the right one.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T12:55:00Z))  
| where ProcessCommandLine contains "task"
| project TimeGenerated, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc 

```
<img width="1477" height="376" alt="image" src="https://github.com/user-attachments/assets/724ed8f1-a08c-462c-b94b-790437b821f8" />

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
To figure out when the privilege-checking started, I focused on anything that used the keyword "who", since the details seemed to point me in that direction. I filtered DeviceProcessEvents for commands like whoami and grouped the results by earliest timestamp. Once I sorted everything ascending, the very first event that showed up was a cmd.exe call running `whoami /groups` on 10/9/25 at 12:52:14PM, which made it clear this was the attacker’s initial privilege probe. I right clicked the date and time for this result and clicked on "Copy value" so I can copy the desired format for submission which was `2025-10-09T12:52:14.3135459Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T12:55:00Z))  
| where ProcessCommandLine contains "who"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc 

```
<img width="1623" height="395" alt="image" src="https://github.com/user-attachments/assets/ac74c3cf-332b-4716-904c-2a96e66c6a3d" />

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
I filtered DeviceNetworkEvents down to outbound traffic on the compromised VM and limited the window to the initial activity period. Since the details stating something about “support,” I expected something like a connectivity probe or Microsoft domain. I sorted everything oldest-to-newest and looked for the very first outbound request that was marked as a remote session initiation. The earliest hit was a PowerShell-initiated connection out to `www.msftconnecttest.com`, which matched the behavior I was expecting.

**Query used to locate events:**

```kql
DeviceNetworkEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:00:00Z))  
| where IsInitiatingProcessRemoteSession == true
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, IsInitiatingProcessRemoteSession
| order by TimeGenerated asc 

```
<img width="1456" height="367" alt="image" src="https://github.com/user-attachments/assets/b5abb04e-a579-4bd7-ad8e-f1f51bdfde1e" />

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
The latest details directed me to trying to find where the attacker may have first dropped a staged artifact. I switched over to DeviceFileEvents and filtered specifically for FileCreated actions involving archive formats (any files with .zip, .rar, or .7z as the file extension). Because staging usually happens late in the chain, I kept my time range tight around the period when other recon and collection steps were happening. As soon as I ran the query, I saw `ReconArtifacts.zip` pop up twice, one in the user’s Documents folder and one in `C:\Users\Public`. Having in mind to find the first drop location, I sorted ascending with the results and grabbed the earliest folder path to find `C:\Users\Public\ReconArtifacts.zip`

**Query used to locate events:**

```kql
DeviceFileEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:00:00Z))  
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".rar", ".7z")
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc 

```
<img width="1461" height="361" alt="image" src="https://github.com/user-attachments/assets/a25e6edb-8bb7-40b4-871d-d49cc3241c9e" />

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
I filtered DeviceNetworkEvents to only show outbound events initiated by PowerShell, and excluded anything with empty IP/URL fields. For this part of the investigation, I added more minutes to the time range to make sure I didn't miss anything. After sorting the results by time, I saw three outbound attempts. The most recent one was a PowerShell call to `httpbin.org` with the IP of `100.29.147.161`.

**Query used to locate events:**

```kql
DeviceNetworkEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z))  
| where RemoteIP != "" or RemoteUrl != ""
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, InitiatingProcessParentFileName
| order by TimeGenerated asc

```
<img width="1477" height="353" alt="image" src="https://github.com/user-attachments/assets/3ec8b676-0893-4036-a293-b1a8bdc9f509" />

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
To track down the persistence mechanism, I focused on anything involving schtasks, since that’s usually the easiest way an actor ensures their tooling reruns after login. I filtered within the same tight timeframe and looked for task creation or queries by name. Right away, I saw a scheduled task being created with `/Create` and then immediately queried with `/Query`. The task name involved stood out clearly as `SupportToolUpdater`.

**Query used to locate events:**

```kql
DeviceProcessEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z))  
| where ProcessCommandLine contains "schtasks"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1467" height="352" alt="image" src="https://github.com/user-attachments/assets/d623fcfa-fe9b-4407-a50b-eadbb7ed406c" />

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
With suspicions of registry or startup-area modifications, I went straight to investigating in DeviceRegistryEvents. The details noted the presence of something with **"RemoteAssistUpdater"**, so I filtered for that name directly. The registry value name `RemoteAssistUpdater` was shown in the results along with the PowerShell command that set it, confirming it as the fallback autorun.

**Note:** DeviceRegistryEvents was not returning results with my query as intended for this exercise. The image of the results were provided by the CTF admin after escalation. In his results you'll noticed he has "Timestamp" instead of "TimeGenerated" for his first column. He was using Microsoft Defender for Endpoint (MDE) when he obtained those results. **You must use "TimeStamp" for MDE and "TimeGenerated" for Log Analytics workspaces.**

**Query used to locate events:**

```kql
DeviceRegistryEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T9:00:00Z) .. datetime(2025-10-09T13:10:00Z))  
| where RegistryValueName contains "RemoteAssistUpdater"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryValueType
| order by TimeGenerated asc 

```
<img width="1879" height="240" alt="image" src="https://github.com/user-attachments/assets/c086172f-88af-4d6d-816f-71df6321900d" />

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
To track down the planted narrative file, I first looked for any suspicious file modifications in DeviceFileEvents around the time of the other activity. I ran the first query filtering on FileModified to see if anything stood out. In those results, the only interesting file related to the operation was `SupportChat_log.txt`. This text file wasn't what we were looking for but it still piqued my interest. I switched to searching for filename patterns containing "SupportChat" to check for any shortcut or artifact the actor might’ve interacted with directly with similar naming. That’s where the `SupportChat_log.lnk` file popped up among the similar text file results which is what we needed to find since it was the user-facing file the actor left behind on purpose.

**Queries used to locate events:**

```kql
//1st Query
DeviceFileEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z)) 
| where ActionType == "FileModified"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

//2nd Query
DeviceFileEvents   
| where DeviceName == "gab-intern-vm"  
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z))  
| where FileName contains ("SupportChat")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc 

```
(1st Query Results)
<img width="1467" height="365" alt="image" src="https://github.com/user-attachments/assets/b4221b88-2e35-42e4-884d-6ca0eab2c101" />
(2nd Query Results)
<img width="1470" height="376" alt="image" src="https://github.com/user-attachments/assets/4803d6f4-5155-456e-87b9-55fa7cf2c262" />

**Answer:**
`SupportChat_log.lnk`

---






## Chronological Event Timeline 

### 0. Early Persistence – Autorun Value Created

- **Timestamp:** `2025-10-09T09:01:55.0000000Z`
- **Event:** A registry autorun value named `RemoteAssistUpdater` is created.
- **Action:** Registry value creation detected.
- **Registry Key:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- **Comment:** Establishes early PowerShell-based persistence before all other activity.

### 1. Suspicious Helpdesk File Appears

- **Timestamp:** `2025-10-09T12:05:38.7360000Z`
- **Event:** File `Helpdesk_247.txt` created in `Downloads`.
- **Action:** File creation detected.
- **Comment:** First indicator that `gab-intern-vm` is the suspicious endpoint.

### 2. Execution of Support Tool Script

- **Timestamp:** `2025-10-09T12:22:27.0000000Z`
- **Event:** Malicious script `SupportTool.ps1` executed.
- **Action:** PowerShell script execution detected.
- **Command:** `powershell.exe -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1`
- **Comment:** Initial malicious execution.

### 3. Fake Defender Tamper Artifact Dropped

- **Timestamp:** `2025-10-09T12:34:59.1260000Z`
- **Event:** Creation of `DefenderTamperArtifact.lnk`.
- **Action:** File creation detected.
- **Comment:** Placed to support a false “Defender tamper” narrative.

### 4. Clipboard Access Attempt

- **Timestamp:** `2025-10-09T12:50:39.9550000Z`
- **Event:** PowerShell attempts to read the clipboard.
- **Action:** Process execution detected.
- **Comment:** A quick probe for sensitive data.

### 5. User Session Enumeration

- **Timestamps:**
  - `2025-10-09T12:50:58.3170000Z` – `cmd.exe /c quser`
  - `2025-10-09T12:50:58.3640000Z` – `quser.exe`
  - `2025-10-09T12:50:59.3440000Z` – `cmd.exe /c qwinsta`
- **Event:** Interactive session discovery.
- **Action:** Process execution detected.
- **Comment:** Used to identify logged-in users.

### 6. Storage Surface Mapping

- **Timestamps:**
  - `2025-10-09T12:51:17.3660000Z` – `cmd.exe /c net use`
  - `2025-10-09T12:51:18.3840000Z` – `wmic logicaldisk get name,freespace,size`
- **Event:** System and share enumeration.
- **Action:** Recon activity detected.
- **Comment:** Mapping available storage for collection and staging.

### 7. Connectivity & Name Resolution Check

- **Timestamps:**
  - `2025-10-09T12:51:32.5900000Z` – `cmd.exe /c nslookup helpdesk-telemetry.remoteassist.invalid`
  - `2025-10-09T12:51:32.6220000Z` – `nslookup`
- **Event:** DNS query to attacker-themed domain.
- **Action:** Network resolution detected.
- **Comment:** Confirms outbound connectivity.

### 8. Session Refresh Check

- **Timestamp:** `2025-10-09T12:51:44.3420000Z`
- **Event:** `qwinsta.exe` executed.
- **Action:** Session enumeration.
- **Comment:** Actor reconfirms session state.

### 9. Runtime Application Inventory (Tasklist)

- **Timestamps:**
  - `2025-10-09T12:51:57.6390000Z` – `cmd.exe /c tasklist /v`
  - `2025-10-09T12:51:57.6860000Z` – `tasklist.exe`
- **Event:** Process inventory enumeration.
- **Action:** Recon activity detected.
- **Comment:** Identifies running applications and security tools.

### 10. Outbound Connectivity Confirmation

- **Timestamp:** `2025-10-09T12:52:10.4880000Z`
- **Event:** `explorer.exe` initiates outbound web request.
- **Action:** Network connection detected.
- **Comment:** Confirms ability to reach the internet.

### 11. Privilege Surface Check

- **Timestamp:** `2025-10-09T12:52:14.3135459Z`
- **Event:** `cmd.exe /c whoami /groups`
- **Action:** Privilege enumeration detected.
- **Comment:** Actor checks available user permissions.

### 12. Additional Network Activity (Normal Browser Traffic)

- **Timestamps:**
  - `2025-10-09T12:56:44.8370000Z` – Edge outbound
  - `2025-10-09T12:57:07.8210000Z` – OneNote CDN access
  - `2025-10-09T12:57:43.8190000Z` – More Edge traffic
- **Event:** Additional outbound communication.
- **Action:** Network activity detected.
- **Comment:** Blends in among normal traffic.

### 13. Bundling / Staging of Recon Artifacts

- **Timestamps:**
  - `2025-10-09T12:58:17.4360000Z` – `ReconArtifacts.zip` created (Public)
  - `2025-10-09T12:59:05.6800000Z` – Another ZIP created (Documents)
  - `2025-10-09T12:59:51.4590000Z` – ZIP moved into Recycle Bin path
- **Event:** Data consolidation.
- **Action:** File creation detected.
- **Comment:** Staging for later exfiltration.

### 14. Outbound Transfer Attempt (Simulated Exfiltration)

- **Timestamps:**
  - `2025-10-09T13:00:39.3930000Z` – Connection to `example.com`
  - `2025-10-09T13:00:40.0450000Z` – Connection to `httpbin.org` (IP: `100.29.147.161`)
- **Event:** Outbound POST-style test connections.
- **Action:** Egress activity detected.
- **Comment:** Final exfiltration attempt.

### 15. Scheduled Re-Execution Persistence Added

- **Timestamps:**
  - `2025-10-09T13:01:28.7700000Z` – Scheduled task created
  - `2025-10-09T13:01:29.7810000Z` – Scheduled task queried
- **Event:** Task `SupportToolUpdater` created under ONLOGON trigger.
- **Action:** Persistent autorun via Task Scheduler created.
- **Comment:** Ensures malicious script re-runs on logon.

### 16. Planted Narrative Artifact – Support Chat Log

- **Timestamps:**
  - `2025-10-09T13:02:41.5690000Z` – `SupportChat_log.lnk` created
  - `2025-10-09T13:03:11.5160000Z` – `SupportChat_log.txt` accessed
- **Event:** False explanatory “support chat” files created and opened.
- **Action:** File creation and file access detected.
- **Comment:** Used to misdirect investigators and justify suspicious activity.

---

## Summary

The user account on "gab-intern-vm" executed a malicious support-themed script from the Downloads folder and proceeded through a full attack lifecycle including reconnaissance, credential and session discovery, storage enumeration, connectivity tests, artifact staging, outbound transfer attempts, and the establishment of multiple persistence mechanisms. The actor also planted misleading “support” and “Defender tamper” artifacts to mask malicious intent. Overall, the activity reflects deliberate execution, staging, and persistence actions designed to mimic legitimate support operations while enabling continued unauthorized access.

---

## Response Taken

Malicious PowerShell activity, persistence mechanisms, and simulated exfiltration attempts were confirmed on endpoint `gab-intern-vm`. The device was isolated, user access was restricted, and management was notified for further action.

---
