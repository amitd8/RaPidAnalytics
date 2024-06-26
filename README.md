# **Welcome to RaPidAnalytics!** 
RaPidAnalytics is a Python script aimed to simplify Windows memory investigations. It quickly analyzes outputs of process data from Volatility3's Pslist/Psscan modules or in real-time investigations by parsing formatted PowerShell output. It then provides simple insights and alerts that may indicate malicous activity.

**With a focus on anomaly detection, it promptly provides alerts and insights, making DFIR investigators' lives easier.**
``` 
RaPidAnalytics Detections:

- Process Masquerading detections (T1036):
   explorer.exe(14480) --> svchost.exe(20700)
   Suspicous svchost.exe(20700) process detected! unfamiliar Parent detected: explorer.exe (14480)

- Suspicious LOLBAS detections (T1059):
   explorer.exe(14480) --> chrome.exe(20808) --> mshta.exe(19964)
   (Medium) mshta.exe(19964) is a LOLBAS commonly used used by attackers

- Persistence detections:
   schtasks.exe(9808) --> powershell.exe(21020)
   (Low) Schedule task Persistence detected.(T1053) -PID: 21020

- Suspicious Tool Invocation:
   explorer.exe(14480) --> bloodhound.exe(3608)
   (Low) bloodhound.exe(3608) is often used by attackers. 3608
```
## Modules
#### Process Masquarding Detection (High) - 
The main module of the script, in which we use Windows OS' process genealogy as a baseline to detect inconsistencies in Parent & Child processes hierarchies.
As seen in the following [SANS poster](https://sansorg.egnyte.com/dl/oQm41D67D6), there are consistent parent processes to most OS' essential processes. 
Using that information, we can detect an attacker's attempt to run malware which masks itself as a legit windows process.
#### LOLBAS detection (Medium) -
Alerts about seen [Living of the land binaries (LOLBAS)](https://github.com/LOLBAS-Project/LOLBAS/blob/master/README.md), that are commonly used by attackers.
#### Discovery (Low) -
Alerts about tools that are commonly used by attackers to learn about the environment they're currently in, and are less likely to be used by regular users.
#### Persistence - 
Winlogon DLL Helper (Medium)- Detects processes created by winlogon.exe, indicates they run on system startup

Schedule tasks running (low)- Outputs process hierarchies that schtasks.exe were included in.



## Using RaPidAnalytics:
#### -  Running with stdin from volatility 3 (For both pslist/psscan) 
``` python
# Script Syntax for volatility3 input from stdin (pslist/psscan)
python3 ./volatility3/vol.py -f ./memtest.mem windows.pslist | python3 ./RaPidAnalytics/RaPidAnalytics.py

```
#### -  Live investigation Usage (Powershell)
``` powershell
# Syntax for live Analysis using Powershell **Using other command than gcim or changing fields order will result in corrupted data**
Get-CimInstance Win32_Process | select ProcessId, ParentProcessId, name | python.exe .\RaPidAnalytics\RaPidAnalytics.py
```

#### -  Supplying file path to output as argument
``` python
# live investigation- Get-CimInstance Win32_Process | select ProcessId, ParentProcessId, name | Out-File -FilePath procout.txt -Encoding utf8
# Volatility3 output- python3 ./volatility3/vol.py -f ./memtest.mem windows.psscan >> procout.txt

python.exe" .\RaPidAnalytics\RaPidAnalytics.py ./procout.txt
```

##### Running `RaPidAnalytics.py` with no inputs from stdin or as an argument will result with an Error.
``` python
# Error
python.exe" .\RaPidAnalytics\RaPidAnalytics.py
Error: No input data was provided. Provide Process data from stdout or as argument (.\path\to\psscan)
```
