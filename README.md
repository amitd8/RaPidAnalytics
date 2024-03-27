# **Welcome to RaPidAnalytics!** 
RaPidAnalytics is a Python script aimed to simplify Windows memory investigations. It quickly analyses outputs of process data from Volatility3's Pslist/Psscan modules or in real-time investigations by parsing PowerShell command's output.

**With a focus on anomaly detection, it promptly provides alerts and insights, making DFIR investigators' lives easier.**
``` 
RaPidAnalytics Detections:

- Process Masquerading detections (T1036):

   explorer.exe(13548) --> svchost.exe(14720)
   Rough svchost.exe process detected! Pid: 14720, abnormal Parent (not services.exe): explorer.exe (13548)

- Suspicious LOLBAS detections (T1059):
   explorer.exe(13548) --> powershell.exe(22928)
   (Medium) powershell.exe(22928) is often used by attackers

- Discovery detections:
   cmd.exe(1248) --> nmap.exe(1356)
   (Low) nmap.exe(1356) Might be an attacker learning about the enviroment (T1053) 
```
## Modules
#### Process Masquarding Detection (High) - 
The main module of the script, in which we use Windows OS' process genealogy as a baseline to detect inconsistencies in Parent & Child processes hierarchies.
As seen in the following [SANS poster](https://sansorg.egnyte.com/dl/oQm41D67D6), there are consistent parent processes to most OS' essential processes. 
Using that information, we can detect an attacker's attempt to run malware which masks itself as a legit windows process.
#### LOLBAS detection (Medium) -
Alerts about seen [Living of the land binaries (LOLBAS)](https://github.com/LOLBAS-Project/LOLBAS/blob/master/README.md), that are commonly used by attackers.
#### Discovery (Low) -
Alerts about tools that are commonly used by attackers to learn about the enviroment they're currently in, and are less likely to be used by regular users.
#### Persistence - 
Schedule tasks running (low)- Outputs process hierarchies that schtasks.exe were included in.

Startup Processes (Medium)- Detects processes created by winlogon.exe, indicates they run on system startup

## Using RaPidAnalytics:
#### -  Running with stdin from volatility 3 (For both pslist/psscan) 
``` python
# Script Syntax for volatility3 input from stdin (pslist/psscan)
python3 ./volatility3/vol.py -f ./memtest.mem windows.pslist | python3 ./RaPidAnalytics/RaPidAnalytics.py

```
#### -  Live investigation Usage (Powershell)
``` powershell
# Syntax for live Analysis using Powershell **Using other command than gcim or changing fields order will result in corrapted data**
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
