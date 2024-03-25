## **Welcome to RaPidAnalytics!** 

RaPidAnalytics is a Python script created to automate Memory Investigations on Windows operating systems by extracting data about running processes in a MemoryImage (using Volatility3's Pslist/Psscan modules) or in an ongoing live investigation (Using Powershell), detecting anomalies and providing valuable alerts & insights based on the collected data.
``` python
RaPidAnalytics Detections:

- Process Masquerading detections (T1036):

   explorer.exe(13548) --> svchost.exe(14720)
   Rough svchost.exe process detected! Pid: 14720, abnormal Parent (not services.exe): explorer.exe (13548)

- Suspicious LOLBAS detections (T1059):
   explorer.exe(13548) --> powershell.exe(22928)
   (Medium) powershell.exe(22928) is often used by attackers

- Discovery detections:
   wininit.exe(1248) --> nmap.exe(1356)
   (Low) nmap.exe(1356)Might be an attacker learning about the enviroment (T1053) 
```
The main module of the script is detecting Process Masquarding Detection - in which we use Windows OS's process gynolagy as a baseline to detect inconsistensies in Parent & Child processes heirerchy.
As seen in the following sans poster, there are a con

# Running RaPidAnalytics:
Running `RaPidAnalytics.py` with no inputs from stdin or as an argument will result with an Error.
``` python
# Script Syntax for -Scope CurrentUser
python.exe" .\PSlistAnalytics\RaPidAnalytics.py
Error: No input data was provided. Provide Process data from stdout or as argument (.\path\to\psscan)
```

#### -  Running with stdin from volatility 3 (For both pslist/psscan) 
``` python
# Script Syntax for volatility3 input from stdin (pslist/psscan)
python3 ./volatility3/vol.py -f ./memtest.mem windows.pslist | python3 ./PSlistAnalytics/RaPidAnalytics.py

```

#### -  Running with stdin from volatility 3 (For both pslist/psscan) 
``` powershell
# Syntax for Analysis from Powershell in live investigation
Get-CimInstance Win32_Process | select ProcessId, ParentProcessId, name | python.exe .\PSlistAnalytics\RaPidAnalytics.py
#Example output
- Suspicious LOLBAS detections (T1059):canning finished
   powershell.exe(508) --> powershell.exe(3316)
   (Medium) powershell.exe(3316) is often used by attackers

- Persistence detections:
   winlogon.exe(6456) --> notepad.exe(4808)
   (High) Winlogon Persistence detected! (T1547) Winlogon executed Unfimilier Process Pid: 4808
```