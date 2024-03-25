## **Welcome to RaPidAnalytics!** 

RaPidAnalytics is a Python script created to automate Memory Investigations on Windows operating systems, by extracting information about running processes using Volatility3's Pslist/Psscan modules or Powershell. 
The script detects anomalies and provides valuable alerts & insights based on the collected data.

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
python3 ./volatility3/vol.py -f ./memtest.mem windows.pslist | python3 ./PSlistAnalytics/kfge2.py
#Example output
Suspicious LOLBAS detections (T1059):canning finished
   powershell.exe(508)
   (Medium) powershell.exe(508) is often used by attackers

   powershell.exe(508) --> powershell.exe(3316)
   (Medium) powershell.exe(3316) is often used by attackers

Persistence detections:
   winlogon.exe(6456) --> notepad.exe(4808)
   (High) Winlogon Persistence detected! (T1547) Winlogon executed Unfimilier Process Pid: 4808
```
