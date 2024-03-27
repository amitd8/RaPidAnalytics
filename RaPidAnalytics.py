import re, sys

# Map a dictionery full of parsed process data for later anomaly analysis. PIDFile - psscan/pslist/Win32_process.readlines() saved as a variable
def EnumerateProcessData(PIDFile):
    PIDsDict = {}    #  PIDsDict - Dictionary that will be built in the following format - pid : [ppid,imagename]
    for line in PIDFile:
        if line.strip():
            # check line for pslist/Win32_process format (first column is PID), enrich dictionary using the current line
            if re.match(r'^\s*(?!0)\d', line): 
                a = line.split() 
                PIDsDict[a[0]] = [a[1],a[2]] 
            # check line for psscan format (first column is Physical memory location), enrich dictionary using the current line
            elif re.match(r'^0x', line):
                a = line.split() 
                PIDsDict[a[2]] = [a[3],a[1]] 
    if PIDsDict: # Check if the dictionary was enriched successfully
        for k,v in PIDsDict.items():
            if re.match(r'^-?\d+\.?\d*$',k) and  re.match(r'^-?\d+\.?\d*$',v[0]):
                return PIDsDict
            else:
                return "Parsing Error: Input data not in the right format"              
    else:  
        return "Parsing Error: Input data not in the right format"

# Printing a given process PID entire hierarchy 
def printhierarchyhelper(pid,PIDsDict):
    if pid in PIDsDict:
        PIDname = PIDsDict[pid][1]
        PPID = PIDsDict[pid][0]
        return str(printhierarchy(PPID,PIDsDict)) + " --> " + PIDname+"("+pid+")"
def printhierarchy(pid,PIDsDict):
        return str(printhierarchyhelper(pid,PIDsDict)).replace("None --> ","")

# Gets a process name, returns amount of times seen in PIDsDict dictionary, and an array of all the pids with this name
def count_occurrences(PIDsDict, pname):
    pids = []
    for pid, ppidname in PIDsDict.items():
        if ppidname[1] == pname:
            pids.append(pid)
    return len(pids), pids

def DetectMasquerading(PIDsDict):
     analysis = ""
     # Monitored for unfimiliar parent processes
     MonitoredProcesses = { "lsass.exe":"wininit.exe", "services.exe":"wininit.exe"
                            ,"RuntimeBroker.exe":"svchost.exe", "taskhostw.exe":"svchost.exe",
                            "svchost.exe":"services.exe","lsaiso.exe":"wininit.exe"
                            }
     # Monitored for not having Exited parent process
     MonitoredProcessesExited = ["wininit.exe","csrss.exe","explorer.exe","winlogon.exe"]
     for process,pprocess in MonitoredProcesses.items():
        count, pids = count_occurrences(PIDsDict,process)   
        for pid in pids:
            parentpid = PIDsDict[pid][0]
            if parentpid not in PIDsDict:
                hierarchy = (printhierarchy(pid,PIDsDict))
                analysis += "   "+hierarchy+"\n"+"   Suspicous "+process+"("+pid+") process detected! None-Existing Parent: "+ parentpid+ "\n"+"\n"
            else:
                if PIDsDict[parentpid][1] != pprocess:
                    parentname = PIDsDict[parentpid][1]
                    hierarchy = (printhierarchy(pid,PIDsDict))
                    analysis += "   "+hierarchy+"\n"+"   Suspicous "+process+"("+pid+") process detected! it has unfimiliar Parent detected: "+ parentname+" ("+parentpid+") "+ "\n"+"\n"

     for process in MonitoredProcessesExited:
        count, pids = count_occurrences(PIDsDict,process)   
        if count > 1:
            for pid in range(1,len(pids)):
                parentpid = PIDsDict[pids[pid]][0]
                if parentpid in PIDsDict:
                        parentname = PIDsDict[parentpid][1]
                        hierarchy = (printhierarchy(pids[pid],PIDsDict))
                        analysis += "   "+hierarchy+"\n"+"   Suspicous "+process+"("+pids[pid]+") process detected! "+process+" usualy has an exited parent ,abnormal Parent: "+ parentname+" ("+parentpid+")\n"+"\n"
                
     if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Process Masquerading detections (T1036):")  
        return '\n'.join(lines)  
     else:
        return analysis
                         
def DetectPersistences(PIDsDict):
    analysis = ""
    #winlogon Dll Helper
    c,winlo = count_occurrences(PIDsDict,"winlogon.exe")   
    uiproc = winlo[0]
    for pid, a in PIDsDict.items():
        if a[0] == uiproc and (a[1] not in ("userinit.exe", "dwm.exe","fontdrvhost.exe")):
            h = (printhierarchy(pid,PIDsDict))
            analysis += "   "+h+"\n"+"   (High) Winlogon Persistence detected! (T1547) Winlogon executed Unfimilier Process Pid: "+pid+ "\n"+"\n" 
    # Schedule tasks related Executions
    c,schpid = count_occurrences(PIDsDict,"schtasks.exe")   
    for spid in schpid:
        h = (printhierarchy(spid,PIDsDict))
        analysis += "   "+h+"\n"+"   (Low) Schedule task Persistence detected.(T1053) "+spid+ "\n"+"\n" 
    
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Persistence detections:")  
        return '\n'.join(lines)  
    else:
        return analysis
            


def DetectDiscovery(PIDsDict):
    analysis = ""
    proc = ["findstr.exe","net.exe","ping.exe","nmap.exe","hostname.exe","whoami.exe"]
    for process in proc:
        c,pids = count_occurrences(PIDsDict,process)   
        for dis in pids:
            h = (printhierarchy(dis,PIDsDict))
            analysis += "   "+h+"\n"+"   (Low) "+process+"("+dis+") Might be an attacker learning about the enviroment (T1053) ""\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Discovery detections:")  
        return '\n'.join(lines)  
    else:
        return analysis     

def DetectLOLBAS(PIDsDict):
    analysis = ""
    proc = ["powershell.exe","wscript.exe","cscript.exe","mshta.exe","wmic.exe"]
    for process in proc:
        c,pids = count_occurrences(PIDsDict,process)   
        for dis in pids:
            h = (printhierarchy(dis,PIDsDict))
            analysis += "   "+h+"\n"+"   (Medium) "+process+"("+dis+") is often used by attackers " "\n"+"\n"
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Suspicious LOLBAS detections (T1059):")  
        return '\n'.join(lines)  
    else:
        return analysis

def DetectPUA(PIDsDict):
    analysis = ""
    proc = ["psexec.exe","bloodhound.exe"]
    for process in proc:
        c,pids = count_occurrences(PIDsDict,process)   
        for dis in pids:
            h = (printhierarchy(dis,PIDsDict))
            analysis += "   "+h+"\n"+"   (Low) "+process+"("+dis+") is often used by attackers. "+dis+ "\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Suspicious Tool Invocation:")  
        return '\n'.join(lines)  
    else:
        return analysis
                     

def Analysis():
    inputdata = None 
     # Checkin if input is from command-line arguments
    if len(sys.argv) > 1:
        input_data = sys.argv[1]
        with open(input_data, "r", encoding='utf-8') as file:
            inputdata = file.readlines()  
    else:
        # Check if input is provided through stdin
        if not sys.stdin.isatty():
            inputdata = sys.stdin.readlines()
    # Check if no data was collected and pring Error
    if not inputdata:
        print("""Error: No input data was provided. Provide Process data from stdin or as an argument (.\\path\\to\\psscan)""")


    PIDsDict   =  EnumerateProcessData(inputdata)
    totalanalysis = ""    
    totalanalysis += DetectMasquerading(PIDsDict)
    totalanalysis += DetectLOLBAS(PIDsDict)
    totalanalysis += DetectDiscovery(PIDsDict)
    totalanalysis += DetectPersistences(PIDsDict)

    if totalanalysis == "":
        return "The modules used didn't detect suspicous activity"
    else:
        return "\nRaPidAnalytics Detections:" +"\n\n"+totalanalysis
    
if __name__ == "__main__":
    print (Analysis() )
        

