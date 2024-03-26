import re, sys

# Map a dictionery full of parsed process data for later anomaly analysis. PIDFile - psscan/pslist/Win32_process.readlines() saved as a variable
def EnumerateProcessData(PIDFile):
    processdict = {}    #  processdict - Dictionary that will be built in the following format - pid : [ppid,imagename]
    for line in PIDFile:
        if line.strip():
            # check line for pslist/Win32_process format (first column is PID), enrich dictionary using the current line
            if re.match(r'^\s*(?!0)\d', line): 
                a = line.split() 
                processdict[a[0]] = [a[1],a[2]] 
            # check line for psscan format (first column is Physical memory location), enrich dictionary using the current line
            elif re.match(r'^0x', line):
                a = line.split() 
                processdict[a[2]] = [a[3],a[1]] 
    if processdict: # Check if the dictionary was enriched successfully
        for k,v in processdict.items():
            if re.match(r'^-?\d+\.?\d*$',k) and  re.match(r'^-?\d+\.?\d*$',v[0]):
                return processdict
            else:
                return "Parsing Error: Input data not in the right format"              
    else:  
        return "Parsing Error: Input data not in the right format"

# Printing a given process pid entire hierarchy 
def printhierarchyhelper(pid,apps):
    if pid in apps:
        #print (pid)
        return str(printhierarchy(apps[pid][0],apps)) + " --> " + apps[pid][1]+"("+pid+")"
def printhierarchy(pid,apps):
        return str(printhierarchyhelper(pid,apps)).replace("None --> ","")

def count_occurrences(apps, pname):
    count = 0
    pids = []
    for pid, name in apps.items():
        if name[1] == pname:
            count += 1
            pids.append(pid)
    return count, pids

def DetectMasquerading(apps):
     analysis = ""
     ps = ["lsass.exe","services.exe","wininit.exe","csrss.exe","RuntimeBroker.exe","taskhostw.exe","svchost.exe","winlogon.exe","lsaiso.exe","explorer.exe"]
     for process in ps:
        count, pids = count_occurrences(apps,process)
        if process == "lsass.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "services.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "wininit.exe":
            if count > 1:
                for pid in range(1,len(pids)):
                    print (pids[pid])
                    if apps[pids[pid]][0] in apps:
                            h = (printhierarchy(pids[pid],apps))
                            analysis += "   "+h+"\n"+"   Rough wininit.exe process detected! Pid: "+pids[pid]+", wininit.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pids[pid]][0]][1]+" ("+apps[apps[pids[pid]][0]][0]+")\n"+"\n"
        elif process == "csrss.exe":
            if count > 1:
                for pid in range(1,len(pids)):
                    if apps[pids[pid]][0] in apps:
                            h = (printhierarchy(pids[pid],apps))
                            analysis += "   "+h+"\n"+"   Rough csrss.exe process detected! Pid: "+pids[pid]+", csrss.exe usualy has an exited parent ,abnormal Parent: "+apps[apps[pids[pid]][0]][1]+" ("+apps[apps[pids[pid]][0]][0]+")\n"+"\n"
        elif process == "svchost.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "services.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", abnormal Parent (not services.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n"+"\n"
        elif process == "RuntimeBroker.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "taskhostw.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "winlogon.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough winlogon.exe process detected! Pid: "+pid+", winlogon.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"+"\n"
        elif process == "lsaiso.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhierarchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhierarchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n"+"\n" 
        elif process == "explorer.exe":
            if count > 1:
                for pid in range(1,len(pids)):
                    if apps[pids[pid]][0] in apps:
                            h = (printhierarchy(pids[pid],apps))
                            analysis += "   "+h+"\n"+"   Rough explorer.exe process detected! Pid: "+pids[pid]+", explorer.exe usualy has an exited parent ,abnormal Parent: "+apps[apps[pids[pid]][0]][1]+" ("+apps[apps[pids[pid]][0]][0]+")\n"+"\n"
     if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Process Masquerading detections (T1036):")  
        return '\n'.join(lines)  
     else:
        return analysis
                         
def DetectPersistences(apps):
    analysis = ""
    #winlogon Dll Helper
    c,winlo = count_occurrences(apps,"winlogon.exe")   
    uiproc = winlo[0]
    for pid, a in apps.items():
        if a[0] == uiproc and (a[1] not in ("userinit.exe", "dwm.exe","fontdrvhost.exe")):
            h = (printhierarchy(pid,apps))
            analysis += "   "+h+"\n"+"   (High) Winlogon Persistence detected! (T1547) Winlogon executed Unfimilier Process Pid: "+pid+ "\n"+"\n" 
    # Schedule tasks related Executions
    c,schpid = count_occurrences(apps,"schtasks.exe")   
    for spid in schpid:
        h = (printhierarchy(spid,apps))
        analysis += "   "+h+"\n"+"   (Low) Schedule task Persistence detected.(T1053) "+spid+ "\n"+"\n" 
    
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Persistence detections:")  
        return '\n'.join(lines)  
    else:
        return analysis
            


def DetectDiscovery(apps):
    analysis = ""
    proc = ["findstr.exe","net.exe","ping.exe","nmap.exe","hostname.exe","whoami.exe"]
    for process in proc:
        c,pids = count_occurrences(apps,process)   
        for dis in pids:
            h = (printhierarchy(dis,apps))
            analysis += "   "+h+"\n"+"   (Low) "+process+" ("+dis+")Might be an attacker learning about the enviroment (T1053) ""\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Discovery detections:")  
        return '\n'.join(lines)  
    else:
        return analysis     

def DetectLOLBAS(apps):
    analysis = ""
    proc = ["powershell.exe","wscript.exe","cscript.exe","mshta.exe","wmic.exe"]
    for process in proc:
        c,pids = count_occurrences(apps,process)   
        for dis in pids:
            h = (printhierarchy(dis,apps))
            analysis += "   "+h+"\n"+"   (Medium) "+process+"("+dis+") is often used by attackers " "\n"+"\n"
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Suspicious LOLBAS detections (T1059):")  
        return '\n'.join(lines)  
    else:
        return analysis

def DetectPUA(apps):
    analysis = ""
    proc = ["psexec.exe","bloodhound.exe"]
    for process in proc:
        c,pids = count_occurrences(apps,process)   
        for dis in pids:
            h = (printhierarchy(dis,apps))
            analysis += "   "+h+"\n"+"   (Low) "+process+" is often used by attackers. "+dis+ "\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "- Suspicious Tool Invocation:")  
        return '\n'.join(lines)  
    else:
        return analysis
                     

# ppidname = apps[apps[pid][0]][1]

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

    totalanalysis = ""
    processdict   =  EnumerateProcessData(inputdata)
    totalanalysis += DetectMasquerading(processdict)
    totalanalysis += DetectLOLBAS(processdict)
    totalanalysis += DetectDiscovery(processdict)
    totalanalysis += DetectPersistences(processdict)

    if totalanalysis == "":
        return "The modules used didn't detect suspicous activity"
    else:
        return "\nRaPidAnalytics Detections:" +"\n\n"+totalanalysis
    
if __name__ == "__main__":
    print (Analysis() )
        

