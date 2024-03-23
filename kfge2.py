import re, sys
# Map a dictionery full of parsed process data for later anomaly analysis
totalanalysis = ""
def enumeratePslist():
    pps = {}
    with open(".\\outputs\\psscan.txt", "r",encoding='utf-8') as file:
        # Iterate over each line in the file mapping data to dict  
        for line in file:
           if line.strip():
                # check if it pslist input
                if re.match(r'^\s*(?!0)\d', line):
                    a = line.split() 
                    pps[a[0]] = [a[1],a[2]]
                # check if psscan input
                elif re.match(r'^0x', line):
                    a = line.split() 
                    pps[a[2]] = [a[3],a[1]]
    if pps:            
        return pps                
    else:  return "Error in data input"
#  pid : [ppid,imagename]

def printhirerchyhelper(pid,apps):
    if pid in apps:
        return str(printhirerchy(apps[pid][0],apps)) + " --> " + apps[pid][1]+"("+pid+")"
def printhirerchy(pid,apps):
        return str(printhirerchyhelper(pid,apps)).replace("None --> ","")

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
     ps = ["lsass.exe","services.exe","wininit.exe","csrss.exe","RuntimeBroker.exe","taskhostw.exe","svchost.exe","winlogon.exe","lsaiso.exe"]
     for process in ps:
        count, pids = count_occurrences(apps,process)
        if process == "lsass.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "services.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "wininit.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough wininit.exe process detected! Pid: "+pid+", Wininit.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"+"\n"
        elif process == "csrss.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough csrss.exe process detected! Pid: "+pid+", csrss.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"+"\n"
        elif process == "svchost.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "services.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", abnormal Parent (not services.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n"+"\n"
        elif process == "RuntimeBroker.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "taskhostw.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" +"\n"
        elif process == "winlogon.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough winlogon.exe process detected! Pid: "+pid+", winlogon.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"+"\n"
        elif process == "lsaiso.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"+"\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n"+"\n" 
     if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "Process Masquerading detections (T1036):")  
        return '\n'.join(lines)  
     else:
        return analysis
                         
def DetectPersistences(apps):
    analysis = ""
    #winlogon Dll Helper
    c,winlo = count_occurrences(apps,"winlogon.exe")   
    uiproc = winlo[0]
    for pid, a in apps.items():
        if a[0] == uiproc and a[1] != "userinit.exe":
            h = (printhirerchy(pid,apps))
            analysis += "   "+h+"\n"+"   (High) Winlogon Persistence detected! (T1547) Winlogon executed Unfimilier Process Pid: "+pid+ "\n"+"\n" 
    # Schedule tasks related Executions
    c,schpid = count_occurrences(apps,"schtasks.exe")   
    for spid in schpid:
        h = (printhirerchy(spid,apps))
        analysis += "   "+h+"\n"+"   (Low) Schedule task Persistence detected.(T1053) "+spid+ "\n"+"\n" 
    
    
    
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "Persistence detections:")  
        return '\n'.join(lines)  
    else:
        return analysis
            


def DetectDiscovery(apps):
    analysis = ""
    proc = ["findstr.exe","net.exe","ping.exe","nmap.exe","hostname.exe","whoami.exe"]
    for process in proc:
        c,pids = count_occurrences(apps,process)   
        for dis in pids:
            h = (printhirerchy(dis,apps))
            analysis += "   "+h+"\n"+"   (Low) Might be an attacker learning about the enviroment.(T1053) "+dis+ "\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "Persistence detections:")  
        return '\n'.join(lines)  
    else:
        return analysis+ "\n   Clean!"       

def DetectLOLBAS(apps):
    analysis = ""
    proc = ["powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","wmic.exe"]
    for process in proc:
        c,pids = count_occurrences(apps,process)   
        for dis in pids:
            h = (printhirerchy(dis,apps))
            analysis += "   "+h+"\n"+"   (Medium) LOLBAS often used by attackers. "+dis+ "\n"+"\n" 
    if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "Suspicious LOBAS detections (T1059):")  
        return '\n'.join(lines)  
    else:
        return analysis+ "\n   Clean!"
    print ("")                  

# ppidname = apps[apps[pid][0]][1]
# def 

x = enumeratePslist()
print (DetectMasquerading(x))
print (DetectDiscovery(x))
print (DetectPersistences(x))
print (DetectLOLBAS(x))

 
        

