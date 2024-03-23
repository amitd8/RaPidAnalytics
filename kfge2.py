
# Map a dictionery full of usful process data for later anomaly analysis
def enumeratePslist():
    pps = {}
    with open(".\outputest.txt", "r") as file:
        # Iterate over each line in the file    
        
        for line in file:
           if line.strip() and line[0].isdigit():
                a = line.split() 
                pps[a[0]] = [a[1],a[2]]
                    
    return pps
#  pid : [ppid,imagename]

def printhirerchyhelper(pid,apps):
    if pid in apps:
        return str(printhirerchy(apps[pid][0],apps)) + " --> " + apps[pid][1]+"("+pid+")"
def printhirerchy(pid,apps):
        return str(printhirerchyhelper(pid,apps)).replace("None --> ","")

def findlegitpids():
     print ("wow")

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
                    analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsass.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" 
        elif process == "services.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough services.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" 
        elif process == "wininit.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough wininit.exe process detected! Pid: "+pid+", Wininit.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"
        elif process == "csrss.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough csrss.exe process detected! Pid: "+pid+", csrss.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"
        elif process == "svchost.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "services.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough svchost.exe process detected! Pid: "+pid+", abnormal Parent (not services.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n"   
        elif process == "RuntimeBroker.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough RuntimeBroker.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" 
        elif process == "taskhostw.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "svchost.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough taskhostw.exe process detected! Pid: "+pid+", abnormal Parent (not svchost.exe): "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" 
        elif process == "winlogon.exe":
            for pid in pids:
                if apps[pid][0] in apps:
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough winlogon.exe process detected! Pid: "+pid+", winlogon.exe usualy has an exited parent ,abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+")\n"
        elif process == "lsaiso.exe":
            for pid in pids:
                if apps[pid][0] not in apps:
                    h = (printhirerchy(pid,apps))
                    analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", None-Existing Parent: "+ apps[pid][0]+ "\n"
                else:
                    if apps[apps[pid][0]][1] != "wininit.exe":
                        h = (printhirerchy(pid,apps))
                        analysis += "   "+h+"\n"+"   Rough lsaiso.exe process detected! Pid: "+pid+", abnormal Parent: "+ apps[apps[pid][0]][1]+" ("+apps[pid][0]+") "+ "\n" 
     if analysis.strip():  
        lines = analysis.split('\n')  
        lines.insert(0, "Process Masquerading detections (T1036):")  
        return '\n'.join(lines)  
     else:
        return analysis  
                         
    
                        

          
          

# def for powershell anomalies
# ppidname = apps[apps[pid][0]][1]


x = enumeratePslist()
print (DetectMasquerading(x))


        

