
# Map a dictionery full of usful process data for later anomaly analysis
def enumeratePslist():
    pps = {}
    with open("C:\\Users\\Blue\\Desktop\\PSlistAnalytics\\outputest.txt", "r") as file:
        # Iterate over each line in the file
        
        for line in file:
           if line.strip() and line[0] not in ("V", "P"):
                a = line.split() 
                pps[a[0]] = [a[1],a[2]]
                    
    return pps
print (enumeratePslist())
def printhirerchy(pid):
    x = []
    

