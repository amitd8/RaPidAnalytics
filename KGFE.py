import re

def anomalies():
    importantppids = {}
    x = open("C:\\Users\\Blue\\Desktop\\Volatility\\outputest.txt", "r")
    pdc = 0
    dcount = 0
    pid = 4
    procname = ''
    # Iterate over each line in the file
    for line in x:
        match = re.search(r'^\.+', line)
        if match:
            # Count the number of dots
            dot_count = match.group(0).count(".")
            print(dot_count)


    x.close()

anomalies()