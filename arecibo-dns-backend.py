#!/usr/bin/python

# Arecibo Backend
# Highly based on xip.io

from  sys import stdin, stdout, stderr
import sqlite3
import time


#### CONFIGURATION ####


version = "v01.1"
domain = "XXXXXXXXXXXXXX
ttl = "432000"
ipaddress = "XXXXXXXXXXX0"
ids = "1"
hostmaster="XXXXXXX@x.xxx"
soa = '%s %s %s' % ("ns1." + domain, hostmaster, ids)


#######################


conn = sqlite3.connect('database.db', check_same_thread=False, timeout=1)
c = conn.cursor()

# Read new line from STDIN
def readLine():
    data = stdin.readline()
    data = data.strip().split('\t')
    return data


# Use when ask for the own domain
def handleIt(qname, ip):
    stdout.write("DATA\t" + qname + "\tIN\tA\t" + ttl + "\t" + ids + "\t" + ip + "\n")
    stdout.write("DATA\t" + qname +  "\tIN\tNS\t" + ttl + "\t" + ids + "\t" + "ns1." + domain + "\n")
    stdout.write("DATA\t" + qname +  "\tIN\tNS\t" + ttl + "\t" + ids + "\t" + "ns2." + domain + "\n")
    stdout.write("END\n")
    stdout.flush()

def handleSoa(qname):
    stdout.write("DATA\t" + qname + "\tIN\tSOA\t" + ttl + "\t" + ids + "\t" + soa + "\n")
    stdout.write("END\n")
    stdout.flush()

def handleNS(qname):
    stdout.write("DATA\t" + qname + "\tIN\tA\t" + ttl + "\t" + ids + "\t" + "\t" + ipaddress + "\n")
    stdout.write("END\n")
    stdout.flush()


# Exfiltration request
def handleX(qname):
    raw = qname.split(".")
    htoken = raw[-4]
    data = '.'.join(raw[:-4])
    stderr.write("      [-] Hextoken: " + htoken + "\n")
    stderr.write("      [-] Data: " + data + "\n")
    stderr.flush()
    c.execute('''SELECT * FROM dnshextokens WHERE htoken=?''', (htoken,))
    row = c.fetchone()
    if row:
        c.execute('''INSERT INTO dnshits(htoken, timestamp, data) VALUES (?, ?, ?)''', (htoken, time.time(), data))
        conn.commit()
    else:
        stderr.write("      /!\\ Invalid HexToken /!\\\n")
        stderr.flush()
    handleIt(qname, ipaddress)


# Dynamic IP request
def handleD(qname):
    raw = qname.split(".")
    if len(raw) != 7:
        stderr.write("    /!\\ Invalid IP /!\\ \n")
        stderr.flush()
        return
    ip = '.'.join(raw[:-3])
    handleIt(qname, ip)




# Welcome message!
def startUp():
    banner = '''

============[CONTACT]===========
      ,-.
     / \  `.  __..-,O
    :   \ --''_..-'.'
    |    . .-' `. '.
    :     .     .`.'
     \     `.  /  ..
      \      `.   ' .
       `,       `.   \\
      ,|,`.        `-.\\
     '.||  ``-...__..-`
      |  |
      |__|  Welcome to Arecibo!
      /||\\
     //||\\\\
    // || \\\\
 __//__||__\\\\__
'--------------'


================================
          CONFIGURATION
================================

'''
    stderr.write(banner)
    stderr.write("[+] Domain: " + domain + "\n")
    stderr.write("[+] IP Address: " + ipaddress + "\n")
    stderr.write("[+] Hostmaster: " + hostmaster + "\n")
    stderr.write("================================\n")
    stderr.flush()

# Lets go!
    readLine()
    stdout.write("Arecibo is up\n")
    stdout.flush()
    while True:
        indata = readLine()
        if len(indata) < 6:
            #stderr.write("[+] Can not parse!\n")
            stderr.flush()
            continue
        qname = indata[1].lower()
        qtype = indata[3]

        # DNS logic
        stderr.flush()
        if (qtype == "A" or qtype == "ANY") and qname.endswith(domain):
            stderr.write("[+] A or ANY question\n")
            stderr.flush()
            if qname == domain:
                handleIt(domain, ipaddress)
            elif (qname == "ns1." + domain or qname == "ns2." + domain):
                handleNS(qname)
            elif(qname.endswith("x." + domain)):
                stderr.write("    [->] eXfiltration request: " + qname + "\n")
                stderr.flush()
                handleX(qname)
            elif(qname.endswith("ip." + domain)):
                stderr.write("    [->] Dynamic IP request: " + qname + "\n")
                stderr.flush()
                handleD(qname)

        if (qtype == "SOA" and qname.endswith(domain)):
            stderr.write("[+] SOA request\n")
            stderr.flush()
            handleSoa(qname)


if __name__ == '__main__':
    startUp()
