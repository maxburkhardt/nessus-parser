## This part of the Nessus parser is intended to, given a filename,
## read it, parse the CSV, and then return a tuple of four dictionaries:
## 1. host_to_vulns, a dictionary from hostname -> set of plugin IDs
## 2. vuln_to_hosts, a dictionary from plugin ID -> set of hostnames
## 3. id_to_name, a dictionary from plugin ID -> human-friendly name
## 4. host_to_ip, a dictionary from hostname -> IP address
import csv
import socket

# Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output

__author__ = "Maximilian Burkhardt, Lead Infosec 2012-2013 and Samuel Zhu, InfoSec Engineer 2013"

def read(filename): 
    PID = 0
    CVE = 1
    CVSS = 2
    RISK = 3
    HOST = 4
    PROTOCOL = 5
    PORT = 6
    NAME = 7
    SYNOPSIS = 8
    DESCRIPTION = 9
    SOLUTION = 10
    OUTPUT = 11

    host_to_vulns = {}
    vuln_to_hosts = {}
    id_to_name = {}
    host_to_ip = {}

    with open(filename, 'rb') as csvfile:
        scanreader = csv.reader(csvfile, delimiter=",", quotechar="\"")
        for row in scanreader:
            # first get the IP address mapping (if not already discovered) and put it in host_to_ip
            if row[HOST] not in host_to_ip:
                try:
                    host_to_ip[row[HOST]] = socket.getaddrinfo(row[HOST], 4444)[0][4][0]
                except:
                    host_to_ip[row[HOST]] = "IP N/A"

            # create id_to_name entries if they don't already exist
            if row[PID] not in id_to_name:
                id_to_name[row[PID]] = row[NAME]

            # add entry to host_to_vulns for this host and this vuln
            if row[HOST] not in host_to_vulns:
                host_to_vulns[row[HOST]] = set()
            host_to_vulns[row[HOST]].add(row[PID])

            # add entry to vuln_to_hosts for this host and this vuln
            if row[PID] not in vuln_to_hosts:
                vuln_to_hosts[row[PID]] = set()
            vuln_to_hosts[row[PID]] = row[HOST]

    return (host_to_vulns, vuln_to_hosts, id_to_name, host_to_ip)
