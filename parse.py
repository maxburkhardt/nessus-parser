#!/usr/bin/env python
import csv
import sys
import socket
import re
import time
import getpass
from string import Template
from rt import RTConnect

# Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output

__author__ = "Maximilian Burkhardt, Lead Infosec 2012-2013"

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

help_message = "NESSUS PARSER HELP\nNow fancier.\nWritten by maxb.\n\nINVOCATION:\n" + sys.argv[0] + " <options> input.csv \n\nOPTIONS:\n--condense-java: combine all java-related vulns in to one category.\n--level <level>: Show vulns of risk level <level>. Available options: Critical (default), High, Medium, Low, None.\n--filter-hostname <regex>: only show hostnames that match the regular expression <regex>. Suggested values: AEIO, SAS, etc. Keep things to one word, or be prepared to debug your regexes.\n--filter-plugin <list of plugin IDs>: only show the listed plugins. Separate desired plugins by commas, WITHOUT spaces. NOTE: this overrides the --level directive.\n--create-tickets <recipe.txt>: makes tickets for all hosts produced in the report.\n\nEXAMPLES:\nBasic query to find all critical vulns at 1950 University, with combined Java results:\n" + sys.argv[0] + " --condense-java 1950.csv\nFind all High-rated vulnerabilities in the AEIO department, out of the more general Admissions scan:\n" + sys.argv[0] + " --condense-java --level High --filter-hostname AEIO admissions.csv\nFind all hosts which showed positive for plugins 1234 and 5678:\n" + sys.argv[0] + " --filter-plugins 1234,5678 hosts.csv\n\nAUXILIARY USAGE:\nMake this script more effective by piping the output to files like so:\n" + sys.argv[0] + " <options> input.csv > outfile.txt\nThen, compare two different outfiles (presumably from the same scan & different weeks) with:\nvimdiff <week1.txt> <week2.txt>"

# parse the args
if len(sys.argv) == 1:
    print help_message
    sys.exit(0)
condense_java = False
level = "Critical"
acceptable_levels = ["Critical", "High", "Medium", "Low", "None"]
host_filter = ".*"
plugin_filter = []
ticket_recipe = None
for i in range(1, len(sys.argv)):
    if sys.argv[i] == "--condense-java":
        condense_java = True
    elif sys.argv[i] == "--level":
        level = sys.argv[i+1]
        if level not in acceptable_levels:
            print "ERROR: not an acceptable argument to the --level option!"
            print help_message
            sys.exit(0)
        i += 1
    elif sys.argv[i] == "--filter-hostname":
        host_filter = sys.argv[i+1]
        i += 1
    elif sys.argv[i] == "--filter-plugin":
        plugin_filter = sys.argv[i+1].split(",")
        i += 1
    elif sys.argv[i] == "--create-tickets":
        ticket_recipe = sys.argv[i+1]
        i += 1
source = sys.argv[-1]
if source[-4:] != ".csv":
    print "ERROR: last argument must be a CSV file with a '.csv' extension!"
    print help_message
    sys.exit(0)

# parse the file
vulns = {}
host_to_vulns = {}
name_map = {}
host_map = {}
with open(source, 'rb') as csvfile:
    scanreader = csv.reader(csvfile, delimiter=",", quotechar="\"")
    for row in scanreader:
        if re.search(host_filter, row[HOST]) == None:
            continue

        # if there is a plugin filter and it matches, *or* if there isn't a filter and it's at the correct level
        if (len(plugin_filter) != 0 and row[PID] in plugin_filter) or (len(plugin_filter) == 0 and row[RISK] == level):
            if row[HOST] not in host_map:
                host_map[row[HOST]] = socket.getaddrinfo(row[HOST], 4444)[0][4][0]

            if row[PID] not in name_map:
                name_map[row[PID]] = row[NAME]

            if row[HOST] not in host_to_vulns:
                host_to_vulns[row[HOST]] = set()
                host_to_vulns[row[HOST]].add(row[PID])
            else:
                host_to_vulns[row[HOST]].add(row[PID])

            if row[PID] in vulns:
                if row[HOST] not in vulns[row[PID]]:
                    vulns[row[PID]].append(row[HOST])
            else:
                vulns[row[PID]] = [row[HOST]]

# assemble statistics
stat_vuln_count = len(vulns)
stat_host_count = len(host_map)
host_counts = {}
most_pop_vuln = (None, 0)
for vuln,hosts in vulns.iteritems():
    if len(hosts) > most_pop_vuln[1]:
        most_pop_vuln = (vuln, len(hosts))
    for host in hosts:
        if host not in host_counts:
            host_counts[host] = 1
        else:
            host_counts[host] += 1
most_vuln_host = (None, 0)
for host,count in host_counts.iteritems():
    if count > most_vuln_host[1]:
        most_vuln_host = (host, count)



# do java condensation if necessary
if condense_java:
    name_map[-1] = "Condensed Java Vulns"
    java_hosts = []
    java_vulns = []
    for vuln,hosts in vulns.iteritems():
        if "Java" in name_map[vuln]:
            java_hosts += hosts
            java_vulns.append(vuln)
    for vuln in java_vulns:
        del vulns[vuln]
    vulns[-1] = list(set(java_hosts))

print "Parse start time:", time.asctime()
print "OPTIONS:"
print "Risk Level:", level
print "Condense Java:", str(condense_java)
print "Host Filter:", host_filter
print "Plugin Filter:", str(plugin_filter)
print "\n\n"

print "STATISTICS:"
print "Number of unique", level, "vulnerabilities found:", str(stat_vuln_count)
print "Number of unique hosts found with", level, "vulnerabilities:", str(stat_host_count)
print "Most widespread", level, "vulnerability:", name_map[most_pop_vuln[0]]
print "Host with the most", level, "vulnerabilities:", most_vuln_host[0]
print "\n\n"


for vuln,hosts in vulns.iteritems():
    print "=====", name_map[vuln], "====="
    for host in hosts:
        print host, "\t\t", host_map[host]
    print " "

if ticket_recipe:
    template_data = ""
    try:
        fh = open(ticket_recipe, "r")
        template_data = fh.read().split("\n", 3)
    except IOError:
        print "Error reading template file!"
        sys.exit(1)
    queue = ""
    requestor = ""
    subject = ""
    body = ""
    for line in template_data:
        temp_line = line.split(" ", 1)
        if temp_line[0] == "Queue:":
            queue = temp_line[1]
        elif temp_line[0] == "From:":
            requestor = temp_line[1]
        elif temp_line[0] == "Subject:" or temp_line[0] == "Subj:":
            subject = temp_line[1]
        else:
            body = line
    subj_template = Template(subject)
    body_template = Template(body)
    print "The parser is now about to make automated tickets in the", queue, "queue for the following hosts:" 
    for host,vulns in host_to_vulns.iteritems():
        print host
    proceed = raw_input("Do you want to proceed? [y/n] ").strip()
    if proceed != "y":
        print "Aborting."
        sys.exit(1)
    
    rtc = RTConnect()
    if rtc.token == None:
        print "You are not currently authenticated with RT. Please enter your CalNet username and password to continue."
        while True:
            user = raw_input("Username: ")
            password = getpass.getpass()  
            rtc.authenticate(user, password)
            if rtc.token == None:
                print "Error! Could not log in to CalNet. Bad username/password?"
            else:
                break
    tickets_created = []
    for host,vulns in host_to_vulns.iteritems():
        vulndata = ""
        for vuln in vulns:
            vulndata += str(vuln) + ": " + name_map[vuln] + "\n"
        print "Creating ticket for", host
        created = rtc.create_ticket(requestor, subj_template.substitute(hostname=host), body_template.substitute(vulns=vulndata, hostname=host, ip=host_map[host]), queue)
        tickets_created.append([created, host, time.asctime(), queue, "https://rt.rescomp.berkeley.edu/Ticket/Display.html?id=" + str(created)])

    filename = "nessus-ticket-generation-" + time.strftime("%m-%d.%H%M") + ".csv"
    oh = open(filename, "w")
    writer = csv.writer(oh, delimiter=",", quotechar="\"")
    for ticket in tickets_created:
        writer.writerow(ticket)
    oh.close()
    print "Done!"
    print "A log of tickets created has been written to", filename
