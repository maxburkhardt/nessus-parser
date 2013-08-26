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

__author__ = "Maximilian Burkhardt, Lead Infosec 2012-2013 and Samuel Zhu, InfoSec Engineer 2013"

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

help_message = """
NESSUS PARSER HELP
Now fancier.
Written by maxb.

INVOCATION:
{0} <options> input.csv 

OPTIONS:
--condense-java: combine all java-related vulns in to one category.
--select-adobe: takes in 0 (no change to parsing), 1 (select ONLY Adobe vulns), or 2 (select only NON-Adobe vulns)
--level <level>: Show vulns of risk level <level>. Available options: Critical (default), High, Medium, Low, None.
--filter-hostname <regex>: only show hostnames that match the regular expression <regex>. Suggested values: AEIO, SAS, etc. Keep things to one word, or be prepared to debug your regexes.
--filter-plugin <list of plugin IDs>: only show the listed plugins. Separate desired plugins by commas, WITHOUT spaces. NOTE: this overrides the --level directive.
--create-tickets <recipe.txt>: makes tickets for all hosts produced in the report.

EXAMPLES:
Basic query to find all critical vulns at 1950 University, with combined Java results:
{0} --condense-java 1950.csv
Find all High-rated vulnerabilities in the AEIO department, out of the more general Admissions scan:
{0} --condense-java --level High --filter-hostname AEIO admissions.csv
Find all hosts which showed positive for plugins 1234 and 5678:
{0} --filter-plugins 1234,5678 hosts.csv

AUXILIARY USAGE:
Make this script more effective by piping the output to files like so:
{0} <options> input.csv > outfile.txt
Then, compare two different outfiles (presumably from the same scan & different weeks) with:
vimdiff <week1.txt> <week2.txt>"
""".format(sys.argv[0])

# parse the args
if len(sys.argv) == 1:
    print help_message
    sys.exit(0)
condense_java = False
select_adobe = 0
level = "Critical"
acceptable_levels = ["Critical", "High", "Medium", "Low", "None"]
host_filter = ".*"
filter_list = []
plugin_filter = []
ticket_recipe = None
for i in range(1, len(sys.argv)):
    if sys.argv[i] == "--select-adobe":
        select_adobe = int(sys.argv[i+1])
        if select_adobe not in [0,1,2]:
            print "ERROR: select-adobe must be 0 (no change), 1 (only adobe) or 2 (no adobe)!"
            sys.exit(0)
        i += 1
    elif sys.argv[i] == "--condense-java":
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
    elif sys.argv[i] == "--filter-group":
        hosts = open(sys.argv[i+1],'r')
        for host in hosts:
            filter_list.append(host)
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
host_flag = False   #flag to determine whether or not a match has been found in filter_list
with open(source, 'rb') as csvfile:
    scanreader = csv.reader(csvfile, delimiter=",", quotechar="\"")
    for row in scanreader:
        if len(filter_list) != 0:  #if filter_list isn't empty, that means we're using group searching
            for f in filter_list:
                if re.search(f, row[HOST]) != None: # if we find a matching filter, break out and flip the flag
                    host_flag = True
                    break
        elif re.search(host_filter, row[HOST]) == None:
            continue

        if host_flag == False:
            continue

        # if there is a plugin filter and it matches, *or* if there isn't a filter and it's at the correct level
        if (len(plugin_filter) != 0 and row[PID] in plugin_filter) or (len(plugin_filter) == 0 and row[RISK] == level):
            if row[HOST] not in host_map:
                try:
                    host_map[row[HOST]] = socket.getaddrinfo(row[HOST], 4444)[0][4][0]
                except:
                    host_map[row[HOST]] = "IP N/A"

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

# Adobe selection
if select_adobe == 1 or select_adobe == 2:
    adobe = {} #vulns,hosts
    for vuln,hosts in vulns.iteritems():
        if "Adobe" in name_map[vuln]:
            adobe[vuln] = hosts
    for vuln in adobe:
        del vulns[vuln]
    if select_adobe == 1: #if proper adobe option selected, only display adobe vulns
        vulns = adobe  

print "Parse start time:", time.asctime()
print "OPTIONS:"
print "Risk Level:", level
print "Condense Java:", str(condense_java)
print "Select Adobe:", str(select_adobe)
print "Host Filter:", host_filter
print "Plugin Filter:", str(plugin_filter)
print "\n\n"

print "STATISTICS:"
print "Number of unique", level, "vulnerabilities found:", str(stat_vuln_count)
print "Number of unique hosts found with", level, "vulnerabilities:", str(stat_host_count)
print "Most widespread", level, "vulnerability:", name_map[most_pop_vuln[0]]
print "Host with the most", level, "vulnerabilities:", most_vuln_host[0]
print "\n\n"

# Vulnerability List Pre-processing
vuln_diff = []
vuln_diff = set(name_map.keys()) - set(vulns.keys())    # get keys in name_map that are not in vulns
for vuln in vuln_diff:                                  # remove keys in name_map that are not in vulns
    del name_map[vuln]
print_dict = {}                                         # create new dict to print things
for vuln,hosts in vulns.iteritems():
    print_dict[name_map[vuln]] = hosts
printList = sorted(print_dict.items())

for i in range(len(printList)):                         # go through printList in order and print things!
    print "=====", printList[i][0], "====="
    for host in printList[i][1]:
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
