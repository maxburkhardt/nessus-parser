import time
import getpass
import csv
from string import Template
from util.rt import RTConnect
def output(csv_data, ticket_recipe, environ):
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
    for host,vulns in csv_data.host_to_vulns.iteritems():
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
    for host,vulns in csv_data.host_to_vulns.iteritems():
        vulndata = ""
        for vuln in vulns:
            vulndata += str(vuln) + ": " + csv_data.id_to_name[vuln] + "\n"
        print "Creating ticket for", host
        created = rtc.create_ticket(requestor, subj_template.substitute(hostname=host), body_template.substitute(vulns=vulndata, hostname=host, ip=csv_data.host_to_ip[host]), queue)
        tickets_created.append([created, host, time.asctime(), queue, "https://rt.rescomp.berkeley.edu/Ticket/Display.html?id=" + str(created)])

    filename = "nessus-ticket-generation-" + time.strftime("%m-%d.%H%M") + ".csv"
    try:
        oh = open(filename, "w")
        writer = csv.writer(oh, delimiter=",", quotechar="\"")
        for ticket in tickets_created:
            writer.writerow(ticket)
        oh.close()
        print "Done!"
        print "A log of tickets created has been written to", filename
    except IOError:
        print "Error writing log file. Tickets were still created, however."
