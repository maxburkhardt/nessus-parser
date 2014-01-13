from scandata import ScanData
def output(csv_data, environ):
    for vuln,hosts in csv_data.vuln_to_hosts.iteritems():
        print "=====", 
        if environ['numeric_ids']:
            print vuln,
        else:
            print csv_data.id_to_name[vuln], 
        print "====="
        for host in hosts:
            print host, "\t\t", csv_data.host_to_ip[host]
        print " "
