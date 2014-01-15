def mutate(csv_data, level, environ):

    # first find all the vuln IDs that we don't care about
    unacceptable_vulns = set()
    for vuln in csv_data.vuln_to_hosts.keys():
        if csv_data.id_to_severity[vuln] != level:
            unacceptable_vulns.add(vuln)

    # remove these vulns from the vuln_to_hosts set
    for vuln in unacceptable_vulns:
        del csv_data.vuln_to_hosts[vuln]
    
    # rebuild host_to_vulns
    csv_data.rebuild_host_to_vulns() 
