from scandata import ScanData
def mutate(csv_data, environ):
    # make a name map entry for the new, combined java vuln
    csv_data.id_to_name['JAVA'] = 'Java Vulnerability'

    hosts_with_java = set()
    java_plugins = set()

    print csv_data.host_to_vulns
    for host,vulns in csv_data.host_to_vulns.iteritems():
        java_found = False

        # first we'll check to see if java is present for this host at all
        for vuln in vulns:
            if "Java" in csv_data.id_to_name[vuln]:
                java_found = True
                java_plugins.add(vuln)

        # if so, remove all other java vulns, and add the special one
        # we can't do this in one loop because you can't modify a set 
        # as you're iterating through it
        if java_found:
            vulns = set(filter(lambda x: "Java" not in x, vulns))
            vulns.add('JAVA')
            hosts_with_java.add(host)

        # now we'll make the vuln_to_hosts dictionary match
        csv_data.rebuild_vuln_to_hosts()
