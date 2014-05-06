def mutate(csv_data, environ):
    # make a name map entry for the new, combined java vuln
    csv_data.id_to_name['JAVA'] = 'Java Vulnerability'
    csv_data.id_to_severity['JAVA'] = environ['level']

    java_plugins = set()
    java_hosts = set()

    for vuln,hosts in csv_data.vuln_to_hosts.iteritems():
        if "Java" in csv_data.id_to_name[vuln] and \
                            csv_data.id_to_severity[vuln] == environ['level']:
            java_plugins.add(vuln)
            for host in hosts:
                java_hosts.add(host)

    for plugin in java_plugins:
        del csv_data.vuln_to_hosts[plugin]
    csv_data.vuln_to_hosts['JAVA'] = java_hosts
    csv_data.rebuild_host_to_vulns()
