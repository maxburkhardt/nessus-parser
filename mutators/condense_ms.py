def mutate(csv_data, environ):
    # make a name map entry for the new, combined microsoft vuln
    csv_data.id_to_name['MS'] = 'Needs Microsoft Updates'
    csv_data.id_to_severity['MS'] = 'High'

    ms_plugins = set()
    ms_hosts = set()

    for vuln,hosts in csv_data.vuln_to_hosts.iteritems():
        if "MS" in csv_data.id_to_name[vuln][:2] or "Microsoft" in csv_data.id_to_name[vuln]:
            ms_plugins.add(vuln)
            for host in hosts:
                ms_hosts.add(host)

    for plugin in ms_plugins:
        del csv_data.vuln_to_hosts[plugin]
    csv_data.vuln_to_hosts['MS'] = ms_hosts
    csv_data.rebuild_host_to_vulns()
