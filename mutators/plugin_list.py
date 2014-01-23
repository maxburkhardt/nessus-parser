def mutate(csv_data, plugin_list, options):
    allowed_plugins = plugin_list.split(",")
    to_remove = set()
    for vuln in csv_data.vuln_to_hosts.keys():
        if vuln not in allowed_plugins:
            to_remove.add(vuln)

    for vuln in to_remove:
        del csv_data.vuln_to_hosts[vuln]

    csv_data.rebuild_host_to_vulns()

