def mutate(csv_data, adobe_selection, environ):
    unacceptable_vulns = set()
    for vuln in csv_data.vuln_to_hosts.keys():
        if adobe_selection == "only" and "Adobe" not in csv_data.id_to_name[vuln]:
            unacceptable_vulns.add(vuln)
        elif adobe_selection == "none" and "Adobe" in csv_data.id_to_name[vuln]:
            unacceptable_vulns.add(vuln)

    for vuln in unacceptable_vulns:
        del csv_data.vuln_to_hosts[vuln]

    csv_data.rebuild_host_to_vulns()
