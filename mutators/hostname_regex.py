import re
def mutate(csv_data, regex, options):
    ignore_hosts = set()
    for host in csv_data.host_to_vulns.keys():
        if re.search(regex, host) == None:
            ignore_hosts.add(host)

    for host in ignore_hosts:
        del csv_data.host_to_vulns[host]

    csv_data.rebuild_vuln_to_hosts()
