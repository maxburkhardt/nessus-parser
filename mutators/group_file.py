import re
def mutate(csv_data, group_file, options):
    include_hosts = set()
    exclude_hosts = set()
    filter_list = []

    try:
        fh = open(group_file, "r")
        filter_list = fh.read().strip().split("\n")
        map(lambda x: x.strip(), filter_list)
        fh.close()
    except IOError:
        print "Error reading group file! Exiting."
        exit(1)
    except:
        print "An unknown error occured while parsing the group file. Exiting."
        exit(1)

    for host in csv_data.host_to_vulns.keys():
        if host in include_hosts or host in exclude_hosts:
            continue
        else:
            included = False
            for pattern in filter_list:
                if re.search(pattern, host):
                    included = True
                    include_hosts.add(host)
                    break
            if not included:
                exclude_hosts.add(host)

    for host in exclude_hosts:
        del csv_data.host_to_vulns[host]

    csv_data.rebuild_vuln_to_hosts() 
