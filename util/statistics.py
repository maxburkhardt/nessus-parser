## this parser module, given the parsed scan results, generates
## some statistics. It returns a 4-tuple of:
## 1. Count of unique vulnerabilities in this scan
## 2. Count of unique hosts with vulnerabilities in this scan
## 3. PID of the most common vulnerability
## 4. Hostname of the host with the most vulnerabilities
def stat_compute(vuln_to_hosts, host_to_vulns): 
    stat_vuln_count = len(vuln_to_hosts)
    stat_host_count = len(host_to_vulns)
    host_counts = {}
    most_pop_vuln = (None, 0)
    for vuln,hosts in vuln_to_hosts.iteritems():
        if len(hosts) > most_pop_vuln[1]:
            most_pop_vuln = (vuln, len(hosts))
        for host in hosts:
            if host not in host_counts:
                host_counts[host] = 1
            else:
                host_counts[host] += 1
    most_vuln_host = (None, 0)
    for host,count in host_counts.iteritems():
        if count > most_vuln_host[1]:
            most_vuln_host = (host, count)
    return (stat_vuln_count, stat_host_count, most_pop_vuln[0], most_vuln_host[0])

def output(csv_data): 
    data = stat_compute(csv_data.vuln_to_hosts, csv_data.host_to_vulns)
    print "STATISTICS:"
    print "Number of unique vulnerabilities found:", str(data[0])
    print "Number of unique hosts found with vulnerabilities:", str(data[1])
    if data[0] != 0:
        print "Most widespread vulnerability:", csv_data.id_to_name[data[2]]
        print "Host with the most vulnerabilities:", data[3]
    print " "
