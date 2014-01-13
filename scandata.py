class ScanData:
    def __init__(self, host_to_vulns, vuln_to_hosts, id_to_name, host_to_ip, id_to_severity):
        self.host_to_vulns = host_to_vulns
        self.vuln_to_hosts = vuln_to_hosts
        self.id_to_name = id_to_name
        self.host_to_ip = host_to_ip
        self.id_to_severity = id_to_severity

    # throw away the current host_to_vulns dictionary and rebuild it from vuln_to_hosts
    def rebuild_host_to_vulns(self):
        self.host_to_vulns = {}
        for vuln,hosts in self.vuln_to_hosts.iteritems():
            for host in hosts:
                if host not in self.host_to_vulns:
                    self.host_to_vulns[host] = set()
                self.host_to_vulns[host].add(vuln)

    # throw away the current vuln_to_hosts dictionary and rebuild it from host_to_vulns
    def rebuild_vuln_to_hosts(self):
        self.vuln_to_hosts = {}
        for host,vulns in self.host_to_vulns.iteritems():
            for vuln in vulns:
                if vuln not in self.vuln_to_hosts:
                    self.vuln_to_hosts[vuln] = set()
                self.vuln_to_hosts[vuln].add(host)
