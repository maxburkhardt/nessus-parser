class ScanData:
    def __init__(self, host_to_vulns, vuln_to_hosts, id_to_name, host_to_ip, id_to_severity):
        self.host_to_vulns = host_to_vulns
        self.vuln_to_hosts = vuln_to_hosts
        self.id_to_name = id_to_name
        self.host_to_ip = host_to_ip
        self.id_to_severity = id_to_severity
