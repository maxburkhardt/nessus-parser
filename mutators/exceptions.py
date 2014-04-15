def mutate(csv_data, exceptions_file, environ):

    with open(exceptions_file) as f:
       for exception in f:
          try:
             hostname, id = exception.split()
          except ValueError:
             continue
          # commented lines:
          if hostname[0] = '#':
             continue
          # don't do anything if we don't have matches for the hostname
          if not hostname in csv_data.host_to_vulns:
             continue
          csv_data.host_to_vulns[hostname] = filter( lambda vuln: vuln != id, csv_data.host_to_vulns[hostname] )
          if not csv_data.host_to_vulns[hostname]:
             del csv_data.host_to_vulns[hostname]
    
    # rebuild vuln_to_hosts
    csv_data.rebuild_vuln_to_hosts() 
