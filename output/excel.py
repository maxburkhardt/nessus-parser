from xlwt import Workbook, easyxf
def output(csv_data, excel_file, environment):
    print "Making an excel file in", excel_file, "!"
    book = Workbook()
    sheet = book.add_sheet("Nessus Vulnerabilities", cell_overwrite_ok=True)        #creating sheet + fonts
    default_style = easyxf("font: name Calibri, height 240;")
    header_style = easyxf("font: name Calibri, height 240; pattern: pattern diamonds, fore_colour pale_blue;")
    header = sheet.row(0)
    header.write(0, "Hostname", header_style)                    #headers
    header.write(1, "IP", header_style)
    header.write(2, "Name", header_style)
    for i in range(len(csv_data.vuln_to_hosts.keys())):
        header.write(i + 3, " ", header_style)
    header.height = 300
    row_count = 1
    col_count = 2
    sheet.col(0).width = 10000
    sheet.col(1).width = 5000
    sheet.col(2).width = 10000
    if not environment['numeric_ids']:                       # we're sorting by name, not plugin id
        collvulns = {}
        for vuln,name in csv_data.id_to_name.iteritems():              # Go through each vuln in id_to_name, collate ones to be collated
            if name[:2] == "MS":                # This should really be refactored to pull from some sort of file in the future
                name = "Needs Windows Updates"
            elif name.find("<") != -1:
                name = "Outdated " + name.split("<")[0]
            collvulns[vuln] = name
        collatedvulns = collvulns
        #for vuln,name in collvulns.iteritems():     # TODO: look through the vulns again to find tags for outdated software that don't have < signs
        #    if name.startswith("Outdated "):
        #        searchname = name.split("Outdated ")[1]
        sortedvulns = sorted(list(set(collatedvulns.values())))                #make a list of the sorted + collated vulnerabilities
        for vuln in sortedvulns:                                    #setting widths for vulnerability names
            sheet.col(col_count).width = 300 * len(vuln)
            col_count += 1
    else:
        sortedvulns = sorted(csv_data.vuln_to_hosts.keys())
        for vuln in sortedvulns:
            sheet.col(col_count).width = 300 * (len(str(vuln)) + 2)
            col_count += 1
    for host in csv_data.host_to_vulns.keys():
        row = sheet.row(row_count)
        row.write(0, host, default_style)
        row.write(1, csv_data.host_to_ip[host], default_style)
        if not environment['numeric_ids']:                                   # pull from alphabetical list, not plugin list
            for vuln in csv_data.host_to_vulns[host]:
                row.write(sortedvulns.index(collatedvulns[vuln]) + 2, collatedvulns[vuln], easyxf("font: name Calibri, height 240;"
                    "pattern: pattern solid, fore_colour red;"))
        else:
            for vuln in csv_data.host_to_vulns[host]:
                row.write(sortedvulns.index(vuln) + 2, vuln, easyxf("font: name Calibri, height 240;"
                    "pattern: pattern solid, fore_colour red;"))
        row.height = 300
        row_count += 1
    book.save(excel_file)
