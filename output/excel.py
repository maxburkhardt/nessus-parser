from xlwt import Workbook, easyxf
def output(csv_data, excel_file, environment):
    print "Making an excel file in", excel_file, "!"
    book = Workbook()
    sheet = book.add_sheet("Nessus Vulnerabilities", cell_overwrite_ok=True)        #creating sheet + fonts
    sheet.set_panes_frozen(True)
    sheet.set_horz_split_pos(1)
    sheet.set_vert_split_pos(2)
    sheet.set_remove_splits(True)
    default_style = easyxf("font: name Calibri, height 240;")
    header_style = easyxf("font: name Calibri, height 240; pattern: pattern diamonds, fore_colour pale_blue; align: wrap 1;")
    header = sheet.row(0)
    header.write(0, "Hostname", header_style)                    #headers
    header.write(1, "IP", header_style)

    vuln_names = map(lambda x: csv_data.id_to_name[x], csv_data.vuln_to_hosts.keys())
    vuln_hosts = csv_data.vuln_to_hosts.values()

    for i in range(len(vuln_names)):
        header.write(i + 2, vuln_names[i], header_style)

    header.height = 900
    row_count = 1
    col_count = 2
    sheet.col(0).width = 10000
    sheet.col(1).width = 5000
    sheet.col(2).width = 10000
    for vuln in vuln_names:
        sheet.col(col_count).width = 150 * (len(str(vuln)) + 2)
        col_count += 1
    for host in csv_data.host_to_vulns.keys():
        row = sheet.row(row_count)
        row.write(0, host, default_style)
        row.write(1, csv_data.host_to_ip[host], default_style)
        for i in range(len(vuln_names)):
            if host in vuln_hosts[i]:
                row.write(i + 2, " ", easyxf("font: name Calibri, height 240;"
                    "pattern: pattern solid, fore_colour red;"))
        row.height = 300
        row_count += 1
    book.save(excel_file)
