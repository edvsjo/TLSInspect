import sslyze
import scans
import parser
import csv
import database

# HOSTS = ["www.google.com", "www.facebook.com", "øalkdjføalkjdf"]
# HOSTS = ["www.google.com", "www.facebook.com", "www.uio.no"]
# HOSTS = ["yandex.net"]
# HOSTS = ["google.com"]

def import_hosts(hosts_file, amount=5):
    hosts = []
    with open(hosts_file) as csvfile:
        # spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            # print(', '.join(row))
            hosts.append(', '.join(row).split(",")[1].strip())
            if len(hosts) >= amount:
                break
    print(hosts)
    return hosts

def main():
    # Perform nessesary setup
    # Gather hosts to scan
    # Create a scanner request object for all locations
    # Request a scan for each host
    # Pass the results to the parser
    # Push the results to the database

    hosts = import_hosts("top-1m.csv", amount=100)
    # hosts = HOSTS
    
    # Create a scans object
    scans_obj = scans.Scans(hosts)
    # Perform the scans
    all_server_scan_results = scans_obj.perform_scans()

    failed_scan = []

    # Create a database connection
    conn, cur = database.create_connection()
    # Create a parser object
    for scan_result in all_server_scan_results.get_results():
        host = scan_result.server_location.hostname
        if scan_result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("Failed to connect to: ", host)
            failed_scan.append(host)
        else: 
            print("Parsing scan result for: ", host)
            parser_obj = parser.Parser(host, scan_result)
            if parser_obj.tls1_3_support:
                openSSL_scan_file, session_outfile = scans_obj.openSSL_tls13_request(host)
                # print(openSSL_scan_result)
                parser_obj.parse_openSSL_tls13_scan_result(openSSL_scan_file, session_outfile)

            if parser_obj.tls_ticket_resumption_support and parser_obj.early_data_support:
                early_data_stdout = scans_obj.openSSL_tls13_early_data(host, parser_obj.openSSL_tls13_resumption_file, "earlytest.txt")
                parser_obj.parse_openSSL_tls13_early_data(early_data_stdout)
            
            #If it supports both tls1.3 and lower versions, we need to do a DOWNGRD test
            if parser_obj.tls1_3_support and min(parser_obj.supported_versions) < 5:
                lowest_version = min(parser_obj.supported_versions)
                stdout_file = scans_obj.openSSL_DOWNGRD_test(host, lowest_version)
                parser_obj.parse_openSSL_DOWNGRD_test(stdout_file)
            
            no_sni_test = scans_obj.openSSL_no_SNI_test(host)
            parser_obj.parse_openSSL_no_SNI_test(no_sni_test)

            parser_obj.parse_scan_result()

            # Send the scan result to the database
            database.send_scan_result(parser_obj, cur)
            conn.commit()
    
    # Add the failed hosts to the database
    for host in scans_obj.invalid_hosts:
        failed_scan.append(host)

    
    conn.close()
    print("Failed to connect to: ", failed_scan)
    # scans_obj.openSSL_request("www.uio.no")


if __name__ == "__main__":
    main()
    # import_hosts("top-1m.csv")
