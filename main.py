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
    """
    Imports the top n hosts from the provided csv file

    Args:
        hosts_file (str): The path to the csv file containing the hosts
        amount (int): The number of hosts to import
    Returns:
        hosts (list): The top n hosts from that list. Is sorted top to bottom
    """
    hosts = []
    with open(hosts_file) as csvfile:
        # spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            # print(', '.join(row))
            hosts.append(', '.join(row).split(",")[1].strip())
            if len(hosts) >= amount:
                break
    # print(hosts)
    return hosts

def main():
    """
    Main function for the scanner.
    """

    # Import the hosts to scan
    hosts = import_hosts("top-1m.csv", amount=1)
    # hosts = HOSTS
    
    print("Attempting to connect to database")
    # Create a database connection
    conn, cur = database.create_connection()

    scans_obj = scans.Scans(hosts)

    # Perform the sslyze scans
    all_server_scan_results = scans_obj.perform_scans()

    failed_scan = []

    # Count the number of hosts that has been scanned
    count = 0

    # For each scan result from the sslyze scans we need to parse the result and do further scans
    for scan_result in all_server_scan_results.get_results():
        host = scan_result.server_location.hostname
        print("Scan result for: ", host)
        
        # Commit the results to the database every 50 hosts
        count += 1
        if count % 50 == 0:
            print("Scanned ", count, " hosts. Commiting results to database")
            conn.commit()


        # Tests if SSLyze was able to connect to the host. This weeds out most of the invalid hosts
        if scan_result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("Failed to connect to: ", host)
            # Add the failed hosts to the database
            failed_scan.append(host)
            database.send_scan_fail(host, cur, "Failed to connect to host")
        else: 
            
            # Because of the asynchronous nature of the scans, we need to check if the scan result is ready
            try:
                parser_obj = parser.Parser(host, scan_result)
            except AttributeError:
                print("Failed to parse: ", host)
                failed_scan.append(host)
                database.send_scan_fail(host, cur, "Failed to parse scan result")
                continue
            else:

                print("Parsing scan result for: ", host)
                # If the host supports TLS 1.3, we need to do a TLS 1.3 scan
                if parser_obj.tls1_3_support:
                    try: 
                        openSSL_scan_file, session_outfile = scans_obj.openSSL_tls13_request(host)
                        parser_obj.parse_openSSL_tls13_scan_result(openSSL_scan_file, session_outfile)
                        database.send_tls_session(parser_obj, cur, False)
                    # To catch the case where the host does not provide a tls 1.3 session to resume
                    except FileNotFoundError:
                        print("No TLS1.3 resumption support: ", host)
                        failed_scan.append(host)
                        database.send_scan_fail(host, cur, "No resumption support")
                        continue
                    else:
                        database.send_tls_scan_raw(parser_obj, openSSL_scan_file, "TLS 1.3 scan", cur)
                
                # If the host supports TLS 1.3 ticket resumption and early data, we need to verify that it actually propperly supports it
                if parser_obj.tls_ticket_resumption_support and parser_obj.early_data_support:
                    early_data_stdout = scans_obj.openSSL_tls13_early_data(host, parser_obj.openSSL_tls13_resumption_file, "earlytest.txt")
                    parser_obj.parse_openSSL_tls13_early_data(early_data_stdout)
                    database.send_tls_scan_raw(parser_obj, early_data_stdout, "Early data scan", cur)

                #If it supports both tls1.3 and lower versions, we need to do a scan to verify that it does support DOWNGRD protection from TLS 1.3
                if parser_obj.tls1_3_support and min(parser_obj.supported_versions) < 5:
                    lowest_version = min(parser_obj.supported_versions)
                    try:
                        stdout_file = scans_obj.openSSL_DOWNGRD_test(host, lowest_version)
                        parser_obj.parse_openSSL_DOWNGRD_test(stdout_file)
                        database.send_tls_scan_raw(parser_obj, stdout_file, "DOWNGRD scan", cur)
                    except:
                        database.send_scan_fail(host, cur, "Something failed with downgrade scan")
                
                try:
                    no_sni_test = scans_obj.openSSL_no_SNI_test(host)
                    parser_obj.parse_openSSL_no_SNI_test(no_sni_test)
                    database.send_tls_scan_raw(parser_obj, no_sni_test, "No SNI scan", cur)
                except:
                    database.send_scan_fail(host, cur, "Something failed with no SNI test")
                else:

                    # parser_obj.parse_scan_result()

                    # Send the scan result to the database
                    database.send_scan_result(parser_obj, cur)
        
    # Add the failed hosts to the database
    for host in scans_obj.invalid_hosts:
        failed_scan.append(host)
        database.send_scan_fail(host, cur, "Invalid hostname")
    print("Failed to connect to: ", failed_scan)

    conn.commit()
    conn.close()
    # scans_obj.openSSL_request("www.uio.no")


if __name__ == "__main__":
    main()
    # import_hosts("top-1m.csv")
