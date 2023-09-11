import sslyze
import scans
import parser
import csv

# HOSTS = ["www.google.com", "www.facebook.com", "øalkdjføalkjdf"]
# HOSTS = ["www.google.com", "www.facebook.com", "www.uio.no"]
HOSTS = ["uio.no"]

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


    hosts = import_hosts("top-1m.csv", amount=10)
    # hosts = HOSTS
    
    # Create a scans object
    scans_obj = scans.Scans(hosts)
    # Perform the scans
    all_server_scan_results = scans_obj.perform_scans()

    failed_scan = []
    # Create a parser object
    for scan_result in all_server_scan_results.get_results():
        host = scan_result.server_location.hostname
        print("Parsing scan result for: ", host)
        if scan_result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("Failed to connect to: ", host)
            failed_scan.append(host)
        else: 
            parser_obj = parser.Parser(host, scan_result)
            
            if parser_obj.tls1_3_support:
                openSSL_scan_file = scans_obj.openSSL_request(host)
                # print(openSSL_scan_result)
                parser_obj.parse_openSSL_tls13_scan_result(openSSL_scan_file)
            
            parser_obj.parse_scan_result()

    print("Failed to connect to: ", failed_scan)
    # scans_obj.openSSL_request("www.uio.no")


if __name__ == "__main__":
    main()
    # import_hosts("top-1m.csv")
