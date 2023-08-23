import sslyze
import scans
import parser

# HOSTS = ["www.google.com", "www.facebook.com", "øalkdjføalkjdf"]
HOSTS = ["www.google.com", "www.facebook.com", "uio.no"]

def import_hosts(hosts_file):
    hosts = []
    with open(hosts_file) as f:
        for line in f:
            hosts.append(line.strip())
    return hosts

def main():
    # Perform nessesary setup
    # Gather hosts to scan
    # Create a scanner request object for all locations
    # Request a scan for each host
    # Pass the results to the parser
    # Push the results to the database


    # hosts = import_hosts("hosts.txt")
    hosts = HOSTS
    
    # Create a scans object
    scans_obj = scans.Scans(hosts)
    # Perform the scans
    all_server_scan_results = scans_obj.perform_scans()

    # Create a parser object
    for scan_result in all_server_scan_results.get_results():
        host = scan_result.server_location.hostname
        parser_obj = parser.Parser(host, scan_result)
        parser_obj.parse_scan_result()
        print(host)
        print("TLSv1.3 Support: ", parser_obj.tls1_3_support)
        print("TLSv1.2 Support: ", parser_obj.tls1_2_support)
        print("TLSv1.1 Support: ", parser_obj.tls1_1_support)
        print("TLSv1.0 Support: ", parser_obj.tls1_0_support)
        print("SSLv3.0 Support: ", parser_obj.ssl3_support)
        print("SSLv2.0 Support: ", parser_obj.ssl2_support)
        print("")
        print("Fallback SCSV: ", parser_obj.fallback_scsv)
        print("")
        print(scan_result.scan_result.session_resumption.result)
        print(scan_result.scan_result.session_renegotiation.result)



if __name__ == "__main__":
    main()
