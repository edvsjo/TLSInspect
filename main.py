import sslyze
import scans
import parser

# HOSTS = ["www.google.com", "www.facebook.com", "øalkdjføalkjdf"]
# HOSTS = ["www.google.com", "www.facebook.com", "www.uio.no"]
HOSTS = ["uio.no"]

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
        
        if parser_obj.tls1_3_support:
            openSSL_scan_result = scans_obj.openSSL_request(host)
            parser_obj.parse_openSSL_tls13_scan_result(openSSL_scan_result)
        
        parser_obj.parse_scan_result()

    
    # scans_obj.openSSL_request("www.uio.no")


if __name__ == "__main__":
    main()
