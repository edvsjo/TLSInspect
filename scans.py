import sslyze

class Scans:
    def __init__(self, hosts):
        # Contains hosts to scan and other scan settings
        # Contains the results of the scans
        self.hosts = hosts
        self.scanner = None
    
    def perform_scans(self):
        # Queue up scan jobs
        # Perform scans for the provided hosts
        # Return the results
        all_scan_requests = []

        try:
            for host in self.hosts:
                r = sslyze.ServerScanRequest(server_location=sslyze.ServerNetworkLocation(hostname=host))
                all_scan_requests.append(r)
        
        except sslyze.errors.ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
            print("Error resolving the supplied hostnames")
            
        
        #Create a scanner object and add all the scans to the queue
        scanner = sslyze.Scanner()
        scanner.queue_scans(all_scan_requests)
        self.scanner = scanner

        return scanner
    




