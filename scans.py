import sslyze
import subprocess
import time

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
    
    import time

    def openSSL_request(self, host):
        # Run an openSSL command line scan for the provided host
        # Should return both the ticket and its lifetime
        print("Running openSSL scan for: ", host)
        url = host + ":443"
        session_outfile = host + ".txt"
        cmd = ["openssl", "s_client", "-tls1_3", "-connect", url, "-sess_out", session_outfile]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Wait for the post handshake ticket and get the lifetime
        time.sleep(5) # Wait for the handshake to complete
        proc.stdin.write("QUIT\n")
        output, _ = proc.communicate()
        
        return output




