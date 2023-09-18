import sslyze
import subprocess
import time
import pathlib

class Scans:
    def __init__(self, hosts):
        # Contains hosts to scan and other scan settings
        # Contains the results of the scans
        self.hosts = hosts
        self.scanner = None
        self.invalid_hosts = []
    
    def perform_scans(self):
        # Queue up scan jobs
        # Perform scans for the provided hosts
        # Return the results
        all_scan_requests = []

        for host in self.hosts:
            try:
                r = sslyze.ServerScanRequest(server_location=sslyze.ServerNetworkLocation(hostname=host))
                all_scan_requests.append(r)
        
            except sslyze.errors.ServerHostnameCouldNotBeResolved:
                # Handle bad input ie. invalid hostnames
                print("Invalid hostname: ", host)
                self.invalid_hosts.append(host)
        
        
        #Create a scanner object and add all the scans to the queue
        scanner = sslyze.Scanner()
        scanner.queue_scans(all_scan_requests)
        self.scanner = scanner

        return scanner
    
    

    def openSSL_tls13_request(self, host):
        # Run an openSSL command line scan for the provided host
        # Should return both the ticket and its lifetime
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        session_outfile = output_folder + host + ".ses"
        stdout_file = output_folder + host + "TLS13Scan.txt"
        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-tls1_3", "-connect", url, "-sess_out", session_outfile, "-state", "-ign_eof"]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Wait for the post handshake ticket and get the lifetime
        _, error = proc.communicate("0 \r\n")

        return stdout_file

    def openSSL_tls13_resumption(self, host, session_in_file):
        pass

    def openSSL_DOWNGRD_test(self, host, lowest_version):
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        stdout_file = output_folder + host + "DOWNGRD.txt"

        possible_lowest_versions = ["-ssl2", "-ssl3", "-tls1", "-tls1_1", "-tls1_2"]
        print(lowest_version)
        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-connect", url, "-debug", "-ign_eof", possible_lowest_versions[lowest_version]]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Wait for the post handshake ticket and get the lifetime
        _, error = proc.communicate("0 \r\n")

        return stdout_file




