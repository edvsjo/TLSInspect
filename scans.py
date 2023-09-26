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
        cmd = ["openssl", "s_client", "-tls1_3", "-connect", url, "-sess_out", session_outfile, "-state", "-ign_eof", "-debug"]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try: 
            _, error = proc.communicate("0 \r\n", timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, error = proc.communicate()
        finally:        
            return stdout_file, session_outfile

    def openSSL_tls13_early_data(self, host, session_in_file, early_data_file):
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        stdout_file = output_folder + host + "TLS13Earlydata.txt"
        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-tls1_3", "-connect", url, "-sess_in", session_in_file, "-ign_eof", "-debug", "-early_data", early_data_file]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        try: 
            _, error = proc.communicate("0 \r\n", timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, error = proc.communicate()
        finally:        
            return stdout_file

    def openSSL_tls13_resumption(self, host, session_in_file):
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        stdout_file = output_folder + host + "TLS13Resumption.txt"
        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-tls1_3", "-connect", url, "-sess_in", session_in_file, "-ign_eof", "-debug"]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try: 
            _, error = proc.communicate("0 \r\n", timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, error = proc.communicate()
        finally:        
            return stdout_file

    def openSSL_DOWNGRD_test(self, host, lowest_version):
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        stdout_file = output_folder + host + "DOWNGRD.txt"

        possible_lowest_versions = ["-ssl2", "-ssl3", "-tls1", "-tls1_1", "-tls1_2"]
        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-connect", url, "-debug", "-ign_eof", possible_lowest_versions[lowest_version]]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try: 
            _, error = proc.communicate("0 \r\n", timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, error = proc.communicate()
        finally:        
            return stdout_file

    def openSSL_no_SNI_test(self, host):
        url = host + ":443"
        output_folder = "output/" + host + "/"
        if not pathlib.Path(output_folder).exists():
            pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        stdout_file = output_folder + host + "no_SNI.txt"

        f = open(stdout_file, "w+")
        cmd = ["openssl", "s_client", "-connect", url, "-debug", "-ign_eof","-noservername"]
        proc = subprocess.Popen(cmd, stdout=f, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        try: 
            _, error = proc.communicate("0 \r\n", timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, error = proc.communicate()
        finally:        
            return stdout_file



