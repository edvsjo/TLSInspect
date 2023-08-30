import sslyze

class Parser:
    def __init__(self, host, scan_result):
        self.host = host
        self.scan_result = scan_result

        self.tls1_3_support = len(self.scan_result.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_2_support = len(self.scan_result.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_1_support = len(self.scan_result.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_0_support = len(self.scan_result.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites) > 0
        self.ssl3_support = len(self.scan_result.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites) > 0
        self.ssl2_support = len(self.scan_result.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites) > 0

        self.fallback_scsv = self.scan_result.scan_result.tls_fallback_scsv.result.supports_fallback_scsv

        self.session_ID_resumption = self.scan_result.scan_result.session_resumption.result.session_id_resumption_result
        self.tls_ticket_resumption = self.scan_result.scan_result.session_resumption.result.tls_ticket_resumption_result
        self.ticket_lifetime = None

        self.early_data_support = self.scan_result.scan_result.tls_1_3_early_data.result.supports_early_data
        self.max_early_data_size = None

        self.openSSL_tls13_scan = None




    def parse_scan_result(self):
        # Parse the scan result
        print(self.host)
        print("TLSv1.3 Support: ", self.tls1_3_support)
        print("TLSv1.2 Support: ", self.tls1_2_support)
        print("TLSv1.1 Support: ", self.tls1_1_support)
        print("TLSv1.0 Support: ", self.tls1_0_support)
        print("SSLv3.0 Support: ", self.ssl3_support)
        print("SSLv2.0 Support: ", self.ssl2_support)
        print("Fallback SCSV: ", self.fallback_scsv)
        print("Session ID resumption: ", self.session_ID_resumption)
        print("TLS Ticket resumption: ", self.tls_ticket_resumption)
        print("Ticket lifetime: ", self.ticket_lifetime)
        print("Early data support: ", self.early_data_support)
        print("Max early data size: ", self.max_early_data_size)
        print("")
        pass

    def parse_openSSL_tls13_scan_result(self, openSSL_scan_result):
        self.openSSL_tls13_scan = openSSL_scan_result
        splitted = openSSL_scan_result.split("\n")
        for entry in splitted:
            stripped = entry.strip()
            if stripped.startswith("TLS session ticket lifetime hint:"):
                secs = int(stripped.split(":")[1].strip().split(" ")[0])
                # print(entry.strip().split(":")[1].strip())
                # print(secs)
                self.ticket_lifetime = secs
                # break
            if stripped.startswith("Max Early Data:"):
                size = int(stripped.split(":")[1].strip().split(" ")[0])
                self.max_early_data_size = size
                # print(size)
                # break
        # ticket_lifetime = splitted.index("TLS session ticket lifetime hint")
        # print(splitted)


    def push_to_database(self, parsed_result):
        # Push the parsed result to the database
        pass
