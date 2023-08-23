

class Parser:
    def __init__(self, host, scan_result):
        self.host = host
        self.scan_result = scan_result

        self.tls1_3_support = None
        self.tls1_2_support = None
        self.tls1_1_support = None
        self.tls1_0_support = None
        self.ssl3_support = None
        self.ssl2_support = None    

        self.fallback_scsv = None

        self.early_data_support = None


    def parse_scan_result(self):
        # Parse the scan result
        # Return the parsed result
        self.supported_versions()
        self.downgrade_protection()
        

    def downgrade_protection(self):
        #TODO: Add DOWNGRD in server random check
        self.fallback_scsv = self.scan_result.scan_result.tls_fallback_scsv.result.supports_fallback_scsv

    def early_data(self):
        if self.tls1_3_support:
            self.early_data_support = self.scan_result.scan_result


    
    def supported_versions(self):
        self.tls1_3_support = len(self.scan_result.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_2_support = len(self.scan_result.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_1_support = len(self.scan_result.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites) > 0
        self.tls1_0_support = len(self.scan_result.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites) > 0
        self.ssl3_support = len(self.scan_result.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites) > 0
        self.ssl2_support = len(self.scan_result.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites) > 0

    def push_to_database(self, parsed_result):
        # Push the parsed result to the database
        pass
