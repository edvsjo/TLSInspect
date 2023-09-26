import sslyze
import psycopg2

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

        self.supported_versions = []
        if self.ssl2_support:
            self.supported_versions.append(0)
        if self.ssl3_support:
            self.supported_versions.append(1)
        if self.tls1_0_support:
            self.supported_versions.append(2)
        if self.tls1_1_support:
            self.supported_versions.append(3)
        if self.tls1_2_support:
            self.supported_versions.append(4)
        if self.tls1_3_support:
            self.supported_versions.append(5)
        

        self.fallback_scsv = self.scan_result.scan_result.tls_fallback_scsv.result.supports_fallback_scsv
        self.support_DOWNGRD = False

        self.session_ID_resumption_support = self.scan_result.scan_result.session_resumption.result.session_id_resumption_result == sslyze.TlsResumptionSupportEnum.FULLY_SUPPORTED
        self.tls_ticket_resumption_support = False
        self.ticket_lifetime = 0

        self.early_data_support = False
        self.max_early_data_size= 0

        self.openSSL_tls13_scan_file = None
        self.openSSL_tls13_resumption_file = None

        self.openSSL_DOWNGRD_scan_file = None

        self.openSSL_no_SNI_scan_file = None
        self.openSSL_no_SNI_success = False

        self.openSSL_early_data_scan_file = None
        self.openSSL_early_data_success = False

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
        print("DOWNGRD support: ", self.support_DOWNGRD)
        print("Session ID resumption: ", self.session_ID_resumption_support)
        print("TLS Ticket resumption: ", self.tls_ticket_resumption_support)
        print("Ticket lifetime: ", self.ticket_lifetime)
        print("Early data support: ", self.early_data_support)
        print("Max early data size: ", self.max_early_data_size)
        print("Early data success: ", self.openSSL_early_data_success)
        print("No SNI: ", self.openSSL_no_SNI_success)
        print("")
        pass

    def parse_openSSL_tls13_scan_result(self, openSSL_scan_file, openSSL_resumption_file):
        self.openSSL_tls13_scan_file = openSSL_scan_file
        self.openSSL_tls13_resumption_file = openSSL_resumption_file

        f = open(openSSL_scan_file, "r")
        file_content = f.read()
        splitted = file_content.split("\n")
        for entry in splitted:
            stripped = entry.strip()

            if stripped.startswith("TLS session ticket lifetime hint:"):
                secs = int(stripped.split(":")[1].strip().split(" ")[0])
                self.ticket_lifetime = secs
                self.tls_ticket_resumption_support = True
            
            if stripped.startswith("Max Early Data:"):
                size = int(stripped.split(":")[1].strip().split(" ")[0])
                self.max_early_data_size = size
                self.early_data_support = True if size != 0 else False
            
        # if ("Max Early Data: 0" in file_content):
        #     self.early_data_support = False
        #     self.max_early_data_size = 0
    
    # def parse_openSSL_tls13_resumption(self, openSSL_resumption_file):
    #     self.openSSL_tls13_resumption_file = openSSL_resumption_file

    #     f = open(openSSL_resumption_file, "r")
    #     file_content = f.read()
    #     splitted = file_content.split("\n")
    #     for entry in splitted:
    #         stripped = entry.strip()

    #         if stripped.startswith("TLS session ticket lifetime hint:"):
    #             secs = int(stripped.split(":")[1].strip().split(" ")[0])
    #             self.ticket_lifetime = secs
    #             self.tls_ticket_resumption_support = True
            
    #         if stripped.startswith("Max Early Data:"):
    #             size = int(stripped.split(":")[1].strip().split(" ")[0])
    #             self.max_early_data_size = size
    #             self.early_data_support = True


    def parse_openSSL_DOWNGRD_test(self, openSSL_DOWNGRD_file):
        self.openSSL_DOWNGRD_scan_file = openSSL_DOWNGRD_file

        f = open(openSSL_DOWNGRD_file, "r")
        file_content = f.read()
        splitted = file_content.split("\n")
        bytes_DOWNGRD = "444f574e475244"
        total_hex = []
        for entry in splitted:
            only_hex = entry.strip()[7:-19].replace(" ", "")
            total_hex.append(only_hex)
        
        total_hex = "".join(total_hex)
        self.support_DOWNGRD = bytes_DOWNGRD in total_hex

    def parse_openSSL_no_SNI_test(self, openSSL_no_SNI_file):
        self.openSSL_no_SNI_scan_file = openSSL_no_SNI_file

        f = open(openSSL_no_SNI_file, "r")
        file_content = f.read()

        #TODO find a better way to check if handshake was successful
        if "New, TLSv" in file_content:
            self.openSSL_no_SNI_success = True
        
    def parse_openSSL_tls13_early_data(self, openSSL_early_data_file):
        f = open(openSSL_early_data_file, "r")
        file_content = f.read()
        splitted = file_content.split("\n")
        for entry in splitted:
            stripped = entry.strip()
            # print(stripped)
            if stripped.startswith("Early data was accepted"):
                self.openSSL_early_data_success = True
                break


    def push_to_database(self, parsed_result):
        # Push the parsed result to the database
        pass
