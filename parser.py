import sslyze
import psycopg2
import re
import cryptography
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import OCSPResponseStatus
from sslyze import (
    CertificateInfoScanResult,
    CertificateInfoExtraArgument,
)
import datetime

class Parser:
    def __init__(self, host, tranco_rank, scan_result):
        """
        Initialize the Parser object.

        :param host: The hostname or IP address of the target.
        :param scan_result: The scan result object from sslyze.
        """
        self.host = host
        self.scan_result = scan_result

        # Check TLS and SSL protocol versions supported by the host
        self.tls1_3_support = self.scan_result.scan_result.tls_1_3_cipher_suites.result.is_tls_version_supported
        self.tls1_2_support = self.scan_result.scan_result.tls_1_2_cipher_suites.result.is_tls_version_supported
        self.tls1_1_support = self.scan_result.scan_result.tls_1_1_cipher_suites.result.is_tls_version_supported
        self.tls1_0_support = self.scan_result.scan_result.tls_1_0_cipher_suites.result.is_tls_version_supported
        self.ssl3_support = self.scan_result.scan_result.ssl_3_0_cipher_suites.result.is_tls_version_supported
        self.ssl2_support = self.scan_result.scan_result.ssl_2_0_cipher_suites.result.is_tls_version_supported

        pat = r"[^_]name='(\S*)'"
        self.tls1_3_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites)):
            self.tls1_3_ciphers.append(str(cipher))

        self.tls1_2_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites)):
            self.tls1_2_ciphers.append(str(cipher))

        self.tls1_1_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites)):
            self.tls1_1_ciphers.append(str(cipher))

        self.tls1_0_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites)):
            self.tls1_0_ciphers.append(str(cipher))

        self.ssl3_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites)):
            self.ssl3_ciphers.append(str(cipher))

        self.ssl2_ciphers = []
        for cipher in re.findall(pat, str(self.scan_result.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites)):
            self.ssl2_ciphers.append(str(cipher))

        # Check for various SSL/TLS features and initialize related attributes
        self.fallback_scsv = self.scan_result.scan_result.tls_fallback_scsv.result.supports_fallback_scsv
        self.support_DOWNGRD = False

        # Check for TLS 1.2 resumption modes
        self.session_ID_resumption_support = self.scan_result.scan_result.session_resumption.result.session_id_resumption_result == sslyze.TlsResumptionSupportEnum.FULLY_SUPPORTED
        self.session_ticket_support = self.scan_result.scan_result.session_resumption.result.tls_ticket_resumption_result == sslyze.TlsResumptionSupportEnum.FULLY_SUPPORTED

        # TLS 1.3 resumption general info
        self.psk_resumption_support = False
        self.ticket_lifetime = 0
        self.ticket_start_time = 0

        # TLS 1.3 early data support
        self.early_data_support = self.scan_result.scan_result.tls_1_3_early_data.result.supports_early_data == True
        self.max_early_data_size= 0
        self.openSSL_early_data_scan_file = None
        self.openSSL_early_data_success = False

        # File paths for various tests
        self.openSSL_tls13_scan_file = None
        self.openSSL_tls13_resumption_file = None

        self.openSSL_DOWNGRD_scan_file = None

        self.openSSL_no_SNI_scan_file = None
        self.openSSL_no_SNI_success = False

        self.top_level_domain = self.host.split(".")[-1]

        self.tranco_rank = tranco_rank

        # Parse the certificate info
        leaf_cert = scan_result.scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0]
        self.certificate = leaf_cert.public_bytes(Encoding.PEM).decode("utf-8")

        self.start_date = leaf_cert.not_valid_before

        self.end_date = leaf_cert.not_valid_after

        self.certificate_chain = ""
        try: 
            for cert in scan_result.scan_result.certificate_info.result.certificate_deployments[0].verified_certificate_chain:
                chain_cert_name = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
                # print(chain_cert_name[0].value)
                self.certificate_chain += chain_cert_name[0].value + ", "
        except:
            self.certificate_chain += "Unknown, "

        try: 
            self.issuer = leaf_cert.issuer.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
        except:
            self.issuer = "Unknown"

        self.key_size = leaf_cert.public_key().key_size

        self.signature_Algorithm = leaf_cert.signature_algorithm_oid._name

        self.public_key_algorithm = leaf_cert.public_key().__str__()

        self.subject_alt_names = ""
        try: 
            alts = leaf_cert.extensions.get_extension_for_oid(cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for alt in alts.value.__str__().split(","):
                if "DNS" in alt:
                    name = alt.split("=")[1]
                    self.subject_alt_names += name[1 : name.rfind("'")] + ", "
        except:
            self.subject_alt_names += "None, "

        self.ocsp_response_success = False
        if scan_result.scan_result.certificate_info.result.certificate_deployments[0].ocsp_response is not None:
            self.ocsp_response_success = scan_result.scan_result.certificate_info.result.certificate_deployments[0].ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL

    def parse_scan_result(self):
        """
        Print various attributes of the scan result.
        """
        print(self.host)
        print("-----------------Version Support-----------------")
        print("TLSv1.3 Support: ", self.tls1_3_support)
        print("TLSv1.2 Support: ", self.tls1_2_support)
        print("TLSv1.1 Support: ", self.tls1_1_support)
        print("TLSv1.0 Support: ", self.tls1_0_support)
        print("SSLv3.0 Support: ", self.ssl3_support)
        print("SSLv2.0 Support: ", self.ssl2_support)
        print("TLSv1.3 Ciphers: ", self.tls1_3_ciphers)
        print("TLSv1.2 Ciphers: ", self.tls1_2_ciphers)
        print("TLSv1.1 Ciphers: ", self.tls1_1_ciphers)
        print("TLSv1.0 Ciphers: ", self.tls1_0_ciphers)
        print("SSLv3.0 Ciphers: ", self.ssl3_ciphers)
        print("SSLv2.0 Ciphers: ", self.ssl2_ciphers)
        print("-----------------Downgrade-----------------")
        print("Fallback SCSV: ", self.fallback_scsv)
        print("DOWNGRD support: ", self.support_DOWNGRD)
        print("-----------------Resumption-----------------")
        print("Session ID resumption: ", self.session_ID_resumption_support)
        print("Session Ticket resumption: ", self.session_ticket_support)
        print("PSK resumption support: ", self.psk_resumption_support)
        print("Ticket lifetime: ", self.ticket_lifetime)
        print("Ticket start time: ", self.ticket_start_time)
        print("Early data support: ", self.early_data_support)
        print("Max early data size: ", self.max_early_data_size)
        print("OpenSSL early data success: ", self.openSSL_early_data_success)
        print("-----------------Misc-----------------")
        print("No SNI: ", self.openSSL_no_SNI_success)
        print("Tranco rank: ", self.tranco_rank)
        print("Top level domain: ", self.top_level_domain)
        print("")
        pass

    def parse_openSSL_tls13_scan_result(self, openSSL_scan_file, openSSL_resumption_file):
        self.openSSL_tls13_scan_file = openSSL_scan_file
        self.openSSL_tls13_resumption_file = openSSL_resumption_file

        with open(openSSL_scan_file, "r") as f:
            file_content = f.read()
            splitted = file_content.split("\n")
            exitcon = False
            for entry in splitted:
                stripped = entry.strip()

                # if stripped.startswith("Protocol  : TLSv1.2"):
                if "Protocol  : TLSv1.2" in stripped:
                    print(f"The {self.host} sent a TLSv1.2 session to resume, when attempting to resume TLS 1.3!")
                    break

                if "Protocol  : TLSv1.3" in stripped:
                    self.psk_resumption_support = True
                    continue

                if "TLS session ticket lifetime hint:" in stripped:
                    secs = int(stripped.split(":")[1].strip().split(" ")[0])
                    self.ticket_lifetime = secs
                    continue

                if "Start Time:" in stripped:
                    time = int(stripped.split(":")[1].strip().split(" ")[0])
                    self.ticket_start_time = time
                    continue

                if "Max Early Data:" in stripped:
                    size = int(stripped.split(":")[1].strip().split(" ")[0])
                    self.max_early_data_size = size
                    if self.ticket_lifetime != 0 and self.ticket_start_time != 0 and self.psk_resumption_support:
                        break

    def parse_openSSL_tls13_resumption(self, openSSL_resumption_file):
        self.openSSL_tls13_resumption_file = openSSL_resumption_file

        with open(openSSL_resumption_file, "r") as f:
            file_content = f.read()
            splitted = file_content.split("\n")
            for entry in splitted:
                stripped = entry.strip()
                if stripped.startswith("Protocol  : TLSv1.2"):
                    print(f"The {self.host} sent a TLSv1.2 session to resume, when attempting to resume TLS 1.3!")
                    break

                if stripped.startswith("TLS session ticket lifetime hint:"):
                    secs = int(stripped.split(":")[1].strip().split(" ")[0])
                    self.ticket_lifetime = secs
                    self.psk_resumption_support = True

                if stripped.startswith("Max Early Data:"):
                    size = int(stripped.split(":")[1].strip().split(" ")[0])
                    self.max_early_data_size = size
                    self.early_data_support = True

    def parse_openSSL_DOWNGRD_test(self, openSSL_DOWNGRD_file):
        """
        Parse the OpenSSL DOWNGRD test results.

        :param openSSL_DOWNGRD_file: Path to the OpenSSL DOWNGRD test results file.
        """
        self.openSSL_DOWNGRD_scan_file = openSSL_DOWNGRD_file

        with open(openSSL_DOWNGRD_file, "r") as f:
            file_content = f.read()
            splitted = file_content.split("\n")
            bytes_DOWNGRD = "444f574e475244"
            total_hex = []
            for entry in splitted:
                only_hex = entry.strip()[7:-19].replace(" ", "").replace("-", "")
                total_hex.append(only_hex)

            total_hex = "".join(total_hex)
            self.support_DOWNGRD = bytes_DOWNGRD in total_hex

    def parse_openSSL_no_SNI_test(self, openSSL_no_SNI_file):
        self.openSSL_no_SNI_scan_file = openSSL_no_SNI_file

        with open(openSSL_no_SNI_file, "r") as f:
            file_content = f.read()

            # TODO find a better way to check if handshake was successful
            if "New, TLSv" in file_content:
                self.openSSL_no_SNI_success = True

    def parse_openSSL_tls13_early_data(self, openSSL_early_data_file):
        self.openSSL_early_data_scan_file = openSSL_early_data_file

        with open(openSSL_early_data_file, "r") as f:
            file_content = f.read()
            splitted = file_content.split("\n")
            for entry in splitted:
                stripped = entry.strip()
                # print(stripped)
                if stripped.startswith("Early data was accepted"):
                    self.openSSL_early_data_success = True
                    break
