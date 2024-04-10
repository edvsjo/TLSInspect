import sslyze
from sslyze import (
    ScanCommandAttemptStatusEnum,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
    ServerScanResult,
)
import pathlib
import scans
import parser
import csv
import database
from datetime import datetime
import json

def import_hosts(hosts_file, count=5, offset=0):
    """
    Imports the top n hosts from the provided csv file

    Args:
        hosts_file (str): The path to the csv file containing the hosts
        amount (int): The number of hosts to import
    Returns:
        hosts (list): The top n hosts from that list. Is sorted top to bottom
        hosts_rank (dict): A dictionary containing the rank of each host
    """
    hosts = []
    hosts_rank = {}
    i = 0
    with open(hosts_file) as csvfile:
        # spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            i += 1
            if i <= offset:
                continue
            # print(', '.join(row))
            splitted = ', '.join(row).split(",")
            hosts.append(splitted[1].strip())
            hosts_rank[splitted[1].strip()] = int(splitted[0].strip())
            if i >= count:
                break
    # print(hosts)
    return hosts, hosts_rank

# The following code is taken from the sslyze documentation
def example_json_result_output(
    json_file_out: pathlib.Path,
    server_scan_results: ServerScanResult,
    date_scans_started: datetime,
    date_scans_completed: datetime,
) -> None:
    json_output = SslyzeOutputAsJson(
        server_scan_results=[ServerScanResultAsJson.from_orm(server_scan_results)],
        invalid_server_strings=[],
        date_scans_started=date_scans_started,
        date_scans_completed=date_scans_completed,
    )
    json_output_as_str = json_output.json()
    json_file_out.write_text(json_output_as_str)


def main(amount=10000, offset=0):
    """
    Main function for the scanner.
    """

    # Import the hosts to scan and their rank
    # hosts, hosts_rank = import_hosts("top-1m.csv", amount)
    hosts, hosts_rank = import_hosts("top-1m.csv", amount, offset)
    # hosts = HOSTS

    print("Attempting to connect to database")
    # Create a database connection
    conn, cur = database.create_connection()
    print("Connected to database")

    scans_obj = scans.Scans(hosts)

    # Perform the sslyze scans
    all_server_scan_results = scans_obj.perform_scans()

    failed_scan = []

    # Count the number of hosts that has been scanned
    count = 0

    amount_invalid = len(scans_obj.invalid_hosts)

    # For each scan result from the sslyze scans we need to parse the result and do further scans
    for scan_result in all_server_scan_results.get_results():
        host = scan_result.server_location.hostname
        print(f"Progress: {count}, Scan result for: {host}")

        date_started = datetime.utcnow()

        # Commit the results to the database every 50 hosts to avoid losing too much data if the program crashes
        count += 1
        if count % 50 == 0:
            print(f"Scanned {count} hosts. Only {amount-count-amount_invalid-offset} left. Commiting results to database")
            conn.commit()

        # Tests if SSLyze was able to connect to the host. This weeds out most of the invalid hosts
        if scan_result.connectivity_error_trace:
            print("Error in SSLyze: ", scan_result.connectivity_error_trace)
            failed_scan.append(host)
            database.send_scan_fail(host, cur, "Failed to connect to host")
            continue

        else: 

            # Because of the asynchronous nature of the scans, we need to check if the scan result is ready
            if scan_result.scan_status != ScanCommandAttemptStatusEnum.COMPLETED:
                print("SSLyze did not complete ", host)
                failed_scan.append(host)
                database.send_scan_fail(host, cur, "SSLyze did not complete")
                continue

            try:
                parser_obj = parser.Parser(host, hosts_rank[host], scan_result)
            except AttributeError:
                print("Failed to parse: ", host)
                failed_scan.append(host)
                database.send_scan_fail(host, cur, "Failed to parse scan result")
                continue
            else:

                print(f"Parsing scan result for: ", host)
                # If the host supports TLS 1.3, we need to do a TLS 1.3 scan
                if parser_obj.tls1_3_support:
                    try: 
                        openSSL_scan_file, session_outfile = scans_obj.openSSL_tls13_request(host)
                        parser_obj.parse_openSSL_tls13_scan_result(openSSL_scan_file, session_outfile)
                        database.send_tls_session(parser_obj, cur, False)
                    # To catch the case where the host does not provide a tls 1.3 session to resume
                    except FileNotFoundError:
                        print(f"No TLS1.3 resumption file found {host}")
                        database.send_scan_fail(host, cur, "No resumption file")
                    except:
                        print(f"Something failed with TLS 1.3 scan for {host}")
                        database.send_scan_fail(host, cur, "Something failed with TLS 1.3 scan")
                    else:
                        database.send_tls_scan_raw(parser_obj, openSSL_scan_file, "TLS 1.3 scan", cur)

                # If the host supports TLS 1.3 ticket resumption and early data, we need to verify that it actually propperly supports it
                if parser_obj.psk_resumption_support and parser_obj.early_data_support:
                    try:
                        early_data_stdout = scans_obj.openSSL_tls13_early_data(host, parser_obj.openSSL_tls13_resumption_file, "earlytest.txt")
                        parser_obj.parse_openSSL_tls13_early_data(openSSL_early_data_file=early_data_stdout)
                        database.send_tls_scan_raw(parser_obj, early_data_stdout, "Early data scan", cur)
                    except:
                        print(f"Something failed with early data scan for {host}")
                        database.send_scan_fail(host, cur, "Something failed with early data scan")

                # If it supports both tls1.3 and lower versions, we need to do a scan to verify that it does support DOWNGRD protection from TLS 1.3
                if parser_obj.tls1_3_support and parser_obj.tls1_2_support:
                    try:
                        stdout_file = scans_obj.openSSL_DOWNGRD_test(host)
                        parser_obj.parse_openSSL_DOWNGRD_test(stdout_file)
                        database.send_tls_scan_raw(parser_obj, stdout_file, "DOWNGRD scan", cur)
                    except:
                        print(f"Something failed with downgrade scan for {host}")
                        database.send_scan_fail(host, cur, "Something failed with downgrade scan")

                try:
                    no_sni_test = scans_obj.openSSL_no_SNI_test(host)
                    parser_obj.parse_openSSL_no_SNI_test(no_sni_test)
                    database.send_tls_scan_raw(parser_obj, no_sni_test, "No SNI scan", cur)
                except:
                    print(f"Something failed with no SNI test for {host}")
                    database.send_scan_fail(host, cur, "Something failed with no SNI test")
                try:
                    database.send_certificate(parser_obj, cur)
                except:
                    print(f"Failed to send certificate to database for {host}")
                    database.send_scan_fail(host, cur, "Failed to send certificate to database")

                # parser_obj.parse_scan_result()
                # Send the scan result to the database
                # Save the sslyze scan result to a json file
                # json_path = pathlib.Path(f"scan_results/{host}.json")
                # print(f"Saving sslyze scan result to {json_path}")
                # example_json_result_output(json_path, scan_result, date_started, datetime.utcnow())

                database.send_scan_result(parser_obj, cur)

    print("Finished scanning all hosts. Commiting results to database")
    # Add the failed hosts to the database
    for host in scans_obj.invalid_hosts:
        failed_scan.append(host)
        database.send_scan_fail(host, cur, "Invalid hostname")
    print("Failed to connect to: ", failed_scan)
    print("That is a total of ", len(failed_scan), " hosts")

    conn.commit()

    # conn.rollback()
    conn.close()


if __name__ == "__main__":
    main(amount=100000, offset=90000)
    # import_hosts("top-1m.csv")
