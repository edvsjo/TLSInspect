import psycopg2
from configparser import ConfigParser
import parser
import time
import datetime


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db

def create_connection():
    params = config(filename='Development code/Scanner/database.ini')

    conn = psycopg2.connect(**params)

    cur = conn.cursor()
    return conn, cur


def send_scan_result(parser_obj, cursor):
    sql = f""" INSERT INTO scan_result (
host,
time,
tls1_3_support,
tls1_2_support,
tls1_1_support,
tls1_0_support,
ssl3_support,
ssl2_support,
fallback_scsv,
support_DOWNGRD,
session_ID_resumption_support,
tls_ticket_resumption_support,
ticket_lifetime,
early_data_support,
max_early_data_size,
no_SNI_success)
VALUES
(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    values =[
    parser_obj.host, 
    datetime.datetime.now(),
    parser_obj.tls1_3_support, 
    parser_obj.tls1_2_support, 
    parser_obj.tls1_1_support,
    parser_obj.tls1_0_support, 
    parser_obj.ssl3_support,
    parser_obj.ssl2_support,
    parser_obj.fallback_scsv,
    parser_obj.support_DOWNGRD,
    parser_obj.session_ID_resumption_support,
    parser_obj.tls_ticket_resumption_support,
    parser_obj.ticket_lifetime,
    parser_obj.early_data_support,
    parser_obj.max_early_data_size,
    parser_obj.openSSL_no_SNI_success]
    try:
        cursor.execute(sql, values)
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
