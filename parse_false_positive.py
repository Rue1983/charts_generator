from collections import namedtuple
from collections import OrderedDict
from collections import Counter
import logging
import traceback
import os
import sqlite3
import re
import csv
import regex
import datetime

PIC_DIR = 'pictures/'
DB_NAME = 'alerts0614b.db'
FALSE_RESPONSE = [403]  # those response code that we need to check if it's false-positive


def get_data_from_db(id, db_name):
    """
    Get 1000 records from db in range of id : id +999 nd put it into pool
    :param id:
    :param db_name:
    :param data_pool:
    :return:
    """
    if os.path.isfile(db_name) is False:
        return -1
    pool_size = 10000
    #alerts_result = []
    global data_pool
    data_pool = {i: {'alert': ''} for i in range(id, id+pool_size)}
    conn = sqlite3.connect(db_name)
    conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
    c = conn.cursor()
    cursor = c.execute('select id,host,request,status,msg '
                       'from alerts where owasp is null and id>=%d and id<%d ' % (id, id+pool_size))
    for row in cursor:
        alerts_result = list(row)
        request_uri_raw = ''
        matchmsg = re.match(r'\'(https?://.*)\' not allowed', alerts_result[4])
        if matchmsg:
            request_uri_raw = matchmsg.group(1)
        alerts_result[4] = request_uri_raw
        uri = ''
        match_vars = re.match(r'(\w+) (.*) (HTTP/\d?.?\d?)$', alerts_result[2])
        if match_vars:
            uri = match_vars.group(2)
        alerts_result[2] = uri
        Alert = namedtuple('Alert', ['id', 'host', 'uri', 'status', 'request_uri_raw'])
        alert = Alert._make(alerts_result)
        data_pool[alert.id]['alert'] = alert
    conn.close()
    #print(data_pool)
#get_data_from_db(117777, DB_NAME)
# print(data_pool[117777])


def get_data(id, db_name):
    """
    Get all data by id and return 2 list for both alerts and request_headers table
    :param id:
    :return: 2 list
    """
    global data_pool
    if id not in data_pool:
        if os.path.isfile(db_name) is False:
            return -1
        else:
            get_data_from_db(id, db_name)
    #print(data_pool)
    return data_pool[id]['alert']
# get_data_from_db(117777, db_name)
# get_data(114791, "alertsbig.db")


def parse_false_positive(db_name):
    """
    Need to be run after modsec_charts.get_owasp_attack_type() so that owasp column exist in db.
    Get all potential false-positive url from db and put them into a csv file order by number.
    :param db_name: alerts db name
    :return:
    """
    dict_result = {}
    dict_numbers = {}
    start_id = 1
    get_data_from_db(start_id, db_name)
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    cursor = c.execute('select count(*) from alerts ')
    for row in cursor:
        rec_num = row[0]
    conn.close()
    for i in range(start_id, rec_num + 1):
        alert = get_data(i, db_name)
        if not alert:
            continue
        #print('\n', alert)
        print(alert)
        if alert.status not in FALSE_RESPONSE:
            continue
        if alert.uri in dict_numbers:
            dict_numbers[alert.uri] += 1
        else:
            dict_numbers[alert.uri] = 1
            dict_result[alert.uri] = alert
    ordered_result = OrderedDict(sorted(dict_numbers.items(), key=lambda t: t[1], reverse=True))
    print('\n', dict_numbers)
    print('\n', dict_result)
    print('\n', ordered_result)
    with open("%sfalse_positive_%s.csv" % (PIC_DIR, db_name[:-3]), 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(["URI", "host", "id", "request", "numbers"])
        for k in ordered_result.keys():
            csvwriter.writerow([k, dict_result[k].host, dict_result[k].id, dict_result[k].request_uri_raw, ordered_result[k]])
parse_false_positive(DB_NAME)