from collections import namedtuple
from collections import OrderedDict
from collections import Counter
import logging
import traceback
import os
import sqlite3
import re
import csv
import requests
import regex
import datetime
from concurrent.futures import ThreadPoolExecutor

PIC_DIR = 'pictures/'
DB_NAME = 'alerts0827.db'
FALSE_RESPONSE = set([403])  # those response code that we need to check if it's false-positive
TRUE_RESPONSE = set([404]) # Those response code that make the url true-positive


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
    cursor = c.execute('select id,host,request,status,msg,reason,method '
                       'from alerts where owasp is null and id>=%d and id<%d ' % (id, id+pool_size))
    for row in cursor:
        alerts_result = list(row)
        if alerts_result[5] == 20:
            # skip license error
            continue
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
        Alert = namedtuple('Alert', ['id', 'host', 'uri', 'status', 'request_uri_raw', 'reason', 'method'])
        alert = Alert._make(alerts_result)
        data_pool[alert.id]['alert'] = alert
    conn.close()
    #print(data_pool)
#get_data_from_db(117777, DB_NAME)
#print(data_pool[117777])


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


def get_url_response(url):
    url_str = url[0]
    # url_str = url[0].replace('xsh_gxun', 'xsh.gxun', 1)
    method_code = url[1]
    try:
        if method_code == 1:
            r = requests.get(url_str, timeout=6)
        elif method_code == 2:
            r = requests.post(url_str, timeout=6)
        elif method_code == 3:
            r = requests.put(url_str, timeout=6)
        elif method_code == 4:
            r = requests.head(url_str, timeout=6)
        elif method_code == 5:
            #TODO: handle trace here but requests does not have trace function
            return 0
            pass
        elif method_code == 6:
            r = requests.options(url_str, timeout=6)
        elif method_code == 0:
            # TODO: handle PROPFIND/Connection here but requests does not have trace function
            return 0
            pass
        else:
            raise ValueError("Unknown http method number")
    except requests.exceptions.RequestException as e:
        print(e)
        return 0
    #print(r.status_code)
    r.close()
    return r.status_code
    # r = requests.get('https://api.github.com/events')
    # print(r.status_code)
#get_url_response('https://api.github.com/events', 5)


def check_url_response_concurrently(urls_list):
    url_sections = []
    concurrent = 5
    ret = []
    while urls_list:
        url_sections.append(urls_list[:concurrent])
        del (urls_list[:concurrent])
    with ThreadPoolExecutor(concurrent) as executor:
        for url in url_sections:
            if len(url) < 5:
                for u in url:
                    tmp = executor.submit(get_url_response, u)
                    ret.append(tmp.result())
            else:
                a = executor.submit(get_url_response, url[0])
                b = executor.submit(get_url_response, url[1])
                c = executor.submit(get_url_response, url[2])
                d = executor.submit(get_url_response, url[3])
                e = executor.submit(get_url_response, url[4])
                for i in a, b, c, d, e:
                    ret.append(i.result())
    #print(ret)
    return ret


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
    # get alerts data from db and put into pool
    get_data_from_db(start_id, db_name)
    # get number of records in alerts
    conn = sqlite3.connect(db_name)
    conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
    c = conn.cursor()
    cursor = c.execute('select count(*) from alerts ')
    for row in cursor:
        rec_num = row[0]
    conn.close()

    for i in range(start_id, rec_num + 1):
        alert = get_data(i, db_name)
        if not alert:
            continue
        print('\n', alert)
        if alert.status not in FALSE_RESPONSE:
            continue
        # if reason is invalid web server name or method
        elif alert.reason == 12 or alert.reason == 14:
            continue
        # if alert.request_uri_raw:
        #     response_code = get_url_response(alert.request_uri_raw, alert.method)
        #     if response_code in TRUE_RESPONSE:
        #         print('-------------catch 404 here')
        #         true_positive.add(alert.uri)
        #         continue
        # else:
        #     #TODO: make url from host and uri here
        #     pass

        if alert.uri in dict_numbers:
            dict_numbers[alert.uri] += 1
        else:
            dict_numbers[alert.uri] = 1
            dict_result[alert.uri] = alert
    # sorted dict by descend {uri:number}
    ordered_result = OrderedDict(sorted(dict_numbers.items(), key=lambda t: t[1], reverse=True))
    ordered_uri = list(ordered_result.keys())
    # sorted url get from msg or host+uri
    ordered_url = []
    for k in ordered_result.keys():
        if dict_result[k].request_uri_raw:
            ordered_url.append([dict_result[k].request_uri_raw, dict_result[k].method])
        else:
            # TODO: make url from host and uri here, need to determine http or https
            ordered_url.append(['http://' + dict_result[k].host + dict_result[k].uri, dict_result[k].method])
    print('====++++==== ordered url is : ', ordered_url)
    ordered_status = check_url_response_concurrently(ordered_url)
    print('====++++==== ordered status is : ', ordered_status)
    for i, status in enumerate(ordered_status):
        if status in TRUE_RESPONSE:
            del(ordered_result[ordered_uri[i]])
            del(dict_result[ordered_uri[i]])
    #print('\n', dict_numbers)
    # print('\n', dict_result)
    #print('\n', ordered_result)
    with open("%sfalse_positive_%s.csv" % (PIC_DIR, db_name[:-3]), 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(["URI", "host", "id", "request", "numbers"])
        for k in ordered_result.keys():
            csvwriter.writerow([k, dict_result[k].host, dict_result[k].id, dict_result[k].request_uri_raw, ordered_result[k]])
starttime = datetime.datetime.now()
parse_false_positive(DB_NAME)
endtime = datetime.datetime.now()
print('-----total time cost------', endtime - starttime)
