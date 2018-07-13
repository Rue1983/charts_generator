from collections import namedtuple
from collections import defaultdict
from collections import OrderedDict
from collections import Counter
from timeout import timeout
import timeout
import errno
import logging
import traceback
import os
import sqlite3
import re
import regex
import datetime
import logging
import csv
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

regex.DEFAULT_VERSION = regex.V1
ZY_RULE_FILE = "zy_rules_new.conf"  # File we write parsed rules into.
RULES_DIR = "rules"
DROP_LIST = set(['REQBODY_ERROR', 'MULTIPART_STRICT_ERROR', 'IP:REPUT_BLOCK_FLAG', 'XML:/*', 'RESPONSE_BODY', 'FILES'])
WAITING_LIST = set(['FILES_NAMES', 'REQUEST_BODY', 'TX:MAX_NUM_ARGS', 'TX:ARG_NAME_LENGTH', 'TX:ARG_LENGTH',
                'TX:TOTAL_ARG_LENGTH', 'TX:MAX_FILE_SIZE', 'COMBINED_FILE_SIZES'])
COOKIE = 'Cookie'
db_name = 'alerts0709.db'
PIC_DIR = 'pictures/'
result_file_name = "%smodsec_result_%s.csv" % (PIC_DIR, db_name[:-3])


def get_all_variable_types(file_name):
    if not isinstance(file_name, str):
        raise TypeError('bad operand type')
    ret = []
    op = []
    with open(file_name, 'r', encoding='ansi') as f:
        for line in f.readlines():
            list_line = line.split('\t')
            a = list_line[2].split('|')
            op.append(list_line[3][:10])
            for i in a:
                ret.append(i)
    new_ret = list(set(ret))
    new_ret.sort(key=ret.index)
    logger.info('%s\n%s' % (new_ret, op))


def get_all_operator_types(file_name):
    ret = []
    op = []
    if not isinstance(file_name, str):
        raise TypeError('bad operand type')
    with open(file_name, 'r', encoding='ansi') as f:
        for line in f.readlines():
            list_line = line.split('\t')
            ret.append(list_line[3])
    for i in ret:
        ii = i.strip('"')
        matchobj = re.match(r'^!*@*(\w+) .*', ii)
        if matchobj:
            op.append(matchobj.group(1))
        matchobj = re.match(r'^!*@*(\w+)', ii)
        print(matchobj)
        if matchobj:
            op.append(matchobj.group(1))
    new_ret = list(set(op))
    new_ret.sort(key=op.index)
    for i in new_ret:
        print(i)
    return new_ret


def get_all_rules(filename):
    """
    Get all rules from given file which is saved rules we collect from modSecurity
    :param filename:
    :return: all rules and all files' data in 2 dicts
    """
    dict_rules = OrderedDict()
    dict_datafiles = {}
    dt = []
    rule_keys = ['message', 'variables', 'oprators', 'chain']
    chain_keys = ['variables', 'oprators']
    Rules = namedtuple('Rule', ['message', 'variables', 'oprators'])
    with open(filename, 'r', encoding='UTF-8') as f:
        for line in f.readlines():
            if line.startswith('#'):
                # Ignore comments
                continue
            li = line.split('\t')
            dict_rule = dict(zip(rule_keys, li[1:4]))
            if len(li) > 4:  # handle chain rule if any
                chain = {}
                for chain_rule in li[4:]:
                    if chain_rule:
                        mo = re.match(r'^SecRule (.*) "(.*)"$', chain_rule.strip('\n\r'))
                        if mo:
                            tmp_list = [mo.group(1), mo.group(2)]
                            if chain:
                                chain['chain']['chain'] = dict(zip(chain_keys, tmp_list))
                            else:
                                chain['chain'] = dict(zip(chain_keys, tmp_list))
                        else:
                            print("failed to match rule: %s" % line)
                dict_rule['chain'] = chain['chain']
                #print('chain rule is:', dict_rule)
            dict_rules[li[0]] = dict_rule
            if li[3].strip('"\n\r').lower().startswith('@pmf'):
                data_file_name = li[3].strip('"\n\r').split(' ')[1]
                dt.append(data_file_name)
    for file in dt:
        f_path = '%s\\%s' % (RULES_DIR, file)
        f_list = []
        with open(f_path, 'r', encoding='UTF-8') as f:
            for line in f.readlines():
                if line and not line.startswith('#'):
                    f_list.append(line.rstrip('\n'))
        if f_list:
            dict_datafiles[file] = set(f_list)
    #print(dict_rules, '\n', dict_datafiles)
    return dict_rules, dict_datafiles
#get_all_rules(ZY_RULE_FILE)


def get_vars_from_request(request):
    args_dict = {}
    args_get = []
    args_get_names = []
    request_filename = ''
    request_basename = ''
    query_string = ''
    method = ''
    uri = ''
    request_protocol = ''
    ret = []
    if request is None:
        # return empty list if request is None, number should be the same as the normal return.
        return [''] * 8
    match_vars = re.match(r'(\w+) (.*) (HTTP/\d?.?\d?)$', request)
    if match_vars:
        method = match_vars.group(1)
        uri = match_vars.group(2)
        request_protocol = match_vars.group(3)

    sector = uri.split('?')
    request_filename = sector[0]
    request_basename = request_filename.split('/')[-1]
    if len(sector) > 1:
        loc = uri.find('?')
        query_string = uri[loc+1:]
    if '=' in uri:
        tmp = []
        for s in sector:
            tmp = tmp + s.split('&')
        for t in tmp:
            arg = t.split('=')
            if len(arg) > 1:
                arg[0] = arg[0].split('/')[-1]
                args_dict[arg[0]] = arg[1]
                args_get_names.append(arg[0])
                args_get.append('%s:%s' % (arg[0], arg[1]))
    args_get_names = list(args_dict.keys())
    #args_get = set(args_get)
    #print('args_get:%s\nargs_get_names:%s\n request_filename:%s\n request_basename:%s\n '
     #     'query_string:%s\n method:%s\n uri:%s\n request_protocol:%s\n'
     #     % (args_get, args_get_names, request_filename, request_basename, query_string, method, uri, request_protocol))
    ret = []
    ret.append(method)
    ret.append(args_get)
    ret.append(args_get_names)
    ret.append(request_filename)
    ret.append(request_basename)
    ret.append(query_string)
    ret.append(request_protocol)
    ret.append(uri)
    return ret    #args_get, args_get_names, request_filename, request_basename, query_string, method, uri, request_protocol
# request = 'GET /bemarket/shop/index.php?pageurl=viewpage&filename=../../../../../../../../../../../../../../etc/passwd HTTP/1.1'
# request2 = 'GET /htgrep/file=index.html&hdr=/etc/passwd HTTP/2'
# request3 = 'GET /scripts/script/cat_for_gen.php?ad=1&ad_direct=../&m_for_racine=%3C/option%3E%3C/SELECT%3E%3C?phpinfo();?%3E HTTP/1.1'
# request4 = 'GET /scripts/script/cat_for_gen.php?ad=1&ad_direct=../&m_for_racine=</option></SELECT><?phpinfo();?> HTTP/0.9'
# request5 = 'GET /portal/js/)&&m.contains(h,d)&&(d.src?m._evalUrl&&m._evalUrl(d.src):m.globalEval((d.text||d.textContent||d.innerHTML|| HTTP/2'
# request6 = 'GET /browserconfig.xml HTTP/1.1'
# get_vars_from_request(request5)


@timeout.timeout(10)
def execute_rule(alert, header, rule, chain=False, matched=[]):
    """
    Make a list of rule result for each variable, and return list lenth, if it's true which means record match the rule.
    :param alert:
    :param header:
    :param rule:
    :param chain: if it has chain rule
    :param matched: if chain rule has matched some variables
    :return:
    """
    ret = []
    logger.debug('Rule is: %s' % rule)
    if chain and matched:
        variables = matched
    else:
        variables = parse_variables(alert, header, rule['variables'])
        if variables is None:
            return ret
    operators = rule['oprators']
    operators = operators.strip('"\n\r')
    if operators.endswith('"'):
        operators = operators[:-1]
    is_op_neg = 0
    if operators.startswith('!@'):
        is_op_neg = 1
        operators = operators.strip('!')
    if not variables:
        return ret
    for v in variables:
        if operators.startswith('@rx '):
            operators = operators[4:]
            if type(v) == list:
                for s in v:
                    matchobj = regex.search(r'%s' % operators, str(s))
                    if matchobj or is_op_neg:
                        ret.append(matchobj.group(0))
                        continue
            else:
                matchobj = regex.search(r'%s' % operators, str(v))
                if matchobj or is_op_neg:
                    ret.append(matchobj.group(0))
                else:
                    continue
        elif not operators.startswith('@'):
            if operators != '^$' and not v and not is_op_neg:
                continue
            if type(v) == list:
                for s in v:
                    matchobj = regex.search(r'%s' % operators, str(s))
                    if matchobj or is_op_neg:
                        ret.append(matchobj.group(0))
                        continue
            else:
                matchobj = regex.search(r'%s' % operators, str(v))
                if matchobj or is_op_neg:
                    ret.append(matchobj.group(0))
                else:
                    continue
        elif operators.lower().startswith('@pmf'):  # @pmf equal to @pmFromFiles
            if not v:
                continue
            file_name = operators.split(' ')[1]
            if type(v) == list:
                for s in v:
                    for op in DATA_FILES[file_name]:
                        if op in s:
                            ret.append(s)
                            continue
            else:
                for op in DATA_FILES[file_name]:
                    if op in v:
                        ret.append(v)
                        continue
        elif operators.lower().startswith('@pm'):
            if not v:
                continue
            op_list = operators.split(' ')[1:]
            for op in op_list:
                if op in str(v):
                    ret.append(str(v))
                    continue
        elif operators.startswith('@eq'):
            if not v:
                continue
            if (int(operators[4:]) == int(v)) or is_op_neg:
                ret.append('1')
        elif operators.startswith('@validateByteRange'):
            if not v:
                continue
            if type(v) == list:
                pass
            else:
                pass
        elif operators.startswith('@within'):
            pass  # only one rule use it to check allowed http version which is not we care about.
        elif operators.startswith('@endsWith'):
            if v and str(v).endswith(operators[10:]):
                    ret.append('1')
        elif operators == '@ParaPollution':  # handle rule 921170
            if v:
                counter = Counter(v)
                for key in counter.keys():
                    if int(counter[key]) > 1:
                        ret.append(key)
            pass
        elif operators.startswith('@detectXSS'):
            pass
        elif operators.startswith('@detectSQLi'):
            pass
        elif operators.startswith('@validateUrlEncoding'):
            pass
        elif operators.startswith('@ge'):
            pass
        elif operators.startswith('@beginsWith'):
            pass
        elif operators.startswith('@gt'):
            pass
        else:
            pass
            #raise ValueError('Unsupported modSecurity operator found!')
    return ret


def parse_variables(alerts, headers, variables):
    """
    Parse variables input, remove unsupported and duplicate items, get data for the rest ones and return in a list.
    :param alerts:
    :param headers:
    :param variables:
    :return: a list of data
    """
    new_vars = []
    if not isinstance(variables, str):
        raise TypeError('bad operand type')
    if alerts.reason == 20:
        # Return none if the alert is just license verification failure.
        return None
    list_var = variables.split('|')
    list_var.sort()  # Put ! and & items at the beginning
    for v in list_var:
        nv = v.lstrip('!&')
        if nv in DROP_LIST or nv in WAITING_LIST:
            continue
        else:
            new_vars.append(v)
    real_var = []
    if len(new_vars) != 0:
        for v in new_vars:
            if v.lstrip('!&').startswith('REQUEST_HEADERS:'):
                variable_name = v.split(':')[1]
                if len(headers) == 0:
                    continue
                if not headers[variable_name]:
                    continue
                elif v.startswith('!') and headers[variable_name]:
                    headers.pop(variable_name)
                elif v.startswith('&'):
                    real_var.append(len(headers[variable_name]))
                else:
                    real_var.append(headers[variable_name])
                continue
            elif v.lstrip('!&').startswith('REQUEST_COOKIES:'):
                cookie_name = v.split(':')[1]
                if len(headers) == 0:
                    continue
                elif not headers[COOKIE]:
                    continue
                elif v.startswith('!'):
                    if headers[COOKIE][cookie_name]:
                        headers[COOKIE].pop(cookie_name)
                elif v.startswith('&'):
                    real_var.append(len(headers[COOKIE][cookie_name]))
                else:
                    real_var.append(headers[COOKIE][cookie_name])
                continue
            elif v.lstrip('!&') == 'REQUEST_HEADERS':
                whole_header = []
                if not headers:
                    continue  # real_var.append('')
                for (key, value) in headers.items():
                    if key == COOKIE and headers[key]:
                        whole_cookie = []
                        for c_key, c_value in headers[key].items():
                            whole_cookie.append('%s;%s' % (c_key, c_value))
                        whole_header.extend(whole_cookie)
                    else:
                        whole_header.append('%s:%s' % (key, value))
                real_var.append(whole_header)
            elif v == 'REQUEST_HEADERS_NAMES':
                if len(headers):
                    real_var.append(list(headers.keys()))  # real_var.append('')
            elif v == 'REQUEST_COOKIES_NAMES':
                if not headers or len(headers[COOKIE]) == 0:
                    continue  # real_var.append('')
                else:
                    real_var.append(list(headers[COOKIE].keys()))
            elif v == 'ARGS_GET' or v == 'ARGS':
                #print('captured args: %s' % alerts.args_get)
                if alerts.args_get:
                    real_var.append(alerts.args_get)
            elif v == 'ARGS_GET_NAMES' or v == 'ARGS_NAMES':
                #print('captured args_names: %s' % alerts.args_get_names)
                if len(alerts.args_get_names):
                    real_var.append(alerts.args_get_names)
            elif v == 'REQUEST_URI':
                if alerts.uri:
                    real_var.append(alerts.uri)
            elif v == 'REQUEST_LINE':
                real_var.append(alerts.request)
            elif v == 'RESPONSE_STATUS':
                #print('captured RESPONSE_STATUS: %s' % alerts.status)
                real_var.append(alerts.status)
            elif v == 'REQUEST_PROTOCOL':
                real_var.append(alerts.request_protocol)
            elif v == 'QUERY_STRING':
                if alerts.query_string:
                    real_var.append(alerts.query_string)
            elif v == 'REQUEST_BASENAME':
                if alerts.request_basename:
                    real_var.append(alerts.request_basename)
            elif v == 'REQUEST_FILENAME':
                if alerts.request_filename:
                    real_var.append(alerts.request_filename)
            elif v == 'REQUEST_METHOD':
                real_var.append(alerts.method)
            elif v == 'REQUEST_URI_RAW':
                if alerts.request_uri_raw:
                    real_var.append(alerts.request_uri_raw)
    #print('return parsed vars are : ', real_var)
    return real_var


def get_data_from_db(id, db_name):
    """
    Get 10000 records from db in range of id : id +999 nd put it into pool
    :param id:
    :param db_name:
    :return:
    """
    if os.path.isfile(db_name) is False:
        return -1
    pool_size = 10000
    logger.info('Getting data from db: from %d to %d' % (id, id + pool_size - 1))
    header_result = defaultdict(lambda: '')
    alerts_result = []
    global data_pool
    data_pool = {i: {'alert': '', 'header': ''} for i in range(id, id+pool_size)}
    conn = sqlite3.connect(db_name)
    conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
    c = conn.cursor()
    cursor = c.execute('select id,ip,remoteName,request,status,host,msg,reason '
                       'from alerts where id>=%d and id<%d' % (id, id+pool_size))
    for row in cursor:
        alerts_result = list(row)
        request_uri_raw = ''
        matchmsg = re.match(r'\'(https?://.*)\' not allowed', alerts_result[6])
        if matchmsg:
            request_uri_raw = matchmsg.group(1)
        alerts_result[6] = request_uri_raw
        request_vars = get_vars_from_request(alerts_result[3])
        # if request_vars is None:
        #    logger.error('TypeError found in %s' % alerts_result)
        Alert = namedtuple('Alert', ['id', 'ip', 'remotename', 'request', 'status', 'host', 'request_uri_raw',
                                     'reason', 'method', 'args_get', 'args_get_names', 'request_filename',
                                     'request_basename', 'query_string', 'request_protocol', 'uri'])
        alerts_result.extend(request_vars)
        alert = Alert._make(alerts_result)
        data_pool[alert.id]['alert'] = alert
    cursor = c.execute('select * from request_headers where alert_id>=%d and alert_id<%d' % (id, id+pool_size))
    for row in cursor:
        if row[2] == COOKIE:
            cookie_dict = defaultdict(lambda: '')
            cookie_list = row[3].strip(';').split(';')
            for cookie in cookie_list:
                c_list = cookie.strip().split('=')
                if len(c_list) < 2:
                    continue
                cookie_dict[c_list[0]] = c_list[1]
            header_result[row[2]] = cookie_dict
        else:
            header_result[row[2]] = row[3]
        data_pool[row[1]]['header'] = header_result
    cursor.close()
    c.close()
    conn.close()
#get_data_from_db(301000, db_name)
#print(data_pool)
# print(data_pool[117777])


def get_data(id, db_name):
    """
    Get all data by id and return 2 list for both alerts and request_headers table
    :param id:
    :param db_name:
    :return: 2 list
    """
    global data_pool
    if id not in data_pool:
        if os.path.isfile(db_name) is False:
            return -1
        else:
            get_data_from_db(id, db_name)
    #print(data_pool)
    return data_pool[id]['alert'], data_pool[id]['header']
# get_data_from_db(117777, db_name)
# get_data(114791, "alertsbig.db")

# alert, header = get_data(114791, db_name)
# dict_rules = get_all_rules(ZY_RULE_FILE)
# parse_variables(alert,header,dict_rules['920201'].variables)


def write_to_csv(file_content, csv_file, mode):
    """
    Write content to specific file with specific mode
    :param file_content: what you want to write into csv file, iterable items like list
    :param csv_file: csv file name
    :param mode: a, w
    :return:
    """
    with open(csv_file, mode, newline='') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for r in file_content:
            csv_writer.writerow(r)


def read_csv(csv_file=result_file_name):
    result = []
    with open(csv_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        print(type(csv_reader))
        for r in csv_reader:
            result.append(r)
    return(result)


def run_rules():
    # try:
    starttime = datetime.datetime.now()
    # get_all_operator_types(ZY_RULE_FILE)
    start_id = 1  # 109975
    result = []
    global DATA_FILES
    dict_rules, DATA_FILES = get_all_rules(ZY_RULE_FILE)
    get_data_from_db(start_id, db_name)
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    cursor = c.execute('select count(*) from alerts ')
    for row in cursor:
        rec_num = row[0]
    logger.info('Start running rules from %s' % start_id)
    # Remove the old result file before starting
    # if os.path.exists(result_file_name):
    #     os.remove(result_file_name)
    for i in range(start_id, rec_num+1):  # (114791, 114791+1):  # 114791 #54890 ,rec_num+1
        i_result = []
        alert, header = get_data(i, db_name)
        logger.debug('Running rules against id: %d' % i)
        for k in dict_rules.keys():
            #print('\n', i, '#####', k)
            try:
                rule_result = execute_rule(alert, header, dict_rules[k])  # 930100
            except timeout.TimeoutError:
                logger.warning("Rule execution timeout captured!!!")
                continue
            logger.debug('Rule id is: %s \n result is: %s' % (k, rule_result))
            if not rule_result:
                continue
            elif 'chain' in dict_rules[k]:
                result_chain1 = []
                var_name = dict_rules[k]['chain']['variables']
                if var_name == 'TX:0' or var_name == 'MATCHED_VARS':
                    result_chain1 = execute_rule(alert, header, dict_rules[k]['chain'], True, rule_result)
                else:
                    result_chain1 = execute_rule(alert, header, dict_rules[k]['chain'])
                if result_chain1:
                    if 'chain' in dict_rules[k]['chain']:
                        if var_name == 'TX:0' or var_name == 'MATCHED_VARS':
                            result_chain2 = execute_rule(alert, header, dict_rules[k]['chain']['chain'], True,
                                                         rule_result)
                        else:
                            result_chain2 = execute_rule(alert, header, dict_rules[k]['chain']['chain'])
                        if result_chain2:
                            i_result.append(k)
                            # print('+++++ %s chain2 passed' % k)
                            continue
                    else:
                        i_result.append(k)
                        continue
            else:
                i_result.append(k)  # 930100
        if len(i_result) > 0:
            result.append(i_result)
        else:
            result.append('')

        # Write result into file before it is too big.
        if len(result) == 10000:
            write_to_csv(result, result_file_name, 'a')
            result = []
    # Write the rest result into csv file
    write_to_csv(result, result_file_name, 'a')
    return result


if __name__ == '__main__':
    run_rules()

