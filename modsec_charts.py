import requests
import pygal
from collections import Counter
import matplotlib.pyplot as plt
from pywaffle import Waffle
import modsec_rules
import sqlite3
#import gen_report.DB_NAME as DB_NAME
import sys
#sys.path.append("D:\PycharmProjects\pegasus")
DB_NAME = 'alerts0626.db'



result = ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ['920230', '942431', '942432'], ['920230', '942430', '942431', '942432'], ['920230', '942430', '942431', '942432'], '', ['920230', '942430', '942431', '942432'], '', '', '', '', '', '', ['920230', '942430', '942431', '942432'], ['920230', '942431', '942432'], ['920230', '942430', '942431', '942432'], '', '', '', '', '', '', '', '', '', '', '', '', '', '', ['920230', '942430', '942431', '942432'], '', '', '', '', '', '', ['920230', '942430', '942431', '942432'], ['920230', '942430', '942431', '942432'], ['920230', '942430', '942431', '942432'], ['920230', '942430', '942431', '942432'], '', '', '', '', ['920230', '942430', '942431', '942432'], '']
dict_rulename = {913:'Scanner Detection', 920:'Protocol Enforcement', 921:'Protocol Attack', 930:'Local File Inclusion',
                 931:'Remote File Inclusion', 932:'Remote Code Execution', 933:'PHP Attack', 941:'XSS',
                 942:'SQL Injection', 943:'Session Fixation', 950:'Data Leakages'}


def classify(result_list):
    #print('input: ', result_list)
    new_list = []
    for item in result_list:
        new_list.append(item[:3])
    #print(new_list)
    if len(set(new_list)) == 1:
        return new_list[0]
    lc = Counter(new_list)
    #if len(lc) > 1:
    #print(list(lc.keys())[list(lc.values()).index(max(lc.values()))])
    return list(lc.keys())[list(lc.values()).index(max(lc.values()))]


def add_owasp_column(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    columns = [i[1] for i in c.execute('PRAGMA table_info(alerts)')]
    if 'owasp' not in columns:
        cursor = c.execute('alter table alerts add column owasp integer;')
        cursor.close()
        c.close()
        conn.close()


def update_db(db_name, table_name, col_name, rec_id, value):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    cursor = c.execute('update %s set %s = %s where id =%s;' % (table_name, col_name, value, rec_id))
    conn.commit()
    print('update %s set %s = %s where id =%s;' % (table_name, col_name, value, rec_id))
    cursor.close()
    c.close()
    conn.close()


def get_owasp_attack_type(db_name, list_input):
    #print('list input is ', list_input)
    add_owasp_column(db_name)
    ret = {913: 0, 920: 0, 921: 0, 930: 0, 931: 0, 932: 0, 933: 0, 941: 0, 942: 0, 943: 0, 950: 0}
    for i, r in enumerate(list_input):
        if not r:
            continue
        else:
            attack_type = int(classify(r))
            #print(attack_type)
            ret[attack_type] = ret[attack_type] + 1
            update_db(db_name, 'alerts', 'owasp', i+1, attack_type)
    ret = {key:ret[key] for key in ret.keys() if ret[key]}
    #print(ret)
    return ret


def owasp_attack_type_bar(db_name, list_input):
    dict_result = get_owasp_attack_type(db_name, list_input)
    bar_chart = pygal.Bar(truncate_legend=-1, human_readable=True)
    bar_chart.title = 'Alerts by attack types'
    for k,v in dict_result.items():
        if v == 0:
            continue
        bar_chart.add(dict_rulename[k],v)
    bar_chart.render()
    bar_chart.render_to_file('OWASP_attack_types.svg')
    

def owasp_attack_type_waffle(db_name, list_input):
    """
    Draw waffle chart for owasp attack type
    http://pywaffle.readthedocs.io/en/latest/class.html
    :param list_input example: ['941110', '941160', '941320', '942130', '942370', '942431', '942460', '942432'], ['920230', '930120', '932160', '942432'], ['920230', '942432'], ['930110'], '', '']
    :return: none
    """
    dict_result = get_owasp_attack_type(db_name, list_input)
    if not dict_result:
        raise ValueError("Result of modSecurity is empty")
    #print('---- before ', dict_result)
    total_number = sum(dict_result.values())
    dict_result = {dict_rulename[key]: int('%d' % (dict_result[key]/total_number*100)) for key in dict_result.keys()
                   if dict_result[key] >= total_number/100}
    #print('-----', dict_result)
    # The values are rounded to 10 * 10 blocks
    fig = plt.figure(
        FigureClass=Waffle,
        rows=10,
        columns=10,
        values=dict_result,
        title={'label': 'Attacks by Types', 'loc': 'left'},
        legend = {'loc': 'lower left', 'bbox_to_anchor': (0, -0.4)}
    )
    plt.show()
    plt.savefig('owasp_types_waffle.png', dpi=150)
    # color for grey unknown is #BCBCBC


def test():
    data = {'Democratic': 48, 'Republican': 46, 'Libertarian': 3}
    fig = plt.figure(
        FigureClass=Waffle,
        rows=5,
        values=data,
        title={'label': 'Attacks by Types', 'loc': 'left'},
        legend={'loc': 'lower left', 'bbox_to_anchor': (0, 1.05)}
    )
    plt.show()

#classify(['920230', '942431', '942432'])
#get_owasp_attack_type(db_name, result)
#owasp_attack_type_bar(result)
#owasp_attack_type_waffle(get_owasp_attack_type(db_name, result))
#test()
#test = modsec_rules.run_rules()
#print(test)
#owasp_attack_type_waffle(db_name, modsec_rules.run_rules())




