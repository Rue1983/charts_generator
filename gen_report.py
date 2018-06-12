import docx
from docx.shared import Inches
import gen_charts
import modsec_charts
import modsec_rules
import os
import sqlite3
import configparser
RULE_TYPES = 'rule_types.conf'
REPORT_TEMPLATE = 'zywaf防护报告模板2.docx'
DB_NAME = 'alerts0605.db'

dict_insert_pic = {'注：攻击类型详细描述见附录': 'reason_type_pie.png', '从本图中可以获知网站遭遇扫描或者黑客攻击':
    'alerts_by_date.png', '前十大攻击源IP分析': 'ip_source_bar.png', '不可信访问24小时时间分布': 'world1.png',
                   '从24小时的分布图上来看': '24h_stackedline_chart_all.png'}


def insert_txt(text, para):
    run = para.add_run(u'\n%s' % text)
    run.font.size = docx.shared.Pt(24)


def insert_txt_before_para(txt, para):
    """
    :param txt:
    :param para:
    :return:
    """
    new_para = para.insert_paragraph_before()
    new_para.add_run(u'%s' % txt)


def insert_graph_before_para(graph_name, para):
    """
    Use insert_before to avoid indent issue when add pic in new run
    :param graph_name:  picture name
    :param para:  paragraph instance
    :return: none
    """
    new_para = para.insert_paragraph_before()
    run = new_para.add_run(u'')
    run.add_picture('pictures\\%s' % graph_name, width=Inches(6.75))


def get_owasp_types(db_name):
    """
    Get all types of owasp rule id in column owasp
    :return:
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute('SELECT DISTINCT owasp FROM alerts;')
        for row in cursor:
            if row[0] is not None:
                result.append(row[0])
        conn.close()
        print(result)
        return result
#get_owasp_types('alertsbig.db')


def get_random_sample(db_name, rule_type):
    """
    Get random sample by given dbname and rule type like: alerts.db, 942
    :param db_name:
    :param rule_type:
    :return: samples in list, total number of the rule types in int.
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        times = 0
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute('select ip,time,request from alerts where owasp=%s ORDER by random() limit 1' % rule_type)
        for row in cursor:
            #print(row)
            result = list(row)
        cursor = c.execute('select count(id) from alerts where owasp=%s' % rule_type)
        for row in cursor:
            times = row[0]
        conn.close()
        print(result, '\n times is : %d' % times)
        return result, times
#get_random_sample(DB_NAME, 942)


def get_config_value(file_name, section, key):
    """
    Get value from given section and keyname from the given conf file.
    :param section:
    :param key:
    :return:
    """
    configfile = configparser.ConfigParser()
    configfile.read(RULE_TYPES)
    ret = configfile.get(str(section), key)
    return ret
#get_config_value(RULE_TYPES, '920', 'harm')


def gen_customer_report(db_name):
    """
    Generate customer report base on given alerts db and template file.
    :param db_name:
    :return:
    """
    result = 0
    report = docx.Document(REPORT_TEMPLATE)
    for para in report.paragraphs:
        print(para.text)
        if para.text.startswith('2018年1月16日'):
            #insert_txt('插入的文字', para)
            #para.text = '测试替换'
            pass
        elif para.text.startswith('注：不可信访问类型详细描述见附录'):
            #print(para.text)
            insert_graph_before_para('reason_type_pie.png', para)
            result += 1
        elif para.text.startswith('前十大攻击源IP分析'):
            #print(para.text)
            insert_graph_before_para('ip_source_bar.png', para)
            result += 1
        elif para.text.startswith('从上图中可以获知网站遭遇扫描或者黑客攻击的高发日期为'):
            #print(para.text)
            dict_deviation = gen_charts.alerts_by_date_chart_pygal(gen_charts.get_alerts_time_reason(db_name))
            insert_graph_before_para('alerts_by_date.png', para)
            analysis = ''
            if dict_deviation:
                for day in dict_deviation.keys():
                    analysis += '%s年%s月%s日(%d次)，' % (
                        day[:4], day[4:6].lstrip('0'), day[6:8].lstrip('0'), dict_deviation[day])
                analysis = '从上图中可以获知网站遭遇扫描或者黑客攻击的高发日期为%s。' % analysis.rstrip('，')
            para.text = analysis
            result += 1
        elif para.text.startswith('不可信访问24小时时间分布'):
            #print(para.text)
            insert_graph_before_para('world1.png', para)
            result += 1
        elif para.text.startswith('从24小时的分布图上来看'):
            #print(para.text)
            insert_graph_before_para('24h_stackedline_chart_all.png', para)
            list_temp = [0]*24
            dict_24h = gen_charts.all_alert_counts_by_reason_24h(db_name)
            for v in dict_24h.values():
                list_temp = list(map(lambda x: x[0]+x[1], zip(list_temp, v)))
            upper_limit = gen_charts.get_upper_limit(list_temp)
            analysis = ''
            for i, num in enumerate(list_temp):
                if num > upper_limit:
                    analysis += '%d点，' % i
            analysis = '从24小时的分布图上来看，攻击行为在%s进入高发期。' % analysis.rstrip('，')
            para.text = analysis
            result += 1
    failed_types = get_owasp_types(db_name)
    # Insert samples in chapter 4.3
    for ft in failed_types:
        for i, t in enumerate(report.tables):
            first_cells = t.rows[0].cells
            if len(first_cells) < 2:
                continue
            if first_cells[1].text == get_config_value(RULE_TYPES, ft, 'name'):
                sample, times = get_random_sample(db_name, ft)
                harm = get_config_value(RULE_TYPES, ft, 'harm')
                second_cells = t.rows[1].cells
                second_cells[1].text = 'IP: %s\nTime: %s\nRequest: %s' % (sample[0], sample[1], sample[2])
                third_cells = t.rows[2].cells
                third_cells[1].text = str(times)
                fourth_cells = t.rows[3].cells
                fourth_cells[1].text = str(harm)
    report.save("zywaf防护报告模板_test.docx")
    if result != 5:
        raise ValueError("Steps are wrong, result is %d" % result)
#gen_customer_report()


if __name__ == '__main__':
    #modsec_result = modsec_rules.run_rules()
    #modsec_charts.owasp_attack_type_waffle(DB_NAME, modsec_result)
    #modsec_charts.owasp_attack_type_bar(DB_NAME, modsec_result)
    gen_customer_report(DB_NAME)
