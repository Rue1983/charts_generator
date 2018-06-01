import docx
from docx.shared import Inches
import gen_charts


report = docx.Document('zywaf防护报告模板.docx')
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


def gen_customer_report():
    for para in report.paragraphs:
        #print(para.text)
        if para.text.startswith('2018年1月16日'):
            #insert_txt('插入的文字', para)
            para.text = '测试替换'
        elif para.text.startswith('注：攻击类型详细描述见附录'):
            #print(para.text)
            insert_graph_before_para('reason_type_pie.png', para)
        elif para.text.startswith('前十大攻击源IP分析'):
            #print(para.text)
            insert_graph_before_para('ip_source_bar.png', para)
        elif para.text.startswith('从本图中可以获知网站遭遇扫描或者黑客攻击的高发日期为'):
            #print(para.text)
            insert_graph_before_para('alerts_by_date.png', para)
            dict_deviation = gen_charts.alerts_by_date_chart_pygal(gen_charts.get_alerts_time_reason("alertsbig.db"))
            analysis = ''
            if dict_deviation:
                for day in dict_deviation.keys():
                    analysis += '%s年%s月%s日(%d次)，' % (
                        day[:4], day[4:6].lstrip('0'), day[6:8].lstrip('0'), dict_deviation[day])
                analysis = '从本图中可以获知网站遭遇扫描或者黑客攻击的高发日期为%s。' % analysis.rstrip('，')
            para.text = analysis
        elif para.text.startswith('不可信访问24小时时间分布'):
            #print(para.text)
            insert_graph_before_para('world1.png', para)
        elif para.text.startswith('从24小时的分布图上来看'):
            #print(para.text)
            insert_graph_before_para('24h_stackedline_chart_all.png', para)
            list_temp = [0]*24
            dict_24h = gen_charts.all_alert_counts_by_reason_24h('alertsbig.db')
            for v in dict_24h.values():
                list_temp = list(map(lambda x: x[0]+x[1], zip(list_temp, v)))
            upper_limit = gen_charts.get_upper_limit(list_temp)
            analysis = ''
            for i, num in enumerate(list_temp):
                if num > upper_limit:
                    analysis += '%d点，' % i
            analysis = '从24小时的分布图上来看，攻击行为在%s进入高发期。' % analysis.rstrip('，')
            para.text = analysis

    #for table in report.tables:
    report.save("zywaf防护报告模板_test.docx")

    #run.font.size = docx.shared.Pt(24)



gen_customer_report()