import pygal
import os
import sqlite3
import geoip2.database
import seaborn
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import datetime
from datetime import date
from collections import Counter

reason_dict = {1: '隐藏字段篡改', 2: '单选按钮篡改', 3: '链接参数篡改', 4: '未知字段', 5: '未知字段类型', 6: '缓存溢出攻击',
               7: '复选框篡改', 8: 'Cookie篡改', 9: '链接参数篡改', 10: '强制浏览', 11: '非正常HTTP请求', 12: 'HTTP请求方法无效',
               13: '协议错误', 14: '服务器域名无效', 15: '特殊字符'}
reason_dict_en = {1: 'Hidden Field Tampering', 2: 'Radio Button Tampering', 3: 'Select Option Tampering',
                  4: 'Unknown Field', 5: 'Unknown Field Type', 6: 'Buffer Overrun', 7: 'Checkbox Tampering',
                  8: 'Cookie Tampering', 9: 'Link Tampering', 10: 'Forceful Browsing', 11: 'Malformed Request',
                  12: 'Invalid HTTP Method', 13: 'Incorrect Protocol', 14: 'Invalid Web Server Name',
                  15: 'Special Characters'}


def get_data_from_db(db_name):
    """
    Get everything from given sqlite db
    :param db_name:
    :return: A list of result
    """
    if os.path.isfile(db_name) is False:
        return 0
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT * from alerts")
        for row in cursor:
            result.append(row)
        return result


def get_upper_limit(data_list):
    """
    Get upper limit of Tukey‘s test
    :param data_list:
    :return: int
    """
    data_list = list(map(int, data_list))
    num = np.array(data_list)
    ul = np.percentile(num, 75) + (np.percentile(num, 75) - np.percentile(num, 25)) * 1.5
    return int(ul)




def get_top10_ip(db_name):
    """
    Get top 10 ip source and alerts counts.
    :param db_name:
    :return: a list of result
    """
    if os.path.isfile(db_name) is False:
        return 0
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT ip, count(*) from alerts as IP group by ip order by count(ip) DESC limit 10")
        for row in cursor:
            result.append(row)
        return result


def get_data_by_reasons(db_name):
    """
    Get counts by alert reasons
    :param db_name:
    :return: A list of reason names and related counts
    """
    if os.path.isfile(db_name) is False:
        return 0
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT reason, count(*) from alerts as Reason group by reason order by count(reason) DESC")
        for row in cursor:
            tmp = [reason_dict[row[0]], row[1]]
            result.append(tmp)
        return result


def get_alerts_time_reason(db_name):
    if os.path.isfile(db_name) is False:
        return 0
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT time, reason from alerts")
        for row in cursor:
            result.append(row)
        return result


def get_location_by_ip(ip):
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return 'internal', 'internal'
    else:
        return response.city.name, response.country.name



def alerts_by_reason_in_24h(date, chart_data):
    """
    Generate charts about alert counts by reasons and hours in a day
    :param date, chart_data:
    :return: Create new svg and png chart file in current dir.
    """
    line_chart = pygal.StackedLine(fill=True, truncate_legend=-1, human_readable=True)
    line_chart.title = 'Alerts in 24 hours of ' + date
    line_chart.x_labels = map(str, range(1, 24))
    dict_24hours = {c: [0]*24 for c in range(1, 16)}
    for alert_time_reason in chart_data:
        alert_dt = datetime.datetime.strptime(alert_time_reason[0], "%Y-%m-%dT%H:%M:%S%z")
        if int(alert_dt.strftime('%Y%m%d')) == int(date):
            reason_code = alert_time_reason[1]
            hour = int(alert_dt.strftime('%H'))
            dict_24hours[reason_code][hour-1] += 1
    for k in dict_24hours.keys():
        if sum(dict_24hours[k]) == 0:
            continue
        line_chart.add(reason_dict_en[k], dict_24hours[k], show_dots=False)
    line_chart.human_readable = True
    line_chart.force_uri_protocol = 'http'
    line_chart.render_to_file('24h_stackedline_chart_%s.svg' % date)
    # line_chart.render_to_png('24h_stackedline_chart_%s.png' % date)


def alerts_by_date_chart_pygal(chart_data):
    """
    Generate chart for alerts counts by day via pygal
    :param chart_data:
    :return: Create new svg and png chart file in current dir.
    """
    # dateline_chart = pygal.DateLine(x_label_rotation=25)
    alert_by_date = []
    alert_counts = []
    for alert_time_reason in chart_data:
        alert_dt = datetime.datetime.strptime(alert_time_reason[0], "%Y-%m-%dT%H:%M:%S%z")
        alert_by_date.append(alert_dt.strftime('%Y%m%d').__str__())
    alert_dict = Counter(alert_by_date)  # Get counts by day
    upper_limit = get_upper_limit(list(alert_dict.values()))
    for k in alert_dict.keys():
        if int(alert_dict[k]) > int(upper_limit):
            alerts_by_reason_in_24h(k, chart_data)
    # Display legend at bottom can avoid truncate problem
    bar_chart = pygal.Bar(legend_at_bottom=True, show_legend=True, truncate_legend=-1, human_readable=True)
    #  legend_at_bottom_columns=4,
    bar_chart.title = 'Alerts By Date'
    for k in sorted(alert_dict.keys()):  # Sort by day
        # dates.append(k)
        alert_counts.append(alert_dict[k])
        bar_chart.add(k, alert_dict[k])
        # dt_k = datetime.datetime.strptime(k, '%Y%m%d').date()
        # dateline_chart.add(dt_k, alert_dict[k])
    # bar_chart.render_to_png('alerts_by_date.png')
    bar_chart.render_to_file('alerts_by_date.svg')
    # dateline_chart.render_to_png('alerts_by_dateline.png')
    # dateline_chart.render_to_file('alerts_by_dateline.svg')


def alerts_world_map_via_ip(chart_data):
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    worldmap_chart = pygal.maps.world.World(truncate_legend=-1, human_readable=True)
    worldmap_chart.title = 'Top 10 IP Sources'
    dict_country = {}
    for data in chart_data:
        try:
            response = reader.city(data[0])
        except geoip2.errors.AddressNotFoundError:
            country_code = 'cn'  # Geolite DB cannot recognize reserved IP, most of this should be internal IP.
        else:
            country_code = response.country.iso_code.lower()
        if country_code not in dict_country:
            dict_country[country_code] = data[1]
        else:
            tmp = dict_country[country_code]
            dict_country[country_code] = int(tmp) + int(data[1])
    worldmap_chart.add('Alerts number', dict_country)
    worldmap_chart.render()
    worldmap_chart.render_to_file("alerts_world_map.svg")


##################################
# Generate a bar chart
# for top 10 ip sources
def ip_source_chart_pygal(chart_data):
    bar_chart = pygal.Bar(truncate_legend=-1, human_readable=True)
    bar_chart.title = 'Top 10 IP Source'
    for data in chart_data:
        city_name, country_name = get_location_by_ip(data[0])
        x_label_name = "%s(%s,%s)" % (data[0], city_name, country_name)
        bar_chart.add(x_label_name, data[1])
        bar_chart.render()
    bar_chart.render_to_file('ip_source_bar.svg')
    # bar_chart.render_to_png('ip_source_bar.png')


def ip_source_chart_seaborn(chart_data):
    x = []
    y = []
    for data in chart_data:
        x.append(data[0])
        y.append(data[1])
    seaborn.set_style("whitegrid")
    ax = seaborn.barplot(x, y, hue=x)
    ax.set_title('Top 10 IP Source')
    ax.set_xlabel('IP Address')
    ax.set_ylabel('Count')
    plt.xticks([])
    ax.set_xlim(-0.5, 9.5)
    widthbars = [1, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    for bar, newwidth in zip(ax.patches, widthbars):
        x = bar.get_x()
        width = bar.get_width()
        centre = x + width / 2.
        bar.set_x(centre - newwidth / 2.)
        bar.set_width(newwidth)
    # plt.figure(figsize=(1, 1))
    plt.savefig('ip_source_seaborn.png')
    plt.show()
    # plt.close()
    # plt.plot(x, y_line, '-o', color='y')


def reason_type_chart_pygal(chart_data):
    pie_chart = pygal.Pie(truncate_legend=-1, human_readable=True)
    pie_chart.title = 'Reason Type'
    for data in chart_data:
        pie_chart.add(data[0], data[1])
        pie_chart.render()
    pie_chart.render_to_file('reason_type_pie.svg')
    pie_chart.print_values = True
    #pie_chart.render_to_png('reason_type_pie.png')


def chart_alerts_by_time_seaborn(csv_name):
    df_alerts = pd.read_csv(csv_name, delimiter="\t")
    seaborn.distplot(df_alerts['reason'], kde=False)
    seaborn.plt.show()
    plt.close()


reason_type_chart_pygal(get_data_by_reasons('alertsbig.db'))
#ip_source_chart_seaborn(get_top10_ip("alertsbig.db"))
#ip_source_chart_pygal(get_top10_ip("alertsbig.db"))
#alerts_world_map_via_ip(get_top10_ip("alertsbig.db"))
#chart_alerts_by_time_seaborn("a.csv")
#alerts_by_date_chart_pygal(get_alerts_time_reason("alertsbig.db"))
#alerts_by_reason_in_24h("20180401", get_alerts_time_reason("alertsbig.db"))
#get_location_by_ip("218.94.157.126")



def draw_bar(chart_data):
    x = []
    y_bar = []
    for data in chart_data:
        x.append(data[0])
        y_bar.append(data[1])
    width = 0.4
    ind = np.linspace(0.5, 9.5, 10)
    # make a square figure
    fig = plt.figure(1)
    ax = fig.add_subplot(111)
    # Bar Plot
    ax.bar(ind-width/2, y_bar, width, color='green')
    # Set the ticks on x-axis
    ax.set_xticks(ind)
    ax.set_xticklabels(x)
    # labels
    ax.set_xlabel('Country')
    ax.set_ylabel('GDP (Billion US dollar)')
    # title
    ax.set_title('Top 10 GDP Countries', bbox={'facecolor': '0.8', 'pad': 5})
    plt.grid(True)
    plt.savefig('test.png')
    plt.show()


def draw_bar2(self, labels, quants):
    width = 0.8
    ind = np.linspace(1, 66, 65)
    # 绘图参数全家桶
    params = {
        'axes.labelsize': '16',
        'xtick.labelsize': '16',
        'ytick.labelsize': '13',
        'lines.linewidth': '2',
        'legend.fontsize': '20',
        'figure.figsize': '26, 24'  # set figure size
    }

    #pylab.rcParams.update(params)
    # make a square figure
    fig = plt.figure(1)
    ax = fig.add_subplot(111)
    # Bar Plot
    # 横的柱状图
    ax.barh(ind - width / 2, quants, width, color='blue')
    # 竖的柱状图
    # ax.bar(ind - width / 2, quants, width, color='blue')
    # Set the ticks on x-axis
    ax.set_yticks(ind)
    ax.set_yticklabels(labels)
    # 竖的柱状图
    # ax.set_xticks(ind)
    # ax.set_xticklabels(labels)
    # labels
    ax.set_xlabel('xxx')
    ax.set_ylabel('xxxxxxxx')
    # title
    ax.set_title('xxxxxxxxxxxxx')
    plt.grid(True)
    # 也可以这样设置图片大小
    # plt.figure(figsize=())
    # plt.show()
    plt.savefig("bar.jpg")
    plt.close()
