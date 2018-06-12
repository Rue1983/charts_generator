import pygal
import os
import sqlite3
import geoip2.database
import numpy as np
import datetime
import pickle
from collections import Counter
from pygal.style import DefaultStyle
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt

reason_dict = {1: '隐藏字段篡改', 2: '单选按钮篡改', 3: '链接参数篡改', 4: '未知字段', 5: '未知字段类型', 6: '缓存溢出攻击',
               7: '复选框篡改', 8: 'Cookie篡改', 9: '链接参数篡改', 10: '强制浏览', 11: '非正常HTTP请求', 12: 'HTTP请求方法无效',
               13: '协议错误', 14: '服务器域名无效', 15: '特殊字符'}
reason_dict_en = {1: 'Hidden Field Tampering', 2: 'Radio Button Tampering', 3: 'Select Option Tampering',
                  4: 'Unknown Field', 5: 'Unknown Field Type', 6: 'Buffer Overrun', 7: 'Checkbox Tampering',
                  8: 'Cookie Tampering', 9: 'Link Tampering', 10: 'Forceful Browsing', 11: 'Malformed Request',
                  12: 'Invalid HTTP Method', 13: 'Incorrect Protocol', 14: 'Invalid Web Server Name',
                  15: 'Special Characters'}


def get_first_last_date(db_name):
    """
    Get the date of first and last record in the given db
    :param db_name:
    :return: firstdate, lastdate+1  (to adapt the "between" operator)
    """
    if os.path.isfile(db_name) is False:
        return -1
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute('select time from alerts order by time limit 1')
        for row in cursor:
            result.append(row)
        cursor = c.execute('select time from alerts order by time DESC limit 1')
        for row in cursor:
            result.append(row)
        start_date = datetime.datetime.strptime(str(result[0][0]), "%Y-%m-%dT%H:%M:%S%z")
        end_date = datetime.datetime.strptime(str(result[1][0]), "%Y-%m-%dT%H:%M:%S%z") + datetime.timedelta(days=1)
        start_str = start_date.strftime("%Y-%m-%d")
        end_str = end_date.strftime("%Y-%m-%d")
        return start_str, end_str


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


def get_alerts_by_ip(ip, db_name):
    """
    Get top 10 ip source and alerts counts.
    :param db_name:
    :return: a list of result
    """
    if os.path.isfile(db_name) is False:
        return -1
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute('SELECT ip, reason, time from alerts where ip = "%s"' % ip)
        for row in cursor:
            result.append(row)
        return result


def get_top10_ip(db_name):
    """
    Get top 10 ip source and alerts counts.
    :param db_name:
    :return: a list of result
    """
    if os.path.isfile(db_name) is False:
        return -1
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
        return -1
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT reason, count(*) from alerts as Reason group by reason order by count(reason) DESC")
        for row in cursor:
            tmp = [reason_dict_en[row[0]], row[1]]
            result.append(tmp)
        return result


def get_reason_counts_by_date(ip_addr, start_date, end_date, db_name):
    """
    Get reson counts by given start date and end date
    :param ip_addr: specific ip
    :param start_date:
    :param end_date: Any record before this value will be included.
    :param db_name: alert db name
    :return:
    """
    if os.path.isfile(db_name) is False:
        exit(1)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        if ip_addr == 'all':
            cursor = c.execute(
                'select time,reason from alerts where time between date(\'%s\') and date(\'%s\')'
                ' order by time' % (start_date, end_date))
        else:
            cursor = c.execute('select time,reason from alerts where ip="%s" and time between date(\'%s\')'
                               ' and date(\'%s\') order by time' % (ip_addr, start_date, end_date))
        for row in cursor:
            result.append(row)
    #print(result)
    return result


def get_uri_by_reason(reason, db_name):
    """
    Get uri numbers and time by specific reason code
    :param reason: reason code
    :param db_name: path of alerts.db
    :return: A list of uri,time,count for one reason in the db
    """
    if os.path.isfile(db_name) is False:
        return -1
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT uri, count(*) from alerts where reason = %d group by uri order by count(uri) DESC limit 10" % reason)
        for row in cursor:
            result.append(row)
        return result


def get_alerts_time_reason(db_name):
    if os.path.isfile(db_name) is False:
        return -1
    else:
        result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute("SELECT time, reason from alerts")
        for row in cursor:
            result.append(row)
        return result


def get_location_by_ip(ip):
    """
    Get country name and city name base on the given ip address
    :param ip:
    :return: (string) cityname, countryname
    """
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return 'internal', 'internal'
    else:
        return response.city.name, response.country.name


def alert_counts_by_reason_24h(ip_addr, start_date, end_date, db_name):
    """
    Generate chart for reasons counts in 24h for a specific ip
    :param ip_addr: specific ip address
    :param start_date:
    :param end_date:
    :param db_name:
    :return:
    """
    chart_data = get_reason_counts_by_date(ip_addr, start_date, end_date, db_name)
    line_chart = pygal.StackedLine(fill=True, truncate_legend=-1, human_readable=True)
    if ip_addr == "all":
        line_chart.title = 'Alerts in 24 hours from %s to %s' % (start_date, end_date)
    else:
        line_chart.title = 'Alerts in 24 hours of %s from %s to %s' % (ip_addr, start_date, end_date)
    line_chart.x_labels = map(str, range(1, 24))
    dict_24hours = {c: [0]*24 for c in range(1, 16)}
    for i in chart_data:
        alert_dt = datetime.datetime.strptime(i[0], "%Y-%m-%dT%H:%M:%S%z")
        reason_code = i[1]
        hour = int(alert_dt.strftime('%H'))
        dict_24hours[reason_code][hour - 1] += 1
    for k in dict_24hours.keys():
        if sum(dict_24hours[k]) == 0:
            continue
        line_chart.add(reason_dict_en[k], dict_24hours[k], show_dots=False)
    line_chart.force_uri_protocol = 'http'
    line_chart.render_to_file('24h_stackedline_chart_%s.svg' % ip_addr)
    #line_chart.render_to_png('24h_stackedline_chart_%s.png' % ip_addr)


def all_alert_counts_by_reason_24h(db_name):
    """
    Generate 24h tread chart for the whole data set in given db
    :param db_name:
    :return:
    """
    start_date, end_date = get_first_last_date(db_name)
    alert_counts_by_reason_24h('all', start_date, end_date, db_name)


def uri_counts_by_reason(reason_code, chart_data):
    """
    Generate chart for specific reason to show the affected numbers
    :param reason_code: 
    :param chart_data: 
    :return: 
    """
    reason_name = reason_dict_en[reason_code]
    h_bar = pygal.HorizontalBar(truncate_legend=-1, human_readable=True, legend_at_bottom=True,
                                legend_at_bottom_columns=1)
    h_bar.title = 'Top 10 affected URI numbers of %s' % reason_name
    for uri_counts in chart_data:
        h_bar.add(uri_counts[0], int(uri_counts[1]))
    h_bar.render_to_file('URI_by_reason_%s.svg' % reason_name)
    #h_bar.render_to_png('URI_by_reason_%s.png' % reason_name)


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
    #line_chart.render_to_png('24h_stackedline_chart_%s.png' % date)


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
    #bar_chart.render_to_png('alerts_by_date.png')
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
    #worldmap_chart.render_to_png("alerts_world_map.png")


def alerts_world_map_via_ip_basemap(chart_data):
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    dict_city = {}
    lat = []
    lon = []
    alert_num = []
    for data in chart_data:
        try:
            response = reader.city(data[0])
        except geoip2.errors.AddressNotFoundError:
            print("internal")  # TODO:  Handle internal ip here
        else:
            location = [response.location.latitude,  response.location.longitude]
            loc_ser = pickle.dumps(location)
            if loc_ser not in dict_city:
                dict_city[loc_ser] = data[1]
            else:
                tmp = dict_city[loc_ser]
                dict_city[loc_ser] = int(tmp) + int(data[1])
    for i in dict_city.keys():
        lat.append(float(pickle.loads(i)[0]))
        lon.append(float(pickle.loads(i)[1]))
        alert_num.append(float(dict_city[i]))
    print(lat, lon, alert_num)

    # Draw map
    fig = plt.figure(figsize=(8, 4.5))
    plt.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.00)
    m = Basemap(projection='robin', lon_0=0, resolution='l')
    m.drawcoastlines(linewidth=0.1)
    m.drawcountries(linewidth=0.1)
    #m.drawmapboundary()
    m.bluemarble(scale=0.5)
    m.fillcontinents(color='#C0C0C0', lake_color='#1A4680', zorder=0.1)
    #x, y = m(lon, lat)
    size = (alert_num/np.max(alert_num))*100
    print(size)
    m.scatter(lon, lat, s=size, label='Alerts Numbers', color='red', marker='v', zorder=2, latlon=True)
    plt.title('Malicious Internet Traffic Source Map')
    plt.savefig('world1.png', dpi=150)
    plt.show()


def ip_source_chart_pygal(chart_data):
    """
    Generate bar chart to display ip source numbers
    :param chart_data:
    :return:
    """
    bar_chart = pygal.Bar(truncate_legend=-1, human_readable=True)
    bar_chart.title = 'Top 10 IP Source'
    for data in chart_data:
        city_name, country_name = get_location_by_ip(data[0])
        x_label_name = "%s(%s,%s)" % (data[0], city_name, country_name)
        bar_chart.add(x_label_name, data[1])
        bar_chart.render()
    bar_chart.render_to_file('ip_source_bar.svg')
    #bar_chart.render_to_png('ip_source_bar.png')


def reason_type_chart_pygal(chart_data):
    pie_chart = pygal.Pie(truncate_legend=-1, human_readable=True)
    pie_chart.title = 'Reason Type'
    for data in chart_data:
        pie_chart.add(data[0], data[1])
        pie_chart.render()
    pie_chart.render_to_file('reason_type_pie.svg')
    pie_chart.print_values = True
    pie_chart.style = DefaultStyle(
        value_font_family='googlefont:Raleway',
        value_font_size=30,
        value_colors=('white',) * 15)
    pie_chart.render_to_png('reason_type_pie.png')


#reason_type_chart_pygal(get_data_by_reasons('alertsbig.db'))
ip_source_chart_pygal(get_top10_ip("alertsbig.db"))
#alerts_world_map_via_ip(get_top10_ip("alertsbig.db"))
#alerts_by_date_chart_pygal(get_alerts_time_reason("alertsbig.db"))
#uri_counts_by_reason(9, get_uri_by_reason(9, "alertsbig.db"))
#all_alert_counts_by_reason_24h('alertsbig.db')
alerts_world_map_via_ip_basemap(get_top10_ip("alertsbig.db"))

# generate 24 chart for all ip and all date
#alert_counts_by_reason_24h('all', '2018-01-16', '2118-04-04', 'alertsbig.db')

#alerts_by_reason_in_24h("20180401", get_alerts_time_reason("alertsbig.db"))
#get_location_by_ip("218.94.157.126")
#get_reason_counts_by_date('114.249.227.204', '2018-01-19', '2018-01-20', 'alertsbig.db')




"""
class Usage(Exception):
    def __init__(self,msg):
        self.msg = msg
def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "h", ["help"])
        except getopt.error, msg:
            raise Usage(msg)
    except Usage, err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
"""

