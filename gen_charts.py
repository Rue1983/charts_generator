import pygal
import os
import sqlite3
import csv
import geoip2.database
import numpy as np
import datetime
import pickle
from collections import Counter
from pygal.style import DefaultStyle
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import folium
from folium.plugins import HeatMap
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
DB_NAME = 'alerts0713.db'
PIC_DIR = 'pictures/'

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
        raise FileNotFoundError("Can't find given db %s" % db_name)
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
        conn.close()
        return start_str, end_str


def get_upper_limit(data_list):
    """
    Get upper limit of Tukey‘s test  离群值
    :param data_list:
    :return: int
    """
    data_list = list(map(int, data_list))
    num = np.array(data_list)
    ul = np.percentile(num, 75) + (np.percentile(num, 75) - np.percentile(num, 25)) * 1.5
    return int(ul)


def get_distinct_ip_num(db_name):
    """
        Get top 10 ip source and alerts counts.
        :param db_name:
        :return: number of distinct ip
        """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute('select count(distinct ip) from alerts')
        for row in cursor:
            result.append(row[0])
        conn.close()
        return result[0]


def get_alerts_by_ip(ip, db_name):
    """
    Get top 10 ip source and alerts counts.
    :param db_name:
    :param ip:
    :return: a list of result
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute('SELECT ip, reason, time from alerts where ip = "%s"' % ip)
        for row in cursor:
            result.append(row)
        conn.close()
        return result


def get_top10_ip(db_name, start_date=None, end_date=None, limit=10):
    """
    Get top 10 ip source and alerts counts.
    :param db_name:
    :param start_date:date in the form of yyyy-mm-dd like 2018-05-01
    :param end_date: date in the form of yyyy-mm-dd like 2018-05-01
    :return: a list of result
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        if start_date and end_date:
            cursor = c.execute("SELECT ip, count(*) from alerts where time between date(\'%s\') and date(\'%s\')"
                               " group by ip order by count(ip) DESC limit %d" % (start_date, end_date, limit))
        elif start_date is None and end_date is None:
            cursor = c.execute("SELECT ip, count(*) from alerts as IP group by ip order by count(ip) DESC limit %d"
                               % limit)
        else:
            raise ValueError("Missing Parameter")
        for row in cursor:
            result.append(list(row))
        #print(result)
        conn.close()
        return result


def get_data_by_reasons(db_name, cn=None):
    """
    Get counts by alert reasons
    :param db_name:
    :return: A list of reason names and related counts
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute("SELECT reason, count(*) from alerts as Reason group by reason order by count(reason) DESC")
        for row in cursor:
            if row[0] == 20:
                # Skip license error
                continue
            if cn:
                tmp = [reason_dict[row[0]], row[1]]
            else:
                try:
                    tmp = [reason_dict_en[row[0]], row[1]]
                except KeyError:
                    print('key error:', row)
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
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
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
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute("SELECT uri, count(*) from alerts where reason = %d group by uri order by count(uri) "
                           "DESC limit 10" % reason)
        for row in cursor:
            result.append(row)
        return result


def get_alerts_time_reason(db_name):
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute("SELECT time, reason from alerts")
        for row in cursor:
            result.append(row)
        return result


def export_all_ip(db_name):
    """
    Export all IP source order by numbers into csv file
    :param db_name: file name of alerts.db
    :return: none
    """
    if os.path.isfile(db_name) is False:
        raise FileNotFoundError("Can't find given db %s" % db_name)
    else:
        result = []
        conn = sqlite3.connect(db_name)
        conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # to avoid decode error
        c = conn.cursor()
        cursor = c.execute("SELECT ip, count(*) from alerts group by ip order by count(ip) DESC;")
        for row in cursor:
            byte_list = []
            for i in row:
                byte_list.append(str(i))
            result.append(byte_list)
        conn.close()
        with open("%sall_ip_%s.csv" % (PIC_DIR, db_name[:-3]), 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for r in result:
                csvwriter.writerow(r)
#export_all_ip('alertsbig.db')


def get_location_by_ip(ip, language=None):
    """
    Get country name and city name base on the given ip address
    :param ip:
    :return: (string) cityname, countryname
    """
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    country_name = ''
    city_name = ''
    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return 'internal', 'internal'
    except ValueError:
        # it's not a valid ip address
        pass
    else:
        # Handle the situation that country, city missing in response.
        if response.country.name:
            if language and language in response.country.names:
                country_name = response.country.names['%s' % language]
            else:
                country_name = response.country.name
        else:
            if language and language in response.registered_country.names:
                country_name = response.registered_country.names['%s' % language]
            else:
                country_name = response.registered_country.name
        if response.city.name:
            if language and language in response.city.names:
                print(response)
                city_name = response.city.names['%s' % language]
            else:
                city_name = response.city.name
    return city_name, country_name


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
    line_chart.x_labels = map(str, range(0, 24))
    dict_24hours = {c: [0]*24 for c in range(1, 16)}
    for i in chart_data:
        alert_dt = datetime.datetime.strptime(i[0], "%Y-%m-%dT%H:%M:%S%z")
        reason_code = i[1]
        if reason_code == 20:
            # skip the license error
            continue
        hour = int(alert_dt.strftime('%H'))
        dict_24hours[reason_code][hour - 1] += 1
    for k in dict_24hours.keys():
        if sum(dict_24hours[k]) == 0:
            continue
        line_chart.add(reason_dict_en[k], dict_24hours[k], show_dots=False)
    line_chart.force_uri_protocol = 'http'
    line_chart.render_to_file('%s24h_stackedline_chart_%s.svg' % (PIC_DIR, ip_addr))
    line_chart.render_to_png('%s24h_stackedline_chart_%s.png' % (PIC_DIR, ip_addr))
    return dict_24hours


def all_alert_counts_by_reason_24h(db_name):
    """
    Generate 24h tread chart for the whole data set in given db
    :param db_name:
    :return:
    """
    start_date, end_date = get_first_last_date(db_name)
    ret = alert_counts_by_reason_24h('all', start_date, end_date, db_name)
    #print(ret)
    return ret


def ip_divide_by_country(db_name):
    num = get_distinct_ip_num(db_name)
    all_ip = get_top10_ip(db_name, limit=num)
    foreign = []
    china = []
    sum_china = 0
    sum_foreign = 0
    for ip in all_ip:
        city, country = get_location_by_ip(ip[0])
        if country == 'internal':
            pass
        elif country == 'China':
            china.append(ip)
            sum_china += ip[1]
        elif country != 'China':
            foreign.append(ip)
            sum_foreign += ip[1]
        else:
            raise ValueError("Unexpected country name found!")
    ret = 'China' if sum_china > sum_foreign else 'Foreign'
    print('\nchina is ', china, '\n', foreign, '\n', ret)
    return china, foreign, ret


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
    h_bar.title = 'Top 10 URI affected by %s' % reason_name
    for uri_counts in chart_data:
        h_bar.add(uri_counts[0], int(uri_counts[1]))
    h_bar.render_to_file('%sURI_by_reason_%s.svg' % (PIC_DIR, reason_name))
    h_bar.render_to_png('%sURI_by_reason_%s.png' % (PIC_DIR, reason_name))


def alerts_by_reason_in_24h(date, chart_data):
    """
    Generate charts about alert counts by reasons and hours in a day
    :param date, chart_data:
    :return: Create new svg and png chart file in current dir.
    """
    line_chart = pygal.StackedLine(fill=True, truncate_legend=-1, human_readable=True)
    line_chart.title = 'Alerts in 24 hours of ' + date
    line_chart.x_labels = map(str, range(0, 24))
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
    line_chart.render_to_file('%s24h_stackedline_chart_%s.svg' % (PIC_DIR, date))
    line_chart.render_to_png('%s24h_stackedline_chart_%s.png' % (PIC_DIR, date))


def alerts_by_date_chart_pygal(chart_data):
    """
    Generate chart for alerts counts by day via pygal
    :param chart_data:
    :return: dict_deviation which contains day:alert numbers of outliers
                upper_limit which is the upper limit for outliers
    """
    alert_by_date = []
    alert_counts = []
    dict_deviation = {}
    for alert_time_reason in chart_data:
        alert_dt = datetime.datetime.strptime(alert_time_reason[0], "%Y-%m-%dT%H:%M:%S%z")
        alert_by_date.append(alert_dt.strftime('%Y%m%d').__str__())
    alert_dict = Counter(alert_by_date)  # Get counts by day
    upper_limit = get_upper_limit(list(alert_dict.values()))
    #print(alert_dict)
    for k in alert_dict.keys():
        if int(alert_dict[k]) > int(upper_limit):
            #print('k is %s' % k)
            dict_deviation[k] = alert_dict[k]
            alerts_by_reason_in_24h(k, chart_data)
            dt_start = datetime.datetime.strptime(str(k), "%Y%m%d")
            start_date = dt_start.strftime('%Y-%m-%d')
            dt_end = dt_start + datetime.timedelta(days=1)
            end_date = dt_end.strftime('%Y-%m-%d')
            ip_source_chart_pygal(get_top10_ip(DB_NAME, start_date, end_date), start_date)
    # Display legend at bottom can avoid truncate problem
    bar_chart = pygal.Bar(legend_at_bottom=True, show_legend=True, truncate_legend=-1, human_readable=True)
    #  legend_at_bottom_columns=4,
    bar_chart.title = 'Alerts By Date'
    for k in sorted(alert_dict.keys()):  # Sort by day
        alert_counts.append(alert_dict[k])
        bar_chart.add(k, alert_dict[k])
    bar_chart.render_to_png('%salerts_by_date.png' % PIC_DIR)
    bar_chart.render_to_file('%salerts_by_date.svg' % PIC_DIR)
    bar_chart.show_legend = False
    bar_chart.title = 'Alerts By Date'  # TODO: update it with begin and end date
    bar_chart.render_to_file('%salerts_by_date_no_legend.svg' % PIC_DIR)
    bar_chart.render_to_png('%salerts_by_date_no_legend.png' % PIC_DIR)
    return dict_deviation, upper_limit


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
    worldmap_chart.render_to_file("%salerts_world_map.svg" % PIC_DIR)
    worldmap_chart.render_to_png("%salerts_world_map.png" % PIC_DIR)


def alerts_world_map_via_ip_basemap(chart_data):
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    dict_city = {}
    lat = []
    lon = []
    alert_num = []
    country = 'China'
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
            if response.country.name != 'China':
                country = response.country.name
    for i in dict_city.keys():
        lat.append(float(pickle.loads(i)[0]))
        lon.append(float(pickle.loads(i)[1]))
        alert_num.append(float(dict_city[i]))
    # data for folium
    folium_data = []
    for i, n in enumerate(lat):
        folium_data.append([lat[i], lon[i], alert_num[i]])
    # Draw folium map
    m = folium.Map(
        location=[35.5236, 109.49],
        tiles='OpenStreetMap',
        zoom_start=4
    )
    HeatMap(folium_data).add_to(m)
    m.save('pictures/folium_heat_wolrd_map.html')
    # Draw map
    fig = plt.figure(figsize=(8, 4.5))
    plt.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.00)
    if country == 'China':
        pic_name = 'world_china.png'
        m = Basemap(llcrnrlon=80.33, llcrnrlat=5.01, urcrnrlon=145.16, urcrnrlat=56.123,
                    resolution='l', projection='cass', lat_0=42.5, lon_0=120)
    else:
        pic_name = 'world.png'
        m = Basemap(projection='robin', lat_0=35, lon_0=110, resolution='l')
    m.drawcoastlines(linewidth=0.1)
    m.drawcountries(linewidth=0.1)
    m.drawmapboundary(fill_color='#A6CAE0', linewidth=0)
    m.bluemarble(scale=0.5)
    m.fillcontinents(color='#C0C0C0', lake_color='#A6CAE0', zorder=0.1)  # , alpha=0.3)#1A4680
    #x, y = m(lon, lat)
    size = (alert_num/np.max(alert_num))*100
    m.scatter(lon, lat, s=size, label='Alerts Numbers', color='red', marker='o', zorder=2, latlon=True)
    plt.title('Malicious Internet Traffic Source Map')
    plt.savefig('%s%s' % (PIC_DIR, pic_name), dpi=300)
    plt.show()


def ip_source_chart_pygal(chart_data, date=None):
    """
    Generate bar chart to display ip source numbers
    :param chart_data:
    :param date: if it is true then chart name is for this day
    :return:
    """
    bar_chart = pygal.Bar(truncate_legend=-1, human_readable=True)
    if date is None:
        bar_chart.title = 'Top 10 IP Source'
        file_name = 'ip_source_bar'
    else:
        bar_chart.title = 'Top 10 IP Source on %s' % date
        file_name = 'ip_source_bar_%s' % date
    for data in chart_data:
        if data[0] is None:
            continue
        city_name, country_name = get_location_by_ip(data[0])
        x_label_name = "%s(%s,%s)" % (data[0], city_name, country_name)
        bar_chart.add(x_label_name, data[1])
        bar_chart.render()
    bar_chart.render_to_file('%s%s.svg' % (PIC_DIR, file_name))
    bar_chart.render_to_png('%s%s.png' % (PIC_DIR, file_name))


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
    pie_chart.render_to_png('%sreason_type_pie.png' % PIC_DIR)
    pie_chart.render_to_file('%sreason_type_pie.svg' % PIC_DIR)


# reason_type_chart_pygal(get_data_by_reasons(DB_NAME))
# ip_source_chart_pygal(get_top10_ip(DB_NAME))
# #alerts_world_map_via_ip(get_top10_ip(DB_NAME))
# alerts_by_date_chart_pygal(get_alerts_time_reason(DB_NAME))
# all_alert_counts_by_reason_24h(DB_NAME)
# ip_num = get_distinct_ip_num(DB_NAME)
# alerts_world_map_via_ip_basemap(get_top10_ip(DB_NAME, limit=ip_num))
# uri_counts_by_reason(14, get_uri_by_reason(14, DB_NAME))
# export_all_ip(DB_NAME)


#top_reasons = get_data_by_reasons(DB_NAME, 'cn')
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

