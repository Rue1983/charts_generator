from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
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


chart_data = get_top10_ip("alertsbig.db")
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
        location = [response.location.latitude, response.location.longitude]
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

fig = plt.figure(figsize=(8, 4.5))
plt.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.00)
m = Basemap(projection='mill', lon_0=0, resolution='c')
#m.bluemarble(scale=0.5)
#m.drawmapboundary()
# m.drawstates(linewidth=0)
#m.drawlsmask(land_color='white',ocean_color='cyan')
m.fillcontinents(color='gray', lake_color='#1A4680', zorder=0.3)
m.drawcoastlines(linewidth=0)
m.drawcountries(linewidth=0.1)
#x, y = m(lon, lat)
size = (alert_num/np.max(alert_num))*1000
print(size)
m.scatter(lon, lat, s=size, color='red', latlon=True)
#m.scatter(-93.2323, 44.9733, s=111, color='red', latlon=True)
#plt.colorbar(label='Malicious Traffic Source Map')
plt.savefig('world1.png', dpi=150)
plt.show()
