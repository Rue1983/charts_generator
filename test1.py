from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
from matplotlib.collections import PathCollection
from matplotlib.path import Path

fig = plt.figure(figsize=(8, 4.5))
plt.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.00)

# MPL searches for ne_10m_land.shp in the directory 'D:\\ne_10m_land'
m = Basemap(projection='robin',lon_0=0,resolution='c')
shp_info = m.readshapefile('ne_10m_land_scale_rank', 'scalerank', drawbounds=True)
ax = plt.gca()
ax.cla()
paths = []
for line in shp_info[4]._paths:
    paths.append(Path(line.vertices, codes=line.codes))
coll = PathCollection(paths, linewidths=0, facecolors='grey', zorder=2)
m = Basemap(projection='robin',lon_0=0,resolution='c')

# drawing something seems necessary to 'initiate' the map properly
m.drawcoastlines(color='white', zorder=0)

#m.bluemarble(scale=0.5)
ax = plt.gca()
ax.add_collection(coll)
#x,y = map(lon,lat)
# map.scatter(x,y,edgecolors='r',facecolors='r',marker='*',s=320)
m.drawcountries()
m.scatter(-93.2323, 44.9733, s=1111, latlon=True)
plt.savefig('world.png', dpi=150)
plt.show()
