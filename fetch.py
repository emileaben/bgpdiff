#!/usr/bin/env python
import arrow
import sys
import urllib

## find the last 8hr boundary with some slack
ts = arrow.now().timestamp

if len( sys.argv ) == 2:
   ts = arrow.get( sys.argv[1] ).timestamp

dump_t = arrow.get( int( ( ts + 3600) / (8*3600)) * (8*3600) )

## fetches the latest from RIS/RouteViews (and others)?
rrc_list=map(lambda x: "rrc%02d" % x, range(0,22) )
rv_list=[
   '',
   'route-views3',
   'route-views4',
   'route-views6',
   'route-views.eqix',
   'route-views.jinx',
   'route-views.kixp',
   'route-views.linx',
   'route-views.nwax',
   'route-views.isc',
   'route-views.wide',
   'route-views.saopaulo',
   'route-views.sydney',
   'route-views.telxatl',
   'route-views.sg',
   'route-views.perth',
   'route-views.sfmix',
   'route-views.soxrs' 
]


# ris files
for rrc in rrc_list:
   url = "http://data.ris.ripe.net/%s/%s/bview.%s.gz" % (
         rrc,
         dump_t.format('YYYY.MM'),
         dump_t.format('YYYYMMDD.HHmm')
      )
   file_name = "./data/%s.%s.gz" % ( rrc, dump_t.format('YYYY-MM-DD.HHmm') )
   urllib.urlretrieve( url , file_name )
   
for rv in rv_list:
   url = "http://archive.routeviews.org/%s/bgpdata/%s/RIBS/rib.%s.bz2" % (
         rv,
         dump_t.format('YYYY.MM'),
         dump_t.format('YYYYMMDD.HHmm')
      )
   if rv == '':
      rv = 'route-views2'
   file_name = "./data/%s.%s.bz2" % ( rv, dump_t.format('YYYY-MM-DD.HHmm') )
   urllib.urlretrieve( url , file_name )
