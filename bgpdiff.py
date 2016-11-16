#!/usr/bin/env python
from radix import Radix
import gzip
import ujson as json
import subprocess
import sys
import re
import math
import numpy as np
import arrow
from _pybgpstream import BGPStream, BGPRecord, BGPElem
from collections import Counter

def fetch_from_file( collector, ts, r ):
   ''' 
   for now assume data is in a specific location on the local filesystem
   ./data/<rc>.<ts>.* # see 'fetch script'
   ''' 
   ext = 'bz2'
   if collector.startswith('rrc'):
      ext = 'gz'
   fname = "./data/%s.%s.%s" % (
      collector,
      ts.format('YYYY-MM-DD.HHmm'),
      ext
   )
   # now see what peer we have to watch at what position in our res
   peer2who = {} # contains (ASN,PEER_IP) tuple map to the index in results
   for who in (1,2):
      if r[ who ]['route_collector'] == collector and r[ who ]['ts'] == ts:
         peer_id = ( r[ who ]['peer_asn'] , r[ who ]['peer_ip'] )
         peer2who[ peer_id ] = who
   # tried load from pickle file to speed things up but that was really marginal speed-up
   # now open file and collect stats over it
   cmd = "%s -m -v -t change %s" % ( CMD_BGPDUMP, fname )
   print >>sys.stderr, "executing %s" % cmd
   for line in subprocess.Popen(cmd, shell=True, bufsize=1024*8, stdout=subprocess.PIPE).stdout:
      # 3 = ASN_IP , 4 = ASN , 5 = PFX , 6 = path
      who=None
      try:
         fields = line.split('|')
         peer_id = ( fields[4], fields[3] )
         if peer_id in peer2who:
            who = peer2who[ peer_id ]
         else:
            continue #this is not the peer you are looking for
      except:
         print >>sys.stderr,"EEP"
         continue
      try: 
         last_change_ts = int(fields[1])
         ts_5m = (last_change_ts / 300 ) * 300
         pfx = fields[5]
         asn = fields[6]
         asns = asn.split(" ")
         if asns[0] == r[who]['peer_asn']:
            asns = asns[1:]
         node = r[who]['radix'].search_exact( pfx )
         if node:
            raise "BGP DATA CONTAINS DUPLICATES; SHOULD NOT HAPPEN: PFX %s" % ( pfx, )
         else:
            newnode = r[who]['radix'].add( pfx )
            newnode.data['aspath'] = asns # used?
            newnode.data['fields'] = fields # used?

         # path length and prepending
         path_len = len( asns )
         if path_len > MAX_REPORTED_PATH_LEN:
            path_len = MAX_REPORTED_PATH_LEN

         asn_count = len( set( asns ) )
         if asn_count > MAX_REPORTED_PATH_LEN:
            asn_count = MAX_REPORTED_PATH_LEN

         if asn_count != path_len:
            r[who]['asn_xpending'] += 1

         r[who]['path_len_cnt'][ path_len ] += 1
         r[who]['path_asn_cnt'][ asn_count ] += 1

      except:
         print >>sys.stderr,"EEP2"
         continue
   return r

def init_result():  
   '''
   initialises the structure that hold data for collector peers to be compared
   '''
   r = {}
   for who in (1,2):
      r[ who ] = {}
      r[ who ]['radix'] = Radix() # holds the radix trees for both
      r[ who ]['path_len_cnt'] = Counter() # path length counter
      r[ who ]['path_asn_cnt'] = Counter() # number of ASNs counter (different from path length because of prepending
      r[ who ]['asn_xpending'] = 0 # covers inpending, prepending (ie. where path_len != asn_count
   return r

def print_header( r ):
   print "COMPARING A:%s to B:%s" % ( r[1]['peer_asn'], r[2]['peer_asn'] )
   print "     TIME A:%s to B:%s" % ( r[1]['ts'], r[2]['ts'] )

def print_prefix_stats( r, set1, set2, missing_from1_naked, missing_from2_naked ):
   print "Prefix counts:      A: %d     B: %d" % ( len(set1), len(set2) )
   print "       unique in:   A: %d     B: %d" % ( len(set1-set2), len(set2-set1) )
   print "missing+naked in:   A: %d     B: %d" % ( len(missing_from1_naked), len(missing_from2_naked) )

def print_path_len_stats( r, pfxset1_size, pfxset2_size ):
   print "path lengths in A vs B"
   for plen in range(0, MAX_REPORTED_PATH_LEN+1):
      if plen == MAX_REPORTED_PATH_LEN:
         plen_str = ">=%s" % plen
      else:
         plen_str = "%-2s" % plen
      plen1 = r[1]['path_len_cnt'][ plen ]
      plen2 = r[2]['path_len_cnt'][ plen ]
      print "  {:<3} {:>8} ({:.1%}) {:>8} ({:.1%})".format(plen_str, 
         plen1, 1.0*plen1/pfxset1_size, 
         plen2, 1.0*plen2/pfxset2_size )

   print "ASNs per path in A vs B"
   for plen in range(0, MAX_REPORTED_PATH_LEN+1):
      if plen == MAX_REPORTED_PATH_LEN:
         plen_str = ">=%s" % plen
      else:
         plen_str = "%-2s" % plen
      plen1 = r[1]['path_asn_cnt'][ plen ]
      plen2 = r[2]['path_asn_cnt'][ plen ]
      print "  {:<3} {:>8} ({:.1%}) {:>8} ({:.1%})".format(plen_str, 
         plen1, 1.0*plen1/pfxset1_size, 
         plen2, 1.0*plen2/pfxset2_size )
   print "percentage of prefixes with in/prepending in A: {:.1%}".format( r[1]['asn_xpending'] * 1.0 /  pfxset1_size )
   print "percentage of prefixes with in/prepending in B: {:.1%}".format( r[2]['asn_xpending'] * 1.0 /  pfxset2_size )

def calc_missing_and_naked( r, set1, set2 ):
   missing_from1_naked = set() # these are the set of prefixes missing in set1 (ie. uniq to set 2) that are not covered by a less specific
   missing_from2_naked = set() #  '' set2
   for pfx in set1 - set2: # prefixes uniq to set 1
      node = r[2]['radix'].search_best( pfx )
      if not node:
         missing_from2_naked.add( pfx )
   for pfx in set2 - set1: # prefixes uniq to set 2
      node = r[1]['radix'].search_best( pfx )
      if not node:
         missing_from1_naked.add( pfx )
   return (missing_from1_naked,missing_from2_naked)

def print_up_path_similarities( r, overlap ):
   '''
   route state distance
   for what % of pfxes (in common) do you make the same next hop decision?
   see: https://cs-people.bu.edu/evimaria/papers/imc12-rsd.pdf
   related is same_path (exact same path)
   returns tuple of: 
      - percentage of same next hop ASN
      - percentage of same path
   '''
   same_up_count = 0
   same_path_count = 0
   up_paths = { # holds the upstreams
      1: Counter(),
      2: Counter(),
   }
   for pfx in overlap:
      n1 = r[1]['radix'].search_exact( pfx )
      n2 = r[2]['radix'].search_exact( pfx )
      up1 = 'self'
      up2 = 'self'
      p1 = n1.data['aspath']
      p2 = n2.data['aspath']
      if len( p1 ) > 0:
         up1 = p1[0]
      if len( p2 ) > 0:
         up2 = p2[0]

      up_paths[1][ up1 ] += 1
      up_paths[2][ up2 ] += 1

      if up1 == up2:
         same_up_count += 1
      if cmp( p1, p2) == 0:
         same_path_count += 1
   pct_same_up = 100.0 * same_up_count / len( overlap )
   pct_same_path = 100.0 * same_path_count / len( overlap )
   print "pfx%% with same next hop ASN: %.1f%%" %  pct_same_up
   print "pfx%% with same upstream path: %.1f%%" % pct_same_path
   most_common_up1 = up_paths[1].most_common(5)
   most_common_up2 = up_paths[2].most_common(5)
   print "For the overlapping prefixes: most common next hop ASN: A vs B"
   for idx in range(0,5):
      #TODO what if there are less then 5 in the most_common set?
      print "  {:<6}  {:>8} ({:.1%})           {:<6}  {:>8} ({:.1%})".format(
         most_common_up1[idx][0], most_common_up1[idx][1], 1.0 * most_common_up1[idx][1] / len(overlap),
         most_common_up2[idx][0], most_common_up2[idx][1], 1.0 * most_common_up2[idx][1] / len(overlap)
      )

def print_naked_characteristics( r, missing1_naked, missing2_naked ):
   '''
   figure out the key characteristics of the missing/naked part
    - total address space size
    - who originates
    - what next hop ASNs
   '''
   print "missing+naked A pfx-distr: %s" % ( _pfx_size_distribution( missing1_naked ) )
   print "missing+naked B pfx-distr: %s" % ( _pfx_size_distribution( missing2_naked ) )

def _pfx_size_distribution( pfxset ):
   plens = {}
   size = {4:0 , 6:0}
   outp = ["pfx sizes:"]
   for p in pfxset:
      base, plen = p.split('/')
      plen = int(plen)
      if ':' in base:
         size[6] += pow(2, 128-plen)
      else:
         size[4] += pow(2, 32-plen)
      plens.setdefault( plen, 0 )
      plens[ plen ] += 1
   for plen in sorted( plens.keys() ):
      outp.append("/%s:%s" % ( plen, plens[plen] ) )
   for af,siz in size.iteritems():
      if siz > 0:
         outp.append("(af:%s total_size:%s)" % (af,siz))
   return ' '.join( outp )

def main():
   r = init_result() # r = the results data structure that will hold info on our peers
   file_defs = set()
   for who in (1,2):
      # fields are 0:ASN,1:PEER_IP,2:ROUTE COLLECTOR NAME,3:timestamp
      peer_def = sys.argv[ who ].split(',')
      r[ who ]['peer_def_raw'] = peer_def
      # normalize timestamps to 8hr interval
      r[ who ]['peer_asn'] = peer_def[0]
      r[ who ]['peer_ip']  = peer_def[1]
      r[ who ]['route_collector'] = peer_def[2]
      r[ who ]['ts'] = arrow.get( peer_def[ 3 ] ) # int( arrow.get( peer_def[3] ).timestamp / 8*3600 ) * 8*3600
      file_defs.add( ( r[ who ]['route_collector'] , r[ who ]['ts'] ) )
   for file_def in file_defs:
      r = fetch_from_file( file_def[0], file_def[1], r )

   ### data is loaded, now do analysis and print the results

   pfxset1 = set( r[1]['radix'].prefixes() )
   pfxset2 = set( r[2]['radix'].prefixes() )
   overlap = pfxset1 & pfxset2
   (missing1_naked, missing2_naked) = calc_missing_and_naked( r, pfxset1, pfxset2 )

   ### print results
   print_header( r )
   print_prefix_stats( r, pfxset1, pfxset2, missing1_naked, missing2_naked )
   print_naked_characteristics( r, missing1_naked, missing2_naked )
   print_path_len_stats( r, len(pfxset1), len(pfxset2) )
   print_up_path_similarities( r, overlap )
   

CMD_BGPDUMP="/Users/emile/bin/bgpdump"
MAX_REPORTED_PATH_LEN=6

if __name__ == '__main__':
   main()

sys.exit(0)

### OLD
peers = Counter()
tree = {1: Radix(), 2: Radix()}
meta = {}
for who in (1,2):
   meta[ who ] = {}
   meta[ who ]['age'] = Counter()
meta[1]['asn'] = ASN1
meta[2]['asn'] = ASN2

def aap():
      last_change_ts = int(fields[1])
      ts_5m = (last_change_ts / 300 ) * 300
      pfx = fields[5]
      asn = fields[6]
      meta[ who ]['age'][ ts_5m ] += 1
      asns = asn.split(" ")
      if asns[0] == meta[who]['asn']:
         asns = asns[1:]
      node = tree[who].search_exact( pfx )

      newnode = tree[who].add( pfx )
      newnode.data['aspath'] = asns
      newnode.data['fields'] = fields

def percentiles_of_timestamps_of_pfxset( pfxset, tree):
   tss = []
   for pfx in pfxset:
      node = tree.search_exact(pfx)
      if node:
         last_change_ts = int( node.data['fields'][1] )
         tss.append( last_change_ts )
      else:
         raise ValueError("pfx %s not in tree, shouldn't happen" % (pfx) )
   #pct_list = map(lambda x: DUMP_TS - x, list( np.percentile( tss, [0,25,50,75,100] ) ) )
   pct_list = list( np.percentile( tss, [0,25,50,75,100] ) )
   return pct_list

def pfx_list_summary( pfx_iter, rtree ):
   things = {}
   things.setdefault('up_asn', Counter())
   for pfx in pfx_iter:
      node = rtree.search_exact( pfx )
      up_asn = None
      path_len = len( node.data['aspath'] )
      if path_len > 0:
         up_asn = node.data['aspath'][0]
      things['up_asn'][ up_asn ] += 1
   summary = {}
   summary['top_up_asns'] = things['up_asn'].most_common( 5 )
   summary['up_asns_count'] = len( things['up_asn'] )
   return summary



### this shows the percentiles of how old the 'not covered' sets are. Are they just relatively recent?
#print "nr pfx in A / no covering in B: %d (ts-distr: %s)" % ( len( not_covered_in_2 ), percentiles_of_timestamps_of_pfxset( not_covered_in_2, tree[1] ) )
#print "nr pfx in B / no covering in A: %d (ts-distr: %s)" % ( len( not_covered_in_1 ), percentiles_of_timestamps_of_pfxset( not_covered_in_1, tree[2] ) )

print "pfx sizes for pfx in A / no covering in B: %s" % ( print_pfx_size_distribution( not_covered_in_2 ) )
print "pfx sizes for pfx in B / no covering in A: %s" % ( print_pfx_size_distribution( not_covered_in_1 ) )

print "summ upstream for pfx in A / no covering in B: %s" % pfx_list_summary( not_covered_in_2, tree[1] )
print "summ upstream for pfx in B / no covering in A: %s" % pfx_list_summary( not_covered_in_1, tree[2] )


'''
#### path ages
# not that useful?
minA = min( meta[1]['age'].keys() )
minB = min( meta[2]['age'].keys() )
maxA = max( meta[1]['age'].keys() )
maxB = max( meta[2]['age'].keys() )

ageA = maxA - minA
ageB = maxB - minB

modeA = meta[1]['age'].most_common(1)[0][0]
modeB = meta[2]['age'].most_common(1)[0][0]

print "oldest timestamp A: %s min (mode: %s min)" % ( ageA/60, (maxA - modeA)/60 )
print "oldest timestamp B: %s min (mode: %s min)" % ( ageB/60, (maxB - modeB)/60 )
'''

### what are the defining characteristics of the differences of not covered sets 'naked'

# sorts of analysis
# - prefix sets
# - as path length comparison
# - amount of prepending
# - amount of communities
# - same origins for same prefixes
# - bgp origin

## further: machine learning: types of ASNs, can you learn? can you make a decision tree?
