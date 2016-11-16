# bgpdiff: compare 2 BGP table snapshots

Inspired by libbgpdump2 which provides a diff for 2 BGP table snapshots, this is an attempt to take that
a step further and provide a concise summary of what the difference between 2 BGP tables is.

Currently the tool works as follows:

You define 2 BGP table snapshots like this:

    ./bgpdiff.py 25091,195.208.209.93,rrc13,2016-09-26T08:00:00 25091,193.232.245.93,rrc13,2016-01-01T00:00:00

so the format to specify is

    ASN,peerIP,RouteCollector,timestamp

bgpdiff assumes you downloaded the snapshot containing this dump into a local ./data/ directory. There is a local
fetch.py script that fetches RouteViews and RIS files into ./data/ into the right format.

Currently this tool takes a few minutes to process the data on my MacbookPro.
