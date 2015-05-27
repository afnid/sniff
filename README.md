# sniff
Network usage sniffer based on pcap libraries which will show the hosts with the biggest data usage using a sliding time window.

<pre>
The sniff utility quickly aggregates your biggest data users on your network so you can identify hosts that are using an excessive amount of bandwidth.  Extremely useful to find all the people streaming video during big sporting events.  Also was able to find hosts doing full backups during peak times of day.  Helpful utility to identify types of traffic for further shaping that was too hard to pick out with just tcpdump.

After going through several different network tools, none of them aggregated the data the way we needed.  This is a pure text based console app for viewing top bandwidth uses.

Aggregates data by host name and protocol.
It groups data by external vs internal hosts.
Hosts are sorted by the biggest to smallest users.
A default 10 second sliding window sums all packets.
Standard pcap options can be passed through.
Asynchronous hostname lookups.


sniff [OPTIONS]... [RULES]...
	-h aggregate totals by host
	-i <iface> device to listen on
	-l exclude local to local packets
	-p aggregate totals by ports
	-s number of lines to show
	-t aggregate totals by protocol
	-v verbose
	-w <window> size of the sample window
	 [RULES]... standard pcap filter rules
	 
In order to build you will need the pcap and anl libraries:

gcc -g -O2 -Wall -o sniff sniff.cpp -lpcap -lanl

Running this with WAN traffic is much more interesting, but here is a sample running within a server lan:

<p>
<img src=screenshot.png/>

</pre>
