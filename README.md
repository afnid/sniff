# sniff
Network usage sniffer based on pcap libraries which will show the hosts with the biggest data usage using a sliding time window.

The sniff utility quickly aggregates your biggest data users on your network so you can identify hosts that are using an excessive amount of bandwidth.  Extremely useful to find all the people streaming video when the world cup was on.  Also was able to find hosts doing full backups during peak times of day.  Helpful utility to identify types of traffic for further shaping.

After going through several different network tools, none of them aggregated the data the way we needed.  This is a pure text based console app for viewing top bandwidth uses.

Aggregates data by host name and protocol.
It groups data by external vs internal hosts.
Hosts are sorted by the biggest to smallest users.
A default 10 second sliding window sums all packets.
Standard pcap options can be passed through.
Asynchronous hostname lookups.
