SNIFF=~/bin/sniff

$(SNIFF): sniff.cpp
	echo run: apt-get install -y libpcap-dev
	g++ -g -Ofast -Wall -Wpedantic -ansi -o $(SNIFF) sniff.cpp -lpcap -lanl
	size $(SNIFF)

clean:
	rm -f *.o $(SNIFF)
