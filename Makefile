all: sniff

sniff: sniff.cpp Makefile
	g++ -g -Ofast -Wall -Wpedantic -ansi -o sniff sniff.cpp -lpcap -lanl

clean:
	rm -f *.o sniff
