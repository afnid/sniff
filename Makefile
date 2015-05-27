all: sniff

sniff: sniff.cpp Makefile
	gcc -g -Ofast -Wpedantic -Wall -o sniff sniff.cpp -lpcap -lanl

clean:
	rm -f *.o sniff
