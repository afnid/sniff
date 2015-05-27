/*
 * Released under GPL V3 or later.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>

typedef u_int32_t addr_t;
typedef u_int32_t hash_t;

struct node {
	time_t created;
	addr_t saddr;
	addr_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint8_t protocol;
	uint8_t tos;

	struct node *next;
	struct node *prev;
};

struct lookup {
	addr_t addr;
	char *name;

	time_t touched;

	struct gaicb *request;
	struct sigevent *handler;

	struct lookup *next;
};

typedef enum {
	KeyProto,
	KeySrcAddr,
	KeyDstAddr,
	KeySrcPort,
	KeyDstPort,
	KeyTos,

	KeyBytes,
	KeyCount,
	KeyMax
} KeyIdxType;

static bpf_u_int32 netmask = 0;
static bpf_u_int32 network = 0;
static int window = 10;
static char *devname = 0;
static char *pcaprules = 0;
static int showlines = 20;
static int verbose = 0;

static int doproto = 1;
static int doports = 0;
static int dohosts = 1;
static int dotos = 0;

static int errors = 0;
static int nolocal = 0;

static time_t nextrefresh = 0;
static int datalink = 0;
static int linkhdrlen = 14;
static size_t allocated;

static const int hashbytes = sizeof(hash_t) * KeyMax;

static size_t thash = 0;
static hash_t *hash = 0;

static struct lookup *lookup = 0;
static int nlookups = 0;

static struct node *head = 0;

static addr_t *networks = 0;

static void *mymalloc(size_t size) {
	void *buf = malloc(size);

	if (!buf) {
		fprintf(stderr, "Out of Memory: %lu\n", size);
		exit(1);
	}

	allocated += size;
	bzero(buf, size);
	return buf;
}

static void myfree(void *buf, size_t size) {
	allocated -= size;
	bzero(buf, size);
	free(buf);
}

static void hexdump(const u_char *buf, int n) {
	printf("%3d  ", 0);

	for (int i = 0; i < n && i < 64; i++) {
		if (i && !(i % 16))
			printf("\n%3d  ", i);

		if (i >= 8 && !((i - 8) % 16))
			printf(" -");

		printf(" %02x", *buf++);
	}

	printf("\n");
}

static addr_t makeaddr(addr_t o0, addr_t o1, addr_t o2, addr_t o3) {
	return htonl((o0 << 24) | (o1 << 16) | (o2 << 8) | o3);
}

static addr_t makemask(int bits) {
	addr_t mask = ~0L;
	return htonl(mask << (sizeof(addr_t) * 8 - bits));
}

static int issamenet(addr_t a1, addr_t a2, addr_t mask) {
	return (a1 & mask) == (a2 & mask);
}

static int isInternal(addr_t addr) {
	if (!networks) {
		networks = (addr_t *) mymalloc(sizeof(addr_t) * 3 * 2);
		networks[0] = makeaddr(192, 168, 0, 0);
		networks[1] = makemask(16);
		networks[2] = makeaddr(172, 16, 0, 0);
		networks[3] = makemask(12);
		networks[4] = makeaddr(10, 0, 0, 0);
		networks[5] = makemask(8);

		if (verbose) {
			for (int i = 0; i < 6; i++) {
				char buf[NI_MAXHOST];
				inet_ntop(AF_INET, &networks[i], buf, sizeof(buf) - 1);
				printf("network %d %x %s\n", i, networks[i], buf);
			}

			for (int i = 0; i < 6; i += 2)
				printf("\nnetwork %d %x %d\n", i, addr, issamenet(networks[i], makeaddr(172, 16, 0, 240), networks[i + 1]));
		}
	}

	if (issamenet(addr, network, netmask))
		return 1;

	for (int i = 0; i < 6; i += 2)
		if (issamenet(addr, networks[i], networks[i + 1]))
			return 1;

	return 0;
}

static const char *fmtaddr(addr_t addr, char *buf, int n) {
	bzero(buf, n);
	inet_ntop(AF_INET, &addr, buf, n - 1);
	return buf;
}

static const char *fmtbytes(uint32_t bytes, char *buf, int n) {
	bzero(buf, n);

	if (bytes > 1024 * 2)
		sprintf(buf, "%u KB", bytes / 1024);
	else
		sprintf(buf, "%u B", bytes);

	return buf;
}

static const char *fmtrate(uint32_t bits, char *buf, int n) {
	bzero(buf, n);

	if (bits >= 3 * 1024)
		sprintf(buf, "%u Kb/s", bits / 1024);
	else
		sprintf(buf, "%u b/s", bits);

	return buf;
}

static void lookup_handler(union sigval val) {
	struct lookup *l = (struct lookup *) (val.sival_ptr);
	int ret = gai_error(l->request);

	if (!ret) {
		char host[NI_MAXHOST];
		bzero(host, sizeof(host));

		struct addrinfo *res = l->request->ar_result;
		int ret = getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host) - 1, NULL, 0, 0);

		if (ret)
			fprintf(stderr, "Error: getaddrinfo_a() = %s\n", gai_strerror(ret));
		else
			l->name = strdup(host);

		free((char *) l->request->ar_name);
		myfree(l->request, sizeof(struct gaicb));
		myfree(l->handler, sizeof(struct sigevent));

		l->request = 0;
		l->handler = 0;
	}

	if (!l->name) {
		printf("\nsnafu\n");

		struct hostent *ent = gethostbyaddr(&l->addr, 4, AF_INET);

		if (ent && ent->h_name)
			l->name = strdup(ent->h_name);
	}
}

static struct lookup *findlookup(addr_t addr) {
	struct lookup *l = lookup;
	struct lookup *last = 0;
	time_t now;

	time(&now);

	while (l && l->addr != addr) {
		if (last && now - l->touched > 30) {
			last->next = l->next;
			free(l->name);
			myfree(l, sizeof(struct lookup));
			l = last;
			nlookups--;
		}

		last = l;
		l = l->next;
	}

	return l;
}

static const char *lookup_addr(addr_t addr) {
	struct lookup *l = findlookup(addr);

	if (!l) {
		l = (struct lookup*) mymalloc(sizeof(struct lookup));
		l->addr = addr;
		l->next = lookup;

		l->request = (struct gaicb *) mymalloc(sizeof(struct gaicb));
		l->handler = (struct sigevent *) mymalloc(sizeof(struct sigevent));

		char buf[NI_MAXHOST];
		bzero(buf, sizeof(buf));
		l->request->ar_name = strdup(inet_ntop(AF_INET, &l->addr, buf, sizeof(buf) - 1));

		l->handler->sigev_notify = SIGEV_THREAD;
		l->handler->sigev_notify_function = lookup_handler;
		l->handler->sigev_value.sival_ptr = l;

		int ret = getaddrinfo_a(GAI_NOWAIT, &l->request, 1, l->handler);

		if (ret)
			fprintf(stderr, "Error: getaddrinfo_a(%s) = %s\n", l->request->ar_name, gai_strerror(ret));

		lookup = l;
		nlookups++;
	}

	time(&l->touched);

	return l->name;
}

static void shownode(const char *title, struct node *n) {
	static int count = 0;

	char srcbuf[255];
	char dstbuf[255];
	fmtaddr(n->saddr, srcbuf, sizeof(srcbuf));
	fmtaddr(n->daddr, dstbuf, sizeof(dstbuf));

	printf("%s %d %ld %d %s:%d %s:%d %d\n", title, count++, n->created, n->protocol, srcbuf, n->sport, dstbuf, n->dport, n->len);
}

static int isExpired(const struct node *n, const time_t now) {
	return now - n->created > window;
}

static struct node *newnode() {
	struct node *node = (struct node*) mymalloc(sizeof(struct node));
	node->next = node;
	node->prev = node;
	return node;
}

static void unlink(struct node *node) {
	//shownode("unlink", node);
	node->next->prev = node->prev;
	node->prev->next = node->next;
}

static void insert(struct node *n) {
	struct node *node = 0;

	if (!head)
		head = newnode();
	else if (isExpired(head->next, n->created)) {
		node = head->next;
		unlink(head->next);
		memcpy(node, n, sizeof(struct node));
	}

	if (!node) {
		node = newnode();
		memcpy(node, n, sizeof(struct node));
	}

	head->prev->next = node;
	node->prev = head->prev;
	node->next = head;
	head->prev = node;
	//shownode("insert", node);
}

static void allochash() {
	if (!hash) {
		thash = 128;
		size_t n = hashbytes * thash;
		hash = (hash_t *) mymalloc(n);
	} else {
		size_t n = hashbytes * thash;
		hash = (hash_t *) realloc(hash, n * 2);

		if (!hash) {
			fprintf(stderr, "Out of Memory %lu", thash);
			exit(1);
		}

		allocated += n;
		bzero(hash + thash * KeyMax, n);
		thash *= 2;
	}
}

static hash_t *hashptr(int index) {
	return hash + index * KeyMax;
}

static int hashget(int index, KeyIdxType offset) {
	return hashptr(index)[offset];
}

static int keycmp(const hash_t *k1, const hash_t *k2) {
	for (int i = 0; i < KeyBytes; i++) {
		int v = *k1++ - *k2++;

		if (v != 0)
			return v < 0 ? -1 : 1;
	}

	return 0;
}

static int hashidx(const hash_t *key) {
	hash_t k = 0;

	for (int i = 0; i < KeyBytes; i++)
		k += key[i];

	for (unsigned int i = 0; i < thash; i++) {
		int n = (i + k) % thash;
		hash_t *h = hashptr(n);

		if (!keycmp(h, key) || !h[KeyBytes])
			return n;
	}

	return -1;
}

static void addhash(const hash_t *key, hash_t add) {
	int n = hashidx(key);

	while (n < 0) {
		allochash();
		n = hashidx(key);
	}

	if (n >= 0) {
		hash_t *h = hashptr(n);

		for (int i = 0; i < KeyBytes; i++)
			*h++ = *key++;

		*h++ += add;
		*h += 1;
	}
}

static int haskey(const hash_t *h) {
	for (int i = 0; i < KeyBytes; i++)
		if (*h++)
			return 1;
	return 0;
}

static int compare(const void *p1, const void *p2) {
	const hash_t *h1 = (hash_t *) p1;
	const hash_t *h2 = (hash_t *) p2;

	if (!haskey(h1) && !haskey(h2))
		return 0;
	if (haskey(h1) && !haskey(h2))
		return -1;
	if (!haskey(h1) && haskey(h2))
		return 1;

	int val = h2[KeyBytes] - h1[KeyBytes];

	if (val != 0)
		return val < 0 ? -1 : 1;

	return keycmp(h1, h2);
}

static const hash_t *fillkey(hash_t *key, hash_t k0, hash_t k1, hash_t k2, hash_t k3, hash_t k4, hash_t k5) {
	key[0] = k0;
	key[1] = k1;
	key[2] = k2;
	key[3] = k3;
	key[4] = k4;
	key[5] = k5;
	return key;
}

static void hashnode(const node *n) {
	hash_t proto = 0;
	hash_t sport = 0;
	hash_t dport = 0;
	hash_t saddr = 0;
	hash_t daddr = 0;
	hash_t tos = 0;

	if (doproto) {
		proto = n->protocol;
		sport = 1; // fix sorts for arp
		dport = 1;
	}

	if (doports) {
		sport = n->sport;
		dport = n->dport;
	}

	if (dohosts) {
		saddr = n->saddr;
		daddr = n->daddr;
	}

	if (dotos)
		tos = n->tos;

	hash_t key[KeyMax];
	bzero(key, sizeof(key));

	addhash(fillkey(key, proto, saddr, daddr, sport, dport, tos), n->len);
}

static void print(int width, const char *s) {
	printf(" %*s", width, s);
}

static int namelen(addr_t addr) {
	const char *name = lookup_addr(addr);
	return !name ? 0 : strlen(name);
}

static void showhash(time_t seconds) {
	qsort(hash, thash, hashbytes, compare);

	uint32_t total = 0;
	int namepad = 20;

	for (unsigned int i = 0; i < thash; i++) {
		hash_t v = hashget(i, KeyBytes);

		if (v) {
			total += v;

			int len;

			if ((len = namelen(hashget(i, KeySrcPort))) > namepad)
				namepad = len;
			if ((len = namelen(hashget(i, KeyDstPort))) > namepad)
				namepad = len;
		}
	}

	if (total) {
		uint32_t sent = 0;
		uint32_t recv = 0;

		for (int internal = 0; internal < 2; internal++) {
			uint32_t other = 0;
			unsigned int others = 0;
			char buf[256];
			int bytes = 0;
			int count = 0;

			for (unsigned int i = 0; i < thash; i++) {
				hash_t val = hashget(i, KeyBytes);

				if (val && internal == isInternal(hashget(i, KeySrcAddr))) {
					if (count == 0) {
						print(4, "idx");
						if (doproto)
							print(6, "proto");
						if (dotos)
							print(5, "tos");
						if (doports) {
							print(5, "port ");
							print(5, "port ");
						}
						print(6, "pkts");
						print(10, "bytes  ");
						print(10, "rate  ");
						print(7, "pct ");
						if (dohosts) {
							printf("  %-15s", "sender");
							printf(" %-15s", "receiver");
						}
						printf("\n");
					}

					double pct = val * 100.0 / total;

					if (isInternal((addr_t) hashget(i, KeySrcAddr)))
						sent += val;
					else
						recv += val;

					bytes += val;

					if (count++ < showlines) {
						printf(" %4u", count);

						if (doproto) {
							int protocol = hashget(i, KeyProto);

							if (protocol == 6)
								printf(" %6s", "tcp");
							else if (protocol == 17)
								printf(" %6s", "udp");
							else
								printf(" %5d ", protocol);
						}

						if (dotos) {
							hash_t tos = hashget(i, KeyTos);

							if (tos)
								printf("  0x%02x ", tos);
							else
								printf("       ");
						}

						if (doports) {
							printf(" %5u", hashget(i, KeySrcPort));
							printf(" %5u", hashget(i, KeyDstPort));
						}

						printf(" %6u", hashget(i, KeyCount));
						printf(" %10s", fmtbytes(val, buf, sizeof(buf)));
						printf(" %10s", fmtrate(val * 8L / seconds, buf, sizeof(buf)));
						printf(" %6.2f%%", pct);

						if (dohosts) {
							addr_t saddr = hashget(i, KeySrcAddr);
							addr_t daddr = hashget(i, KeyDstAddr);

							printf("  %-15s", fmtaddr(saddr, buf, sizeof(buf)));
							printf(" %-15s", fmtaddr(daddr, buf, sizeof(buf)));

							const char *name1 = lookup_addr(saddr);
							const char *name2 = lookup_addr(daddr);

							if (name1)
								printf(" %-*s", namepad, name1);
							if (name2)
								printf(" %s", name2);
						}

						printf("\n");
					} else {
						other += val;
						others++;
					}
				}
			}

			int pad = 4 + 6 + 1;

			if (doproto)
				pad += 6 + 1;
			if (dotos)
				pad += 5 + 2;
			if (doports)
				pad += 5 + 5 + 2;

			if (other > 0) {
				print(pad, "");
				printf(" %10s", fmtbytes(other, buf, sizeof(buf)));
				printf(" %10s", fmtrate(other * 8L / seconds, buf, sizeof(buf)));
				printf(" %6.2f%%", other * 100.0 / bytes);
				printf("   %u other active sessions\n", others);
			}

			if (count)
				printf("\n");

			if (internal == 1) {
				pad += 10 + 1;

				if (sent > 0) {
					print(pad, "sent:");
					printf(" %10s\n", fmtrate(sent * 8L / seconds, buf, sizeof(buf)));
				}

				if (recv > 0) {
					print(pad, "recv:");
					printf(" %10s\n", fmtrate(recv * 8L / seconds, buf, sizeof(buf)));
				}

				print(pad, "total:");
				printf(" %10s\n\n", fmtrate(total * 8L / seconds, buf, sizeof(buf)));
			}
		}

		fflush(stdout);
	}
}

static void refresh(const time_t now) {
	while (1) {
		uint32_t oldthash = thash;
		unsigned int f = 0;
		unsigned int x = 0;
		unsigned int c = 0;
		unsigned int t = 0;

		time_t min = 0;
		time_t max = 0;

		bzero(hash, thash * hashbytes);

		for (struct node *n = head->next; n != head; n = n->next) {
			time_t age = now - n->created;

			if (isExpired(n, now)) {
				if (age > window * 2) {
					struct node *t = n;
					n = n->prev;
					unlink(t);
					myfree(t, sizeof(struct node));
					f++;
				}

				x++;
			} else if (age != 0) {
				if (min == 0 || min > n->created)
					min = n->created;
				if (max == 0 || max < n->created)
					max = n->created;
				hashnode(n);
				c++;
			}

			t++;
		}

		if (oldthash == thash) {
			if (c) {
				char buf[256];

				if (!verbose)
					printf("\e[1;1H\e[2J");
				//system("/usr/bin/clear");

				showhash(max - min + 1);

				printf("=== %s", devname);
				printf(" network=%s", fmtaddr(network, buf, sizeof(buf)));
				printf(" netmask=%s", fmtaddr(netmask, buf, sizeof(buf)));

				if (errors)
					printf(" errors=%u", errors);

				if (nolocal)
					printf(" nolocal");

				printf(" window=%us", window);

				if (max - min + 1 != window)
					printf(" actual=%lu", max - min + 1);

				printf(" packets=%u", c);
				if (x)
					printf(" extra=%u", x);
				if (f)
					printf(" free=%u", f);

				printf(" nodes=%u", t);
				printf(" hash=%lu", thash);
				printf(" lookups=%u", nlookups);
				printf(" linkhdrlen=%u", linkhdrlen);
				printf(" memory=%s", fmtbytes(allocated, buf, sizeof(buf)));

				printf("\n\n");

				errors = 0;
			}

			break;
		}
	}
}

static void callback(u_char *pd, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct iphdr *ip = (struct iphdr *) (packet + linkhdrlen);

	if (datalink == 1) {
		struct ether_header *eh = (struct ether_header *) packet;
		int type = ntohs(eh->ether_type);

		if (type == ETHERTYPE_ARP || type == ETHERTYPE_REVARP)
			return;

		if (type == ETHERTYPE_IPV6) {
			// TODO: struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + linkhdrlen);
			// TODO: ipv6
			return;
		}
	}

	if (ip->version != 4) {
		if (verbose) {
			int type = 0;

			if (datalink == 1) {
				struct ether_header *eh = (struct ether_header *) packet;
				type = ntohs(eh->ether_type);
			}

			printf("bad packet %u %u type=%x ihl=%u v=%u caplen=%u pktlen=%u\n", datalink, linkhdrlen, type, ip->ihl, ip->version, pkthdr->caplen, pkthdr->len);
			hexdump(packet, pkthdr->len);
		}
		errors++;
		return;
	}

	if (nolocal && issamenet(ip->saddr, ip->daddr, netmask))
		return;

	struct node node;
	bzero(&node, sizeof(node));
	node.tos = ip->tos;
	int iplen = ip->ihl * 4;

	if (ip->protocol == 6) {
		struct tcphdr *tcp = (struct tcphdr *) (packet + linkhdrlen + iplen);
		node.sport = ntohs(tcp->source);
		node.dport = ntohs(tcp->dest);
	} else if (ip->protocol == 17) {
		struct udphdr *udp = (struct udphdr *) (packet + linkhdrlen + iplen);
		node.sport = ntohs(udp->source);
		node.dport = ntohs(udp->dest);
	} else if (verbose && !(ip->protocol == 0 || ip->protocol == 1)) {
		printf("unexpected protocol %d pktlen=%d linklen=%d iplen=%d\n", ip->protocol, pkthdr->len, linkhdrlen, iplen);
		hexdump(packet, pkthdr->len);
		return;
	}

	node.created = pkthdr->ts.tv_sec;
	node.len = pkthdr->len;
	node.protocol = ip->protocol;
	node.saddr = ip->saddr;
	node.daddr = ip->daddr;
	insert(&node);

	if (nextrefresh <= node.created) {
		nextrefresh = node.created + 2;
		refresh(node.created);
	}

	if (verbose > 1 || node.len < 34)
		shownode("status", &node);
}

static void showdevs() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devs;

	if (pcap_findalldevs(&devs, errbuf) == -1) {
		fprintf(stderr, "Error: pcap_findalldevs() %s\n", errbuf);
		exit(1);
	}

	int n = 0;

	for (pcap_if_t *d = devs; d; d = d->next) {
		if (!devname)
			devname = d->name;

		printf("iface %d - %s", ++n, d->name);

		if (d->description)
			printf(" (%s)", d->description);

		printf("\n");
	}
}

static void usage() {
	printf("sniff [OPTIONS]... [RULES]...\n");
	printf("\t-h toggle aggregate totals by host\n");
	printf("\t-d toggle aggregate totals by tos/dscp\n");
	printf("\t-i <iface> device to listen on\n");
	printf("\t-l exclude local to local packets\n");
	printf("\t-p aggregate totals by ports used\n");
	printf("\t-s number of lines to show\n");
	printf("\t-t toggle aggregation by protocol\n");
	printf("\t-v verbose debugging info\n");
	printf("\t-w <window> size of the sample window\n");
	printf("\t [RULES]... standard pcap filter rules\n");
}

static void options(int argc, char **argv) {
	int c;

	while ((c = getopt(argc, argv, "di:hm:ps:tvw:")) > 0) {
		switch (c) {
			case 'h':
				dohosts = !dohosts;
				break;
			case 'i':
				devname = optarg;
				break;
			case 'l':
				nolocal = !nolocal;
				break;
			case 'p':
				doports = !doports;
				break;
			case 's':
				showlines = atoi(optarg);
				break;
			case 't':
				doproto = !doproto;
				break;
			case 'd':
				dotos = !dotos;
				break;
			case 'v':
				verbose++;
				break;
			case 'w':
				window = atoi(optarg);
				break;

			case '?':
				usage();
				exit(1);
				break;

			default:
				printf("?? getopt returned character code 0%o ??\n", c);
				usage();
				exit(1);
		}
	}

	if (optind < argc) {
		int len = 0;

		for (int i = optind; i < argc; i++)
			len += strlen(argv[i]) + 1;

		pcaprules = (char *) mymalloc(len);
		char *s = pcaprules;

		for (int i = optind; i < argc; i++) {
			if (i > optind)
				strcpy(s++, " ");
			strcat(s, argv[i]);
			s += strlen(s);
		}
	}

	if (devname)
		printf("Running on interface: %s\n", devname);
	else
		showdevs();

	if (verbose) {
		printf("bufsize %d\n", BUFSIZ);
		printf("node %ld\n", sizeof(struct node));
		printf("lookup %ld\n", sizeof(struct lookup));

		printf("ip %ld\n", sizeof(struct ip));
		printf("tcp %ld\n", sizeof(struct tcphdr));
		printf("udp %ld\n", sizeof(struct udphdr));
	}
}

int main(int argc, char **argv) {
	options(argc, argv);

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_lookupnet(devname, &network, &netmask, errbuf) < 0)
		fprintf(stderr, "Error: pcap_lookupnet() %s\n", errbuf);

	printf("%s network %s\n", devname, fmtaddr(network, errbuf, sizeof(errbuf)));
	printf("%s netmask %s\n", devname, fmtaddr(netmask, errbuf, sizeof(errbuf)));

	pcap_t* pcap;

	if (!(pcap = pcap_open_live(devname, BUFSIZ, 0, 100, errbuf))) {
		fprintf(stderr, "Error: pcap_open_live() %s\n", errbuf);
		showdevs();
		exit(1);
	}

	struct bpf_program fp;

	if (pcaprules) {
		if (pcap_compile(pcap, &fp, pcaprules, 0, network) < 0) {
			fprintf(stderr, "\npcap_compile() failed\n");
			exit(1);
		}

		if (pcap_setfilter(pcap, &fp) < 0) {
			fprintf(stderr, "\npcap_setfilter() failed\n");
			exit(1);
		}
	}

	datalink = pcap_datalink(pcap);

	if (datalink == 113)
		linkhdrlen = 16;

	int loops = 0;

	while (nice(1) >= 0 && loops < 100)
		loops++;

	pcap_loop(pcap, 0, callback, NULL);

	exit(0);
}
