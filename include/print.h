#ifndef PRINT_H
#define PRINT_H

#include "dns.h"
#include <netinet/if_ether.h> //ether_arp
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> //icmp
#include <netinet/tcp.h>     //tcp
#include <netinet/udp.h>     //udp
#include <stdio.h>           //usr/include FILE

int PrintHexDump(u_char *data, int lest);
int PrintEtherHeader(struct ether_header *eh, FILE *fp);
int PrintArp(struct ether_arp *arp, FILE *fp);
int PrintIcmp(struct icmp *ip_icmp, FILE *fp);
int PrintIpHeader(struct iphdr *ip, u_char *opt, int opt_len, FILE *fp);
int PrintUDP(struct udphdr *udphdr, FILE *fp);
int PrintTCP(struct tcphdr *tcphdr, FILE *fp);
int PrintDNSHdr(struct dnshdr *dnshdr, FILE *fp);
int PrintDNSData(struct dnsdata *dnsdata, u_int16_t ancount, FILE *fp);

#endif
