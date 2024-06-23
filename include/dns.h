#ifndef DNS_H
#define DNS_H

// domain name system
//$ curl https://www.rfc-editor.org/rfc/rfc1035.txt
// multicast dns
//$ curl https://www.rfc-editor.org/rfc/rfc6762.txt

#include <sys/types.h>
#define QNAME_MAXLEN 255
#define LABEL_MAXLEN 63

// header flags
#define DNS_QR 0x8000

#define DNS_OP_MSK 0x7800
#define DNS_OP_STD 0x0000
#define DNS_OP_PTR 0x0800
#define DNS_OP_STAT 0x1800

#define DNS_AA 0x0400

#define DNS_TC 0x0200

#define DNS_RD 0x0100

#define DNS_RA 0x0080

#define DNS_Z 0x0070

#define DNS_RC_MSK 0x000F
#define DNS_RC_NOERROR 0x0000
#define DNS_RC_FORMERR 0x0001
#define DNS_RC_SERVFAIL 0x0002
#define DNS_RC_NXDOMAIN 0x0003
#define DNS_RC_NOTIMP 0x0004
#define DNS_RC_REFUSED 0x0005

// resource record types
#define DNS_RRT_A 0x0001
#define DNS_RRT_CNAME 0x0005
#define DNS_RRT_SOA 0x0006
#define DNS_RRT_MB 0x0007
#define DNS_RRT_PTR 0x000c
#define DNS_RRT_MX 0x000f
#define DNS_RRT_AAAA 0x001c

// message compression bit mask
#define DNS_MSK_CMP 0xC000

// dns header
struct dnshdr {
  u_int16_t id;
  u_int16_t flags;
  u_int16_t qdcount;
  u_int16_t ancount;
  u_int16_t nscount;
  u_int16_t arcount;
};

// dns query section
struct dnsq {
  u_char name[128];
  u_int16_t type;
  u_int16_t class;
};

// dns resource record
struct dnsrr {
  u_char name[128];
  u_int16_t type;
  u_int16_t class;
  u_int32_t ttl;
  u_int16_t rdlen;
  u_char rdata[65536];
};

struct dnsdata {
  struct dnsq dnsq;
  struct dnsrr dnsrr[32];
};

// int ParseName(u_char *data, u_char *buf, int *len);
int AnalyzeDNSQ(struct dnshdr *dnshdr, u_char *data, int *qsize);
int AnalyzeDNSRR(u_char *data, int *rrsize);
int AnalyzeDNSR(struct dnshdr *dnshdr, u_char *data, int size);
int ParseName(u_char *name, u_char *start, int offset);
int ParseDNSData(u_char *data, int lest, u_char *start, struct dnsdata *dnsdata);

#endif
