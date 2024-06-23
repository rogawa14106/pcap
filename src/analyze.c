// #include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
// #include <string.h>
#include <sys/types.h> //usr/incldue/x86_64-linux-gnu u_char
// #include <unistd.h>
#include "analyze.h"
#include "checksum.h"
#include "dns.h"
#include "print.h"
#include <net/ethernet.h>     //ether_header
#include <netinet/if_ether.h> //ether_arp
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> //icmp
#include <netinet/tcp.h>     //tcphdr
#include <netinet/udp.h>     //udphdr

int AnalyzeArp(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct ether_arp *arp;

  ptr = data;
  lest = size;

  // 受け取ったデータのサイズが、arpの構造体のサイズ以上であることを確認
  if (lest < sizeof(struct ether_arp)) {
    fprintf(stderr, "lest(%d)<sizeof(struct ether_arp)(%ld)\n", lest,
            sizeof(struct ether_arp));
    return (-1);
  }

  // ポインタをセット
  arp = (struct ether_arp *)ptr;

  // arpパケットの構造体のぶんだけポインタを進める
  ptr += sizeof(struct ether_arp);
  // arpパケットの構造体のぶんだけサイズを小さくする
  lest -= sizeof(struct ether_arp);

  // arpパケット表示
  PrintArp(arp, stdout);

  return (0);
} /*}}}*/

int AnalyzeIcmp(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct icmp *icmp;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct icmp)) {
    fprintf(stderr, "AnalyzeIcmp:error:lest(%d)<sizeof(struct icmp)(%ld)\n",
            lest, sizeof(struct icmp));
    return (-1);
  }

  icmp = (struct icmp *)ptr;

  ptr += sizeof(struct icmp);
  lest -= sizeof(struct icmp);

  PrintIcmp(icmp, stdout);

  return (0);
} /*}}}*/

int AnalyzeTCP(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct tcphdr *tcphdr;

  ptr = data;
  lest = size;
  if (lest < sizeof(struct tcphdr)) {
    fprintf(stderr, "AnalyzeTCP:error:lest(%d)<sizeof(struct tcphdr)(%ld)\n",
            lest, sizeof(struct tcphdr));
    return (-1);
  };

  tcphdr = (struct tcphdr *)ptr;
  ptr += sizeof(struct tcphdr);
  lest -= sizeof(struct tcphdr);

  PrintTCP(tcphdr, stdout);
  return (0);
} /*}}}*/

int AnalyzeUDP(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct udphdr *udphdr;

  ptr = data;
  lest = size;
  if (lest < sizeof(struct udphdr)) {
    fprintf(stderr, "AnalyzeUDP:error:lest(%d)<sizeof(struct udphdr)(%ld)\n",
            lest, sizeof(struct udphdr));
    return (-1);
  };

  udphdr = (struct udphdr *)ptr;
  ptr += sizeof(struct udphdr);
  lest -= sizeof(struct udphdr);

  PrintUDP(udphdr, stdout);

  // analyze protocol
  if (ntohs(udphdr->dest) == 53 || ntohs(udphdr->source) == 53) {
    AnalyzeDNS(ptr, lest);
  }
  return (0);
} /*}}}*/

int AnalyzeIp(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct iphdr *iphdr;
  u_char *opt;
  int opt_len, len;
  u_int16_t sum;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct iphdr)) {
    fprintf(stderr, "AnalyzeIp:lest(%d)<sizeof(struct ip)(%ld)\n", lest,
            sizeof(struct iphdr));
    return (-1);
  }

  iphdr = (struct iphdr *)ptr;
  ptr += sizeof(struct iphdr);
  lest -= sizeof(struct iphdr);

  opt_len = (iphdr->ihl * 4) - sizeof(struct iphdr);
  if (opt_len >= 1500) {
    fprintf(stderr, "AnalyzeIp:ip opt too big");
    return (-1);
  }
  opt = ptr;
  ptr += opt_len;
  lest -= opt_len;

  // check sum of ip header
  sum = IpHdrChecksum(iphdr, opt, opt_len);
  fprintf(stdout, "    (IphdrChecksum: 0x%04x)\n", sum);
  if ((sum != 0) && (sum != 0xFFFF)) {
    fprintf(stderr, "    \e[31m(bad ip header checksum)\e[0m\n");
  }

  // print ip header
  PrintIpHeader(iphdr, opt, opt_len, stdout);

  // analyze protocol
  if (iphdr->protocol == IPPROTO_ICMP) {
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    sum = checksum(ptr, len);
    fprintf(stdout, "    (icmp checksum: 0x%04x)\n", sum);
    if (sum != 0xFFFF && sum != 0) {
      fprintf(stderr, "    \e[31m(bad icmp checksum)\e[0m\n");
      //       return (-1);
    }
    AnalyzeIcmp(ptr, len);

  } else if (iphdr->protocol == IPPROTO_TCP) {
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    sum = IpDataChecksum(iphdr, ptr, len);
    fprintf(stdout, "    (tcp checksum: 0x%04x)\n", sum);
    if (sum != 0xFFFF && sum != 0) {
      fprintf(stderr, "    \e[31m(bad tcp checksum)\e[0m\n");
      //       return (-1);
    }
    AnalyzeTCP(ptr, lest);

  } else if (iphdr->protocol == IPPROTO_UDP) {
    // if udphdr check field is not 0, check ckecksum of udp
    struct udphdr *udphdr = (struct udphdr *)ptr;
    if (udphdr->check != 0) {
      len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
      sum = IpDataChecksum(iphdr, ptr, len);
      fprintf(stdout, "    (udp checksum: 0x%04x)\n", sum);
      if (sum != 0xFFFF && sum != 0) {
        fprintf(stderr, "    \e[31m(bad udp checksum)\e[0m\n");
        //       return (-1);
      }
    }
    AnalyzeUDP(ptr, lest);

  } else if (iphdr->protocol == IPPROTO_UDP) {
    //   case IPPROTO_IPV6:
    //     //     AnalyzeIpv6(ptr, lest);

  } else {
    fprintf(stderr, "    \e[31m(unknown l4 protocol)\e[0m\n");
  }
  return (0);
} /*}}}*/

int AnalyzeIpv6(u_char *data, int size) { /*{{{*/
  ;
  return (0);
} /*}}}*/

int AnalyzePacket(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  struct ether_header *eth;

  ptr = data;
  lest = size;

  // ethernet header
  if (lest < sizeof(struct ether_header)) {
    fprintf(stderr, "lest(%d) < sizeof(struct ether_header)(%ld)\n", lest,
            sizeof(struct ether_header));
    return (-1);
  }
  eth = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);
  PrintEtherHeader(eth, stdout);

  // ethernet
  switch (ntohs(eth->ether_type)) {
  case ETH_P_IP:
    AnalyzeIp(ptr, lest);
    break;
  case ETH_P_IPV6:
    //     AnalyzeIpv6(ptr, lest);
    break;
  case ETH_P_ARP:
    AnalyzeArp(ptr, lest);
    break;
  default:
    fprintf(stdout, "(unknown)\n");
  }

  return (0);
} /*}}}*/

int AnalyzeDNS(u_char *data, int size) { /*{{{*/
  u_char *ptr;
  int lest;
  u_char *start;
  struct dnshdr *dnshdr;
  struct dnsdata *dnsdata;

  ptr = data;
  lest = size;
  start = ptr; // abs data ptr

  if (lest < sizeof(struct dnshdr)) {
    fprintf(stderr, "AnalyzeDNZ:error:lest(%d)<sizeof(struct dnshdr)(%ld)\n",
            lest, sizeof(struct dnshdr));
    return (-1);
  }

  dnshdr = (struct dnshdr *)data;
  ptr += sizeof(struct dnshdr);
  lest -= sizeof(struct dnshdr);

  PrintDNSHdr(dnshdr, stdout);

  //   PrintHexDump(ptr, lest);
  dnsdata = (struct dnsdata *)malloc(sizeof(struct dnsdata));
  ParseDNSData(ptr, lest, start, dnsdata);
  PrintDNSData(dnsdata, htons(dnshdr->ancount), stdout);
  //   if (dnshdr->flags & DNS_QR) {
  //     // response
  //     AnalyzeDNSR(dnshdr, ptr, lest);
  //   } else {
  //     // query
  //     int qsize;
  //     AnalyzeDNSQ(dnshdr, ptr, &qsize);
  //   }

  free(dnsdata);
  return (0);
} /*}}}*/
