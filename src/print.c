#include <stdio.h>
#include <string.h>
// #include <sys/types.h>//u_char
#include "dns.h"
#include <arpa/inet.h>        //htonl, htons
#include <net/ethernet.h>     //ether_header
#include <netinet/ether.h>    //ehter_ntoa, ether_ntoa_r
#include <netinet/if_ether.h> //ether_arp
#include <netinet/ip.h>       //ip
#include <netinet/ip_icmp.h>  //icmp
#include <netinet/tcp.h>      //tcphdr
#include <netinet/udp.h>      //udphdr

int PrintHexDump(u_char *data, int lest) {/*{{{*/
  printf("--- Hex Dump Start ---\n");
  while (lest) {
    printf("ptr: %p, HEX: %02x, CHAR: %c\n", data, *data, *data);
    data++;
    lest--;
  }
  printf("--- Hex Dump Done ---\n");
  return 0;
};/*}}}*/

// <netinet/ether.h>で定義されているether_ntoa_rだと0埋めしてくれないから、自分で定義する。
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size) { /*{{{*/
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1],
           hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  return (buf);
} /*}}}*/

char *ip_ip2str(uint32_t ip, char *buf, int size) { /*{{{*/
  struct in_addr *addr;
  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return (buf);
} /*}}}*/

char *arp_ip2str(uint8_t *ip, char *buf, int size) { /*{{{*/
  snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return (buf);
} /*}}}*/

int PrintEtherHeader(struct ether_header *eh, FILE *fp) { /*{{{*/
  char buf[80];
  fprintf(fp, "\e[32m== ether_header ==\e[0m\n");
  // hw addr
  fprintf(fp, "addrs    : %s > ",
          my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
  fprintf(fp, "%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
  // protocol type
  fprintf(fp, "type     : 0x%x", ntohs(eh->ether_type));
  switch (ntohs(eh->ether_type)) {
  case ETH_P_IP:
    fprintf(fp, "(IP)\n");
    break;
  case ETH_P_IPV6:
    fprintf(fp, "(IPv6)\n");
    break;
  case ETH_P_ARP:
    fprintf(fp, "(ARP)\n");
    break;
  default:
    fprintf(fp, "(unknown)\n");
  }
  return (0);
} /*}}}*/

int PrintArp(struct ether_arp *arp, FILE *fp) { /*{{{*/
  char buf[80];
  fprintf(fp, "    \e[32m== arp_header ==\e[0m\n");
  fprintf(fp, "    arp_hrd: %u\n", ntohs(arp->arp_hrd)); // hardware
  fprintf(fp, "    arp_pro: 0x%x", ntohs(arp->arp_pro)); // protocol
  switch (ntohs(arp->arp_pro)) {
  case ETH_P_IP:
    fprintf(fp, "(IP)\n");
    break;
  case ETH_P_IPV6:
    fprintf(fp, "(IPv6)\n");
    break;
  case ETH_P_ARP:
    fprintf(fp, "(ARP)\n");
    break;
  default:
    fprintf(fp, "(unknown)\n");
  }
  fprintf(fp, "    arp_hln: %u(byte)\n", arp->arp_hln); // hardware addr len
  fprintf(fp, "    arp_pln: %u(byte)\n", arp->arp_pln); // protocol addr len
  fprintf(fp, "    arp_sha: %s\n",
          my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf))); // source hw addr
  fprintf(fp, "    arp_spa: %s\n",
          arp_ip2str(arp->arp_spa, buf, sizeof(buf))); // source protocol addr
  fprintf(fp, "    arp_tha: %s\n",
          my_ether_ntoa_r(arp->arp_tha, buf, sizeof(buf))); // target hw addr
  fprintf(fp, "    arp_tpa: %s\n",
          arp_ip2str(arp->arp_tpa, buf, sizeof(buf))); // target protocol addr
  return (0);
} /*}}}*/

int PrintIpHeader(struct iphdr *iphdr, u_char *opt, int opt_len,
                  FILE *fp) { /*{{{*/
  char buf[80];
  fprintf(fp, "    \e[32m== ip_header ==\e[0m\n");
  //  ip address
  fprintf(fp, "    addrs   : %s > ", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
  fprintf(fp, "%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
  // version
  fprintf(fp, "    version : v%u\n", iphdr->version);
  // header length
  fprintf(fp, "    hdr len : %u(byte)\n", iphdr->ihl * 4);
  // type of service
  fprintf(fp, "    tos     : %u\n", iphdr->tos);
  // total length (header & data)
  fprintf(fp, "    tot len : %u(byte)\n", ntohs(iphdr->tot_len));
  // identification
  fprintf(fp, "    id      : %u\n", ntohs(iphdr->id));
  // fragment off set
  fprintf(fp, "    frag_off: %u\n", ntohs(iphdr->frag_off));
  // time to live
  fprintf(fp, "    ttl     : %u\n", iphdr->ttl);

  // protocol
  fprintf(fp, "    protocol: %02d", iphdr->protocol);
  switch (iphdr->protocol) {
  case IPPROTO_ICMP:
    fprintf(fp, "(ICMP)\n");
    break;
  case IPPROTO_TCP:
    fprintf(fp, "(TCP)\n");
    break;
  case IPPROTO_UDP:
    fprintf(fp, "(UDP)\n");
    break;
    //   case IPPROTO_IPV6:
    //     fprintf(fp, "(IPv6)\n");
    //     break;
  default:
    fprintf(fp, "(unknown)\n");
  }

  fprintf(fp, "    check   : 0x%04x\n", iphdr->check);

  fprintf(fp, "    (opt len : %u)\n", opt_len);

  return (0);
} /*}}}*/

int PrintIcmp(struct icmp *icmp, FILE *fp) { /*{{{*/
  fprintf(fp, "        \e[32m== icmp_header ==\e[0m\n");
  fprintf(fp, "        type: %u\n", icmp->icmp_type);
  fprintf(fp, "        code: %u\n", icmp->icmp_code);
  fprintf(fp, "        checksum: %u\n", icmp->icmp_cksum);
  return (0);
} /*}}}*/

int PrintTCP(struct tcphdr *tcphdr, FILE *fp) { /*{{{*/
  //   char buf[80];
  fprintf(fp, "        \e[32m== tcp_header ==\e[0m\n");
  fprintf(fp, "        sport: %u\n", ntohs(tcphdr->source));
  fprintf(fp, "        dport: %u\n", ntohs(tcphdr->dest));
  fprintf(fp, "        seq: %u\n", ntohs(tcphdr->seq));
  fprintf(fp, "        ack_seq: %u\n", ntohs(tcphdr->ack_seq));
  fprintf(fp, "        data offset: %u\n", tcphdr->doff);
  fprintf(fp, "        fin: %u\n", tcphdr->fin);
  fprintf(fp, "        syn: %u\n", tcphdr->syn);
  fprintf(fp, "        rst: %u\n", tcphdr->rst);
  fprintf(fp, "        psh: %u\n", tcphdr->psh);
  fprintf(fp, "        ack: %u\n", tcphdr->ack);
  fprintf(fp, "        urg: %u\n", tcphdr->urg);
  fprintf(fp, "        window: %u\n", ntohs(tcphdr->window));
  fprintf(fp, "        check: 0x%04x\n", ntohs(tcphdr->check));
  fprintf(fp, "        urg_ptr: %u\n", ntohs(tcphdr->urg_ptr));
  return (0);
} /*}}}*/

int PrintUDP(struct udphdr *udphdr, FILE *fp) { /*{{{*/
  //   char buf[80];
  fprintf(fp, "        \e[32m== udp_header ==\e[0m\n");
  fprintf(fp, "        sport: %u\n", ntohs(udphdr->source));
  fprintf(fp, "        dport: %u\n", ntohs(udphdr->dest));
  fprintf(fp, "        len  : %u\n", ntohs(udphdr->len));
  fprintf(fp, "        check: 0x%04x\n", ntohs(udphdr->check));
  return (0);
} /*}}}*/

int PrintDNSHdr(struct dnshdr *dnshdr, FILE *fp) { /*{{{*/
  u_int16_t flg = ntohs(dnshdr->flags);
  fprintf(fp, "            \e[32m== DNS ==\e[0m\n");
  fprintf(fp, "            id        : %u\n", ntohs(dnshdr->id));
  fprintf(fp, "            flags     : 0x%04x\n", flg);
  fprintf(fp, "                QR    : 0x%04x", flg & DNS_QR);
  if (flg & DNS_QR) {
    fprintf(fp, "(response)\n");
  } else {
    fprintf(fp, "(query)\n");
  }
  fprintf(fp, "                Opcode: 0x%04x\n", flg);
  fprintf(fp, "                AA    : 0x%04x\n", flg);
  fprintf(fp, "                TC    : 0x%04x\n", flg);
  fprintf(fp, "                RD    : 0x%04x\n", flg);
  fprintf(fp, "                RA    : 0x%04x\n", flg);
  fprintf(fp, "                Z     : 0x%04x\n", flg);
  fprintf(fp, "                RCODE : 0x%04x\n", flg);
  fprintf(fp, "            qdcount   : %u\n", ntohs(dnshdr->qdcount));
  fprintf(fp, "            ancount   : %u\n", ntohs(dnshdr->ancount));
  fprintf(fp, "            nscount   : %u\n", ntohs(dnshdr->nscount));
  fprintf(fp, "            arcount   : %u\n", ntohs(dnshdr->arcount));
  return (0);
} /*}}}*/

int PrintDNSData(struct dnsdata *dnsdata, u_int16_t ancount, FILE *fp) {/*{{{*/
  // # print query section
  printf("            --- query section ---\n");
  printf("            name  : %s\n", dnsdata->dnsq.name);
  printf("            type  : %04x\n", ntohs(dnsdata->dnsq.type));
  printf("            class : %04x\n", ntohs(dnsdata->dnsq.class));

  // # print resource record section
  int rr_cnt = 0;
  while (rr_cnt < ancount) {
    fprintf(fp, "            --- resoure record ---\n");
    fprintf(fp, "            name  : %s\n", dnsdata->dnsrr[rr_cnt].name);
    fprintf(fp, "            type  : %04x\n",
            ntohs(dnsdata->dnsrr[rr_cnt].type));
    fprintf(fp, "            class : %04x\n",
            ntohs(dnsdata->dnsrr[rr_cnt].class));
    fprintf(fp, "            ttl   : %08x\n",
            ntohs(dnsdata->dnsrr[rr_cnt].ttl));
    fprintf(fp, "            rdlen : %04x\n",
            ntohs(dnsdata->dnsrr[rr_cnt].rdlen));
    if (htons(dnsdata->dnsrr[rr_cnt].type) == DNS_RRT_A) {
      uint32_t addr;
      char buf[80];
      memcpy(&addr, &dnsdata->dnsrr[rr_cnt].rdata, sizeof(u_int32_t));
      fprintf(fp, "            rdata : %s\n",
              ip_ip2str(addr, buf, sizeof(buf)));
    } else if (htons(dnsdata->dnsrr[rr_cnt].type) == DNS_RRT_CNAME) {
      fprintf(fp, "            rdata : %s\n", dnsdata->dnsrr[rr_cnt].rdata);
    } else if (htons(dnsdata->dnsrr[rr_cnt].type) == DNS_RRT_AAAA) {
      fprintf(fp,
              "            rdata : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
              (int)*dnsdata->dnsrr[rr_cnt].rdata,
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+1),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+2),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+3),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+4),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+5),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+6),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+7),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+8),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+9),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+10),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+11),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+12),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+13),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+14),
              (int)*(dnsdata->dnsrr[rr_cnt].rdata+15));
    } else {
      fprintf(fp, "            rdata: type not supported. print hexdump");
      PrintHexDump(dnsdata->dnsrr[rr_cnt].rdata,
               ntohs(dnsdata->dnsrr[rr_cnt].rdlen));
    }
    rr_cnt++;
  }
  return 0;
}/*}}}*/
