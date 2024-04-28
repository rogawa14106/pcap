#include <stdio.h>
// #include <sys/types.h>//u_char
#include <arpa/inet.h>        //htonl, htons
#include <net/ethernet.h>     //ether_header
#include <netinet/ether.h>    //ehter_ntoa, ether_ntoa_r
#include <netinet/if_ether.h> //ether_arp
#include <netinet/ip.h>       //ip
#include <netinet/ip_icmp.h>  //icmp
#include <netinet/tcp.h>      //tcphdr
#include <netinet/udp.h>      //udphdr

// <netinet/ether.h>で定義されているether_ntoa_rだと0埋めしてくれないから、自分で定義する。
// char *my_ether_ntoa_r(struct ether_addr *hwaddr, char *buf) {
//   sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr->ether_addr_octet[0],
//           hwaddr->ether_addr_octet[1], hwaddr->ether_addr_octet[2],
//           hwaddr->ether_addr_octet[3], hwaddr->ether_addr_octet[4],
//           hwaddr->ether_addr_octet[5]);
//   return (buf);
// }
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size) {
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1],
           hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  return (buf);
}

char *ip_ip2str(uint32_t ip, char *buf, int size) {
  struct in_addr *addr;
  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return (buf);
}

char *arp_ip2str(uint8_t *ip, char *buf, int size) {
  snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return (buf);
}

int PrintArp(struct ether_arp *arp, FILE *fp) {
  char buf[80];
  fprintf(fp, "%6s== arp_header ==\n", "");
  fprintf(fp, "%6sarp_hrd: %u\n", "", ntohs(arp->arp_hrd)); // hardware
  fprintf(fp, "%6sarp_pro: 0x%x", "", ntohs(arp->arp_pro)); // protocol
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
  fprintf(fp, "%6sarp_hln: %u(byte)\n", "", arp->arp_hln); // hardware addr len
  fprintf(fp, "%6sarp_pln: %u(byte)\n", "", arp->arp_pln); // protocol addr len
  fprintf(fp, "%6sarp_sha: %s\n", "",
          my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf))); // source hw addr
  fprintf(fp, "%6sarp_spa: %s\n", "",
          arp_ip2str(arp->arp_spa, buf, sizeof(buf))); // source protocol addr
  fprintf(fp, "%6sarp_tha: %s\n", "",
          my_ether_ntoa_r(arp->arp_tha, buf, sizeof(buf))); // target hw addr
  fprintf(fp, "%6sarp_tpa: %s\n", "",
          arp_ip2str(arp->arp_tpa, buf, sizeof(buf))); // target protocol addr
  return (0);
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp) {
  char buf[80];
  fprintf(fp, "%2s== ether_header ==\n", "");
  fprintf(fp, "%2saddrs    : %s > ", "",
          my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
  fprintf(fp, "%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
  fprintf(fp, "%2stype     : 0x%x", "", ntohs(eh->ether_type));
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
}

int PrintIpHeader(struct iphdr *iphdr, u_char *opt, int opt_len, FILE *fp) {
  char buf[80];
  fprintf(fp, "%4s== ip_header ==\n", "");
  //  ip address
  fprintf(fp, "%4saddrs   : %s > ", "",
          ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
  fprintf(fp, "%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
  // version
  fprintf(fp, "%4sversion : v%u\n", "", iphdr->version);
  // header length
  fprintf(fp, "%4shdr len : %u(byte)\n", "", iphdr->ihl * 4);
  // type of service
  fprintf(fp, "%4stos     : %u\n", "", iphdr->tos);
  // total length (header & data)
  fprintf(fp, "%4stot len : %u(byte)\n", "", ntohs(iphdr->tot_len));
  // identification
  fprintf(fp, "%4sid      : %u\n", "", ntohs(iphdr->id));
  // fragment off set
  fprintf(fp, "%4sfrag_off: %u\n", "", ntohs(iphdr->frag_off));
  // time to live
  fprintf(fp, "%4sttl     : %u\n", "", iphdr->ttl);

  // protocol
  fprintf(fp, "%4sprotocol: %02d", "", iphdr->protocol);
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
  case IPPROTO_IPV6:
    fprintf(fp, "(IPv6)\n");
    break;
  default:
    fprintf(fp, "(unknown)\n");
  }

  fprintf(fp, "%4scheck   : %04x\n", "", iphdr->check);

  fprintf(fp, "%4s(opt len : %04x)\n", "", opt_len);

  return (0);
}

int PrintIcmp(struct icmp *icmp, FILE *fp) {
  fprintf(fp, "%6s== icmp_header ==\n", "");
  fprintf(fp, "%6stype: %u\n", "", icmp->icmp_type);
  fprintf(fp, "%6scode: %u\n", "", icmp->icmp_code);
  fprintf(fp, "%6schecksum: %u\n", "", icmp->icmp_cksum);
  return (0);
}

int PrintTCP(struct tcphdr *tcphdr, FILE *fp) {
  //   char buf[80];
  fprintf(fp, "%6s== tcp_header ==\n", "");
  fprintf(fp, "%6ssport: %u\n", "", ntohs(tcphdr->source));
  fprintf(fp, "%6sdport: %u\n", "", ntohs(tcphdr->dest));
  fprintf(fp, "%6sseq: %u\n", "", ntohs(tcphdr->seq));
  fprintf(fp, "%6sack_seq: %u\n", "", ntohs(tcphdr->ack_seq));
  fprintf(fp, "%6sdata offset: %u\n", "", tcphdr->doff);
  fprintf(fp, "%6sfin: %u\n", "", tcphdr->fin);
  fprintf(fp, "%6ssyn: %u\n", "", tcphdr->syn);
  fprintf(fp, "%6srst: %u\n", "", tcphdr->rst);
  fprintf(fp, "%6spsh: %u\n", "", tcphdr->psh);
  fprintf(fp, "%6sack: %u\n", "", tcphdr->ack);
  fprintf(fp, "%6surg: %u\n", "", tcphdr->urg);
  fprintf(fp, "%6swindow: %u\n", "", ntohs(tcphdr->window));
  fprintf(fp, "%6scheck: %u\n", "", ntohs(tcphdr->check));
  fprintf(fp, "%6surg_ptr: %u\n", "", ntohs(tcphdr->urg_ptr));
  return (0);
}

int PrintUDP(struct udphdr *udphdr, FILE *fp) {
  //   char buf[80];
  fprintf(fp, "%6s== udp_header ==\n", "");
  fprintf(fp, "%6ssport: %u\n", "", ntohs(udphdr->source));
  fprintf(fp, "%6sdport: %u\n", "", ntohs(udphdr->dest));
  fprintf(fp, "%6slen  : %u\n", "", ntohs(udphdr->len));
  fprintf(fp, "%6scheck: %x\n", "", ntohs(udphdr->check));
  return (0);
}
