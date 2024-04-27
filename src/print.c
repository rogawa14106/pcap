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
char *my_ether_ntoa_r(struct ether_addr *hwaddr, char *buf) {
  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr->ether_addr_octet[0],
          hwaddr->ether_addr_octet[1], hwaddr->ether_addr_octet[2],
          hwaddr->ether_addr_octet[3], hwaddr->ether_addr_octet[4],
          hwaddr->ether_addr_octet[5]);
  return (buf);
}

char *ip_ip2str(uint32_t ip, char *buf, int size) {
  struct in_addr *addr;
  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return (buf);
}

int PrintArp(struct ether_arp *arp, FILE *fp) { return (0); }

int PrintIcmp(struct icmp *icmp, FILE *fp) {
  fprintf(fp, "%4s== icmp_header ==\n", "");
  return (0);
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp) {
  char buf[80];
  fprintf(fp, "%2s== ether_header ==\n", "");
  fprintf(fp, "%2s%s > ", "",
          my_ether_ntoa_r((struct ether_addr *)eh->ether_shost, buf));
  fprintf(fp, "%s\n",
          my_ether_ntoa_r((struct ether_addr *)eh->ether_dhost, buf));
  fprintf(fp, "%2stype=%02x", "", ntohs(eh->ether_type));
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

int PrintIpHeader(struct iphdr *iphdr, u_char *opt, FILE *fp) {
  char buf[80];
  fprintf(fp, "%4s== ip_header ==\n", "");
  fprintf(fp, "%4sversion: v%d\n", "", iphdr->version);
  // fprintf(fp, "%4slength : %d(byte)\n", "", iphdr->ihl*4);
  fprintf(fp, "%4s%s > ", "", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
  fprintf(fp, "%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
  return (0);
}

int printTCP(struct tcphdr *tcp, FILE *fp) {
  //   char buf[80];
  fprintf(fp, "%6s== tcp_header ==\n", "");
  return (0);
}
int printUDP(struct udphdr *udp, FILE *fp) {
  //   char buf[80];
  fprintf(fp, "%6s== udp_header ==\n", "");
  return (0);
}
