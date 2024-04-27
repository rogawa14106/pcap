#ifndef PRINT_H
#define PRINT_H

int PrintEtherHeader(struct ether_header* eh, FILE *fp);
int PrintArp(struct ether_arp* arp, FILE *fp);
int PrintIcmp(struct icmp* ip_icmp, FILE* fp);
int PrintIpHeader(struct iphdr* ip, u_char* opt, FILE* fp);

#endif
