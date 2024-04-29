#ifndef CHECKSUM_H
#define CHECKSUM_H
// #include <sys/types.h>
#include <netinet/ip.h>

u_int16_t checksum(u_char *data, int len);
u_int16_t checksum2(u_char *data, int len, u_char *data2, int len2);
u_int16_t IpHdrChecksum(struct iphdr *iphdr, u_char *opt, int opt_len);
u_int16_t IpDataChecksum(struct iphdr *iphdr, u_char *data, int len);

#endif
