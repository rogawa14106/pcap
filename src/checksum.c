#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

u_int16_t checksum(u_char *data, int len) { /*{{{*/
  u_int32_t sum;
  u_int16_t *ptr;
  int c;

  sum = 0;
  ptr = (u_int16_t *)data;
  // 32bitごとの補数和をとる。lenは8bit単位、ptrは16bit単位なので2ずつ減らす
  for (c = len; c > 1; c -= 2) {
    sum += (*ptr);

    // 加算した結果が0x80000000(2^31)以上だった場合(次の加算で桁溢れする可能性がある数に達した場合)、
    // 前半16ビット(sum & 0xFFFF)と後半16ビット(sum >> 16)の和を取る
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }

  // add first half 8bit if len is odd.
  if (c == 1) {
    u_int16_t val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
    //     fprintf(stderr, "    \e[31m!checksum odd!\[0m");
    //     sum += (*ptr >> 8);
  }

  // convert 32-bit word one's complement to 16-bit word one's complement
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // take one's complement. i.e. flip the bits.
  return (~sum);
} /*}}}*/

u_int16_t checksum2(u_char *data, int len, u_char *data2, int len2) { /*{{{*/
  u_int32_t sum;
  u_int16_t *ptr;
  int c;

  sum = 0;

  // checksum of data
  ptr = (u_int16_t *)data;
  for (c = len; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    //     sum += (*ptr >> 8);
    uint16_t val;
    val = ((*ptr) << 8) + (*data2);
    sum += val;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr = (u_int16_t *)(data2 + 1);
    len2--;
  } else {
    ptr = (u_int16_t *)data2;
  }

  // checksum of data2
  ptr = (u_int16_t *)data2;
  for (c = len2; c > 1; c -= 2) {
    sum += *ptr;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    //     sum += (*ptr >> 8);
    u_int16_t val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  // convert 32-bit word one's complement to 16-bit word one's complement
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // take one's complement
  return (~sum);
} /*}}}*/

u_int16_t IpHdrChecksum(struct iphdr *iphdr, u_char *opt, int opt_len) { /*{{{*/
  u_int16_t sum;
  if (opt_len == 0) {
    // if has no options, check sum of only header.
    sum = checksum((u_char *)iphdr, sizeof(struct iphdr));
  } else {
    // if has options, check sum of header and option.
    sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), opt, opt_len);
  }
  return sum;
} /*}}}*/

u_int16_t IpDataChecksum(struct iphdr *iphdr, u_char *data, int len) { /*{{{*/
  struct psedou_ip {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t padding;
    u_int8_t protocol;
    u_int16_t len;
  };

  u_int16_t sum;
  struct psedou_ip pseudo_hdr;

  // create pseudo header to caliculate checksum of udp/tcp
  memset(&pseudo_hdr, 0, sizeof(struct psedou_ip));
  pseudo_hdr.saddr = iphdr->saddr;
  pseudo_hdr.daddr = iphdr->daddr;
  pseudo_hdr.protocol = iphdr->protocol;
  pseudo_hdr.len = htons(len);

  sum = checksum2((u_char *)&pseudo_hdr, sizeof(pseudo_hdr), data, len);

  return sum;
} /*}}}*/
