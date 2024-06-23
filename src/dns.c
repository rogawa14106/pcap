#include "dns.h"
#include "print.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

int ParseName(u_char *name, u_char *start, int offset) {
  u_char *cursor;
  cursor = start + offset;
  //   printf("start:%p, cursor:%p\n", start, cursor);
  int name_size;
  name_size = 0;

  while (1) {
    if (*cursor == '\0') {
      // nullだったらParseNameを抜ける
      //       printf("ParseName:null\n");
      name_size++;
      return name_size;
    } else if (ntohs(*cursor) & DNS_MSK_CMP) {
      // 圧縮メッセージだったら、ParseNameを再帰呼出し。
      cursor++;
      name_size++;
      //       printf("cmp cursor: %02x, offset: %d\n", *cursor, (int)*cursor);
      ParseName(name, start, (int)*cursor);
      cursor++;
      name_size++;
      return name_size;
    } else {
      // 通常は、数字を読んでその分だけ読み進める
      //       printf("cursor: %02x, is_cmp:%x,%x\n", *cursor, *cursor << 8,
      //       DNS_MSK_CMP);
      int cnt = *cursor;
      cursor++;
      name_size++;
      for (int i = 0; i < cnt; i++) {
        *name = *cursor;
        //         printf("%02x:ParseName:name: %c, %02x\n", i, *name,
        //         (int)*name);
        cursor++;
        name++;
        name_size++;
      }
      *name = '.';
      name++;
    }
  }

  return name_size;
}

int ParseDNSData(u_char *data, int lest, u_char *start,
                 struct dnsdata *dnsdata) {
  int rr_cnt = 0;
  int name_size = 0;
  int offset;
  offset = sizeof(struct dnshdr);

  // # read query section
  //   printf("--- read query section start --- lest: %d\n", lest);
  // read query name
  name_size = ParseName(dnsdata->dnsq.name, start, offset);
  //   printf("debug:dnsdata->dnsq.name: %s\n", dnsdata->dnsq.name);
  data += name_size;
  offset += name_size;
  lest -= name_size;
  // read query type
  memcpy(&dnsdata->dnsq.type, data, sizeof(dnsdata->dnsq.type));
  //   printf("ptr: %p, debug:dnsdata->dnsq.type: %04x\n", data,
  //   ntohs(dnsdata->dnsq.type));
  data += sizeof(dnsdata->dnsq.type);
  offset += sizeof(dnsdata->dnsq.type);
  lest -= sizeof(dnsdata->dnsq.type);
  // read query class
  memcpy(&dnsdata->dnsq.class, data, sizeof(dnsdata->dnsq.class));
  //   printf("ptr: %p, debug:dnsdata->dnsq.class: %04x\n", data,
  //   ntohs(dnsdata->dnsq.class));
  data += sizeof(dnsdata->dnsq.class);
  offset += sizeof(dnsdata->dnsq.class);
  lest -= sizeof(dnsdata->dnsq.class);
  //   printf("--- read query section end --- lest: %d\n", lest);

  // # read resource record section
  while (lest > 0) {
    //     printf("--- read rr loop start --- lest: %d\n", lest);

    // read response name
    name_size = ParseName(dnsdata->dnsrr[rr_cnt].name, start, offset);
    data += name_size;
    offset += name_size;
    lest -= name_size;
    //     printf("debug:dnsdata->dnsrr[rr_cnt].name: %s\n",
    //     dnsdata->dnsrr[rr_cnt].name);

    // read response type
    memcpy(&dnsdata->dnsrr[rr_cnt].type, data,
           sizeof(dnsdata->dnsrr[rr_cnt].type));
    //     printf("ptr: %p, debug:dnsdata->dnsrr[rr_cnt].type: %04x\n", data,
    //     ntohs(dnsdata->dnsrr[rr_cnt].type));
    data += sizeof(dnsdata->dnsrr[rr_cnt].type);
    offset += sizeof(dnsdata->dnsrr[rr_cnt].type);
    lest -= sizeof(dnsdata->dnsrr[rr_cnt].type);

    // read response class
    memcpy(&dnsdata->dnsrr[rr_cnt].class, data,
           sizeof(dnsdata->dnsrr[rr_cnt].class));
    //     printf("ptr: %p, debug:dnsdata->dnsrr[rr_cnt].class: %04x\n", data,
    //     ntohs(dnsdata->dnsrr[rr_cnt].class));
    data += sizeof(dnsdata->dnsrr[rr_cnt].class);
    offset += sizeof(dnsdata->dnsrr[rr_cnt].class);
    lest -= sizeof(dnsdata->dnsrr[rr_cnt].class);

    // read response ttl
    memcpy(&dnsdata->dnsrr[rr_cnt].ttl, data,
           sizeof(dnsdata->dnsrr[rr_cnt].ttl));
    //     printf("ptr: %p, debug:dnsdata->dnsrr[rr_cnt].ttl: %08x\n", data,
    //     ntohs(dnsdata->dnsrr[rr_cnt].ttl));
    data += sizeof(dnsdata->dnsrr[rr_cnt].ttl);
    offset += sizeof(dnsdata->dnsrr[rr_cnt].ttl);
    lest -= sizeof(dnsdata->dnsrr[rr_cnt].ttl);

    // read response rdlength
    memcpy(&dnsdata->dnsrr[rr_cnt].rdlen, data,
           sizeof(dnsdata->dnsrr[rr_cnt].rdlen));
    //     printf("ptr: %p, debug:dnsdata->dnsrr[rr_cnt].rdlen: %04x\n", data,
    //     ntohs(dnsdata->dnsrr[rr_cnt].rdlen));
    data += sizeof(dnsdata->dnsrr[rr_cnt].rdlen);
    offset += sizeof(dnsdata->dnsrr[rr_cnt].rdlen);
    lest -= sizeof(dnsdata->dnsrr[rr_cnt].rdlen);

    // read response rdata
    // あとは、タイプによってRDATAの読み方を変えるだけ！
    if (htons(dnsdata->dnsrr[rr_cnt].type) == DNS_RRT_CNAME) {
      ParseName(dnsdata->dnsrr[rr_cnt].rdata, start, offset);
    } else {
      memcpy(&dnsdata->dnsrr[rr_cnt].rdata, data, dnsdata->dnsrr[rr_cnt].rdlen);
    }
    //     printf("ptr: %p, debug:dnsdata->dnsrr[rr_cnt].rdata: %s\n", data,
    //     dnsdata->dnsrr[rr_cnt].rdata);
    data += ntohs(dnsdata->dnsrr[rr_cnt].rdlen);
    offset += ntohs(dnsdata->dnsrr[rr_cnt].rdlen);
    lest -= ntohs(dnsdata->dnsrr[rr_cnt].rdlen);

    rr_cnt++;
    //     printf("--- read rr loop end --- lest: %d\n", lest);
  }

  return 0;
}
