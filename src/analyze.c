#include <stdio.h>
#include <sys/types.h> //usr/incldue/x86_64-linux-gnu u_char
// #include <unistd.h>
#include <net/ethernet.h> //ether_header
#include <netinet/if_ether.h> //ether_arp
#include <netinet/ip_icmp.h> //icmp
#include <netinet/ip.h>
#include "print.h"

int AnalyzeArp(u_char* data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_arp *arp;

    ptr=data;
    lest=size;

    //受け取ったデータのサイズが、arpの構造体のサイズ以上であることを確認
    if(lest<sizeof(struct ether_arp)) {
        fprintf(stderr, "lest(%d)<sizeof(struct ether_arp)(%ld)\n", lest, sizeof(struct ether_arp));
        return(-1);
    }

    //ポインタをセット
    arp=(struct ether_arp*)ptr;

    //arpパケットの構造体のぶんだけポインタを進める
    ptr+=sizeof(struct ether_arp);
    //arpパケットの構造体のぶんだけサイズを小さくする
    lest-=sizeof(struct ether_arp);

    //arpパケット表示
    PrintArp(arp, stdout);

    return(0);
}

int AnalyzeIcmp(u_char* data, int size)
{
    u_char* ptr;
    int lest;
    struct icmp* icmp;

    ptr=data;
    lest=size;

    if(lest<sizeof(struct icmp)) {
        fprintf(stderr, "AnalyzeIcmp:error:lest(%d)<sizeof(struct icmp)(%ld)\n", lest, sizeof(struct icmp));
        return(-1);
    }

    icmp=(struct icmp*)ptr;

    ptr+=sizeof(struct icmp);
    lest-=sizeof(struct icmp);

    PrintIcmp(icmp, stdout);

    return(0);
}

int AnalyzeIp(u_char* data, int size)
{
    u_char* ptr;
    int lest;
    struct iphdr* iphdr;
    u_char* opt;
    int opt_len;

    ptr=data;
    lest=size;

    if(lest<sizeof(struct iphdr)) {
        fprintf(stderr, "lest(%d)<sizeof(struct ip)(%ld)\n", lest, sizeof(struct iphdr));
        return(-1);
    }

    iphdr=(struct iphdr*)ptr;
    ptr+=sizeof(struct iphdr*);
    lest-=sizeof(struct iphdr*);

    opt_len=iphdr->ihl*4-sizeof(struct iphdr);

    opt=ptr;
    ptr+=opt_len;
    lest-=opt_len;

    PrintIpHeader(iphdr, opt, stdout);

    return(0);
}

int AnalyzePacket(u_char* data, int size)
{
    u_char* ptr;
    int lest;
    struct ether_header* eth;

    ptr=data;
    lest=size;

    // ethernet header
    if(lest<sizeof(struct ether_header)) {
        fprintf(stderr, "lest(%d) < sizeof(struct ether_header)(%ld)\n", lest, sizeof(struct ether_header));
        return(-1);
    }
    eth=(struct ether_header*)ptr;
    ptr+=sizeof(struct ether_header);
    lest-=sizeof(struct ether_header);
    PrintEtherHeader(eth, stdout);

    //ethernet
    switch(ntohs(eth->ether_type)) {
        case ETH_P_IP:
            AnalyzeIp(ptr, lest);
            break;
        case ETH_P_IPV6:
            break;
        case ETH_P_ARP:
            break;
        default:
            fprintf(stdout, "(unknown)\n");
    }

    return(0);
}
// ############################################
// ###                 ARP                  ###
// ############################################
// ### /net/if_arp.h ###
// struct arphdr
  // {
    // unsigned short int ar_hrd;		/* Format of hardware address.  */
    // unsigned short int ar_pro;		/* Format of protocol address.  */
    // unsigned char ar_hln;		/* Length of hardware address.  */
    // unsigned char ar_pln;		/* Length of protocol address.  */
    // unsigned short int ar_op;		/* ARP opcode (command).  */
// #if 0
    // /* Ethernet looks like this : This bit is variable sized
       // however...  */
    // unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    // unsigned char __ar_sip[4];		/* Sender IP address.  */
    // unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    // unsigned char __ar_tip[4];		/* Target IP address.  */
// #endif

// ### /netinet/if_ether.h ###
// struct	ether_arp {
    // struct	arphdr ea_hdr;		/* fixed-size header */
    // uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
    // uint8_t arp_spa[4];		/* sender protocol address */
    // uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
    // uint8_t arp_tpa[4];		/* target protocol address */
// };
// #define	arp_hrd	ea_hdr.ar_hrd
// #define	arp_pro	ea_hdr.ar_pro
// #define	arp_hln	ea_hdr.ar_hln
// #define	arp_pln	ea_hdr.ar_pln
// #define	arp_op	ea_hdr.ar_op

// ############################################
// ###                ICMP                  ###
// ############################################
// ### /netinet/ip_icmp.h ###
// struct icmphdr
// {
  // uint8_t type;		/* message type */
  // uint8_t code;		/* type sub-code */
  // uint16_t checksum;
  // union
  // {
    // struct
    // {
      // uint16_t	id;
      // uint16_t	sequence;
    // } echo;			/* echo datagram */
    // uint32_t	gateway;	/* gateway address */
    // struct
    // {
      // uint16_t	__glibc_reserved;
      // uint16_t	mtu;
    // } frag;			/* path mtu discovery */
  // } un;
// };

// struct icmp
// {
  // uint8_t  icmp_type;	/* type of message, see below */
  // uint8_t  icmp_code;	/* type sub code */
  // uint16_t icmp_cksum;	/* ones complement checksum of struct */
  // union
  // {
    // unsigned char ih_pptr;	/* ICMP_PARAMPROB */
    // struct in_addr ih_gwaddr;	/* gateway address */
    // struct ih_idseq		/* echo datagram */
    // {
      // uint16_t icd_id;
      // uint16_t icd_seq;
    // } ih_idseq;
    // uint32_t ih_void;
// 
    // /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    // struct ih_pmtu
    // {
      // uint16_t ipm_void;
      // uint16_t ipm_nextmtu;
    // } ih_pmtu;
// 
    // struct ih_rtradv
    // {
      // uint8_t irt_num_addrs;
      // uint8_t irt_wpa;
      // uint16_t irt_lifetime;
    // } ih_rtradv;
  // } icmp_hun;
// #define	icmp_pptr	icmp_hun.ih_pptr
// #define	icmp_gwaddr	icmp_hun.ih_gwaddr
// #define	icmp_id		icmp_hun.ih_idseq.icd_id
// #define	icmp_seq	icmp_hun.ih_idseq.icd_seq
// #define	icmp_void	icmp_hun.ih_void
// #define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
// #define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
// #define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
// #define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
// #define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
  // union
  // {
    // struct
    // {
      // uint32_t its_otime;
      // uint32_t its_rtime;
      // uint32_t its_ttime;
    // } id_ts;
    // struct
    // {
      // struct ip idi_ip;
      // /* options and then 64 bits of data */
    // } id_ip;
    // struct icmp_ra_addr id_radv;
    // uint32_t   id_mask;
    // uint8_t    id_data[1];
  // } icmp_dun;
// #define	icmp_otime	icmp_dun.id_ts.its_otime
// #define	icmp_rtime	icmp_dun.id_ts.its_rtime
// #define	icmp_ttime	icmp_dun.id_ts.its_ttime
// #define	icmp_ip		icmp_dun.id_ip.idi_ip
// #define	icmp_radv	icmp_dun.id_radv
// #define	icmp_mask	icmp_dun.id_mask
// #define	icmp_data	icmp_dun.id_data
// };

// ############################################
// ###                 IP                   ###
// ############################################
// ### /netinet/ip.h ###
// struct iphdr
  // {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
    // unsigned int ihl:4;
    // unsigned int version:4;
// #elif __BYTE_ORDER == __BIG_ENDIAN
    // unsigned int version:4;
    // unsigned int ihl:4;
// #else
// # error	"Please fix <bits/endian.h>"
// #endif
    // uint8_t tos;
    // uint16_t tot_len;
    // uint16_t id;
    // uint16_t frag_off;
    // uint8_t ttl;
    // uint8_t protocol;
    // uint16_t check;
    // uint32_t saddr;
    // uint32_t daddr;
    // /*The options start here. */
  // };

// struct ip
  // {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
    // unsigned int ip_hl:4;		/* header length */
    // unsigned int ip_v:4;		/* version */
// #endif
// #if __BYTE_ORDER == __BIG_ENDIAN
    // unsigned int ip_v:4;		/* version */
    // unsigned int ip_hl:4;		/* header length */
// #endif
    // uint8_t ip_tos;			/* type of service */
    // unsigned short ip_len;		/* total length */
    // unsigned short ip_id;		/* identification */
    // unsigned short ip_off;		/* fragment offset field */
// #define	IP_RF 0x8000			/* reserved fragment flag */
// #define	IP_DF 0x4000			/* dont fragment flag */
// #define	IP_MF 0x2000			/* more fragments flag */
// #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    // uint8_t ip_ttl;			/* time to live */
    // uint8_t ip_p;			/* protocol */
    // unsigned short ip_sum;		/* checksum */
    // struct in_addr ip_src, ip_dst;	/* source and dest address */
  // };
