#include <arpa/inet.h>  //usr/include htons()
#include <linux/if.h>   //ifreq
#include <stdio.h>      //usr/include printf()
#include <string.h>     //usr/include memset()
#include <sys/ioctl.h>  //usr/include/x86_64-linux-gnu //ioctl
#include <sys/socket.h> //usr/include/x86_64-linux-gnu socket()
#include <unistd.h>     //usr/include close()
// #include <net/ethernet.h> //usr/include
// #include <netinet/ip.h> //usr/include
#include "analyze.h"
#include <netinet/if_ether.h> //usr/include <linux/if_ether.h> ETH_P_IP, ETH_P_ALL
#include <netpacket/packet.h> //usr/include sockaddr_ll

int InitRawSocket(char *Device, int IPOnlyFlag, int PromiscFlag) { /*{{{*/
  printf("# InitRawSocket\n");
  struct ifreq ifreq;
  struct sockaddr_ll sa_ll;
  int soc;

  if (IPOnlyFlag) {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
      perror("socket");
      return (-1);
    }
  } else {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
      perror("socket");
      return (-1);
    }
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, Device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return (-1);
  }
  printf("  ifindex: %d\n", ifreq.ifr_ifindex);

  sa_ll.sll_family = PF_PACKET;
  if (IPOnlyFlag) {
    sa_ll.sll_protocol = htons(ETH_P_IP);
  } else {
    sa_ll.sll_protocol = htons(ETH_P_ALL);
  }
  sa_ll.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(soc, (struct sockaddr *)&sa_ll, sizeof(sa_ll)) < 0) {
    perror("bind");
    close(soc);
    return (-1);
  }

  if (PromiscFlag) {
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl SIOCGIFFLAGS");
      close(soc);
      return (-1);
    }
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
      perror("ioctl SIOCSIFFLAGS");
      close(soc);
      return (-1);
    }
  }

  return (soc);
} /*}}}*/

int main(int argc, char *argv[]) { /*{{{*/
  typedef struct {
    char *Device;
    int IPOnlyFlag;
    int PromiscFlag;
  } PARAM;
  PARAM Param = {"enp1s0", 1, 0};

  char buf[65535];
  int soc, size, rcvcnt;

  rcvcnt = 0;

  if ((soc = InitRawSocket(Param.Device, Param.IPOnlyFlag, Param.PromiscFlag)) <
      0) {
    fprintf(stderr, "InitRawSocket:error:%s\n", Param.Device);
    return (-1);
  }
  printf("  socfd: %d\n", soc);

  while (1) {
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    } else {
      rcvcnt++;
      fprintf(stdout,
              "\n\e[32m"
              "## recieve flame (No.%05d, size: %05d) "
              "#########################"
              "\e[0m\n",
              rcvcnt, size);
      AnalyzePacket((u_char *)buf, size);
      fprintf(stdout, "\e[32m##################################################"
                      "################"
                      "\e[0m\n");
    }
  }

  close(soc);
  return (0);
} /*}}}*/
