#include <string.h>
#include <sys/types.h>

u_int16_t checksum(u_char *data, int len) {
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

  // lenが奇数だった場合8bitぶん足しそこねてしまうので、そのぶんを足してやる
  if (c == 1) {
    //     u_int16_t val;
    //     val = 0;
    //     memcpy(&val, ptr, sizeof(u_int8_t));
    //     sum += val;
    sum += (*ptr >> 8);
  }

  // 32bitごとの補数和を16bitごとの補数和に変換。2回やるのは、桁上がりするから。
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // 1の補数を取る。つまり、ビットを反転する。
  return (~sum);
}
