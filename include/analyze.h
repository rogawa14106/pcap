#ifndef ANALYZE_H
#define ANALYZE_H
#include <sys/types.h>

int AnalyzePacket(u_char *data, int size);
int AnalyzeTCP(u_char *data, int size);
int AnalyzeUDP(u_char *data, int size);

#endif // analyze.h
