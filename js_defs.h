#ifndef _NJ_DEFS_H
#define _NJ_DEFS_H

#include <inttypes.h>

#define js_log(X, ...) fprintf(stderr, "%s [%d] - " X, __FILE__, __LINE__, ##__VA_ARGS__)

#define JS_PCAP_BUFF_SIZE 65535

typedef struct
{
  uint32_t m_uSrcIP;
  uint32_t m_uDstIP;
  uint8_t m_uZero;
  uint8_t m_uProto;
  uint16_t m_uLen;
} __attribute__((__packed__)) js_pseudo_hdr_t;



#endif
