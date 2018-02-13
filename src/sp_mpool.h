#ifndef __SP_MPOOL_H__
#define __SP_MPOOL_H__

#include <stdint.h>


typedef enum __EventMdataType
{
    SP_EVENT_PKT,
    SP_PACKET,
} EventMdataType;

typedef struct __EventMBufPkt
{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t proto;
    uint16_t sp;
    uint16_t dp;
    uint32_t timestamp;
    uint32_t pkt_rawlen;
    void *pkt_raw;
} EventMBufPkt;

typedef struct __EventMbufIds
{
    uint32_t sig_id;
    uint32_t sig_gid;
    uint32_t sig_rev;
    uint32_t class_id;
    uint32_t sig_prio;
    uint32_t sig_ref_id;
} EventMbufIds;

typedef struct __EventMBuf
{
    uint16_t type;
    uint8_t sid;
    uint8_t bid;
    uint64_t cid;
    EventMbufIds evn_ids;
    EventMBufPkt evn_pkt;
    uint8_t data[2048];
//    Packet pkt;
//    Unified2IDSEvent event;
} EventMBuf;

#endif  /*__SP_MPOOL_H__*/

