#ifndef __SPO_MPOOL_RING__
#define __SPO_MPOOL_RING__

#include <stddef.h>

#include "decode.h"

#define KEYWORD_MR_DPDK        "mr-dpdk"


typedef enum mr_types_en {
    MR_ENUM_MIN_VAL = 0,
    MR_DPDK_MMAP,
    MR_ENUM_MAX_VAL = MR_DPDK_MMAP + 1
} mrtype_t;

typedef struct __MREvent {
    uint8_t rid;
    us_cid_t event_id;
    uint32_t event_type;
    void *event;
    Packet *p;
    u_int32_t i_sig_id;
} MREvent;

typedef struct __MRAdPkt {
    uint8_t rid;
    us_cid_t event_id;
    uint32_t u2raw_datalen;
    unsigned long u2raw_esc_len;
    void *u2raw_data;
    Packet *p;
}MRPkt;


void spo_mr_init(char *args);
void spo_mr_setup(void);
void spo_mpool_ring(Packet *p, void *event, uint32_t event_type, void *arg);
void spo_mr_clean_exit(int signal, void *arg);

#endif    /* __SPO_MPOOL_RING__ */
