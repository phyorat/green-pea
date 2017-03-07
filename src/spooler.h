/* 
**
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
**
*/

#ifndef __SPOOLER_H__
#define __SPOOLER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "plugbase.h"


//Definition of bit length for event id
#define USI_CID_UINT_64//USI_CID_UINT_32

#ifdef USI_CID_UINT_32
typedef uint32_t					us_cid_t;
#else
typedef uint64_t					us_cid_t;
//#define us_cid_t					uint64_t
#endif

#define SPOOLER_EXTENSION_FOUND     0
#define SPOOLER_EXTENSION_NONE      1
#define SPOOLER_EXTENSION_EPARAM    2
#define SPOOLER_EXTENSION_EOPEN     3

typedef enum
{
	SPOOLER_OPENED,
	SPOOLER_RECORD_SKIP,
	SPOOLER_RECORD_SKIP_DONE,
	SPOOLER_RECORD_READY,
	SPOOLER_HEADER_READ,
	SPOOLER_RECORD_READ,
}spool_state;

#define WALDO_STATE_ENABLED         0x01
#define WALDO_STATE_OPEN            0x02
#define WALDO_STATE_DIRTY           0x04

#define WALDO_MODE_NULL             0
#define WALDO_MODE_READ             1
#define WALDO_MODE_WRITE            2

#define WALDO_FILE_SUCCESS          0
#define WALDO_FILE_EEXIST           1
#define WALDO_FILE_EOPEN            2
#define WALDO_FILE_ETRUNC           3
#define WALDO_FILE_ECORRUPT         4
#define WALDO_STRUCT_EMPTY          10
#define WALDO_FILE_SKIP             20


#define MAX_FILEPATH_BUF    1024

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

//#####USI Set up######################
#ifndef ENABLE_MYSQL
  #define ENABLE_MYSQL
#endif

#define SPOOLER_FILE_STREAM
#define SPOOLER_FIXED_BUF
#define SPOOLER_RECORD_RING
#define SPOOLER_RBUF_SIZE	    65536
#define SPOOLER_RING_SIZE       (0x2000)
#define SPOOLER_RING_BITMASK    (SPOOLER_RING_SIZE-1)
#define SPOOLER_DUAL_THREAD

#define SPOOLER_RING_PLUSONE(num)		(((num)+1) & SPOOLER_RING_BITMASK)

#define SPOOLER_RING_INC(para)		do{ \
										pthread_mutex_lock(&para->lock_ring);	\
										(para->sring->event_prod) = ((para->sring->event_prod)+1) & SPOOLER_RING_BITMASK;	\
										para->sring->event_cnt++;	\
										pthread_mutex_unlock(&para->lock_ring);	\
										}while(0);

#define SPOOLER_RING_DEC(para)		do{ \
										pthread_mutex_lock(&para->lock_ring);	\
										(para->sring->event_top) = ((para->sring->event_top)+1) & SPOOLER_RING_BITMASK;	\
										para->sring->event_cnt--;	\
										pthread_mutex_unlock(&para->lock_ring);	\
										}while(0);

#define SPOOLER_RING_EVENT_DEC(para)		do{ \
												pthread_mutex_lock(&para->lock_ring);	\
												(para->sring->event_top) = ((para->sring->event_top)+2) & SPOOLER_RING_BITMASK;	\
												para->sring->event_cnt -= 2;	\
												pthread_mutex_unlock(&para->lock_ring);	\
											}while(0);

#define SPOOLER_RING_COMS_N_DEC(para, num)	do{ \
												pthread_mutex_lock(&para->lock_ring);	\
												(para->sring->event_coms) = ((para->sring->event_coms)+num) & SPOOLER_RING_BITMASK;	\
												pthread_mutex_unlock(&para->lock_ring);	\
											}while(0);

#define SPOOLER_RING_FLUSHOUT(para)         do{ \
		                                        pthread_mutex_lock(&para->lock_ring);   \
		                                        memset(para->sring, 0, sizeof(spooler_ring));  \
                                                pthread_mutex_unlock(&para->lock_ring); \
                                            }while(0);

#define SPOOLER_WALDO_SET_REC(waldo, ts, idx)      do { \
		                                                pthread_mutex_lock(&waldo->lock_waldo);   \
		                                                waldo->data.record_idx = idx;   \
		                                                waldo->data.timestamp = ts; \
		                                                waldo->updated = 1;	\
		                                                pthread_mutex_unlock(&waldo->lock_waldo); \
                                                    }while(0);

#define SPOOLER_WALDO_GET_REC(waldo, ts, idx)      do { \
                                                        pthread_mutex_lock(&waldo->lock_waldo);   \
                                                        idx = waldo->data.record_idx;   \
                                                        ts = waldo->data.timestamp; \
                                                        waldo->updated = 0;	\
                                                        pthread_mutex_unlock(&waldo->lock_waldo); \
                                                    }while(0);

#define SPOOLER_RING_FULL(ring)			( SPOOLER_RING_SIZE <= (ring)->event_cnt )
#define SPOOLER_RING_EMPTY(ring)		( 0 == (ring)->event_cnt )
#define SPOOLER_RING_PROCEED(ring)		( (((ring)->event_prod+1)&SPOOLER_RING_BITMASK) != (ring)->event_coms )


//#####USI Set up end##################

#ifndef SPOOLER_FIXED_BUF
typedef struct _Record
{
    /* raw data */
    void                *header;
    void                *data;

    Packet              *pkt;       /* decoded packet */
} Record;
#else
typedef struct _Record
{
    /* raw data */
	uint32_t			data_pos;
	uint32_t			data_end;
    uint8_t             data[SPOOLER_RBUF_SIZE];

    Packet              pkt[1];       /* decoded packet */
} Record;
#endif

typedef struct _EventRecordNode
{
    uint32_t                type;   /* type of event stored */
#ifndef SPOOLER_RECORD_RING
    void                    *data;  /* unified2 event (eg IPv4, IPV6, MPLS, etc) */
    uint8_t                 used;   /* has the event be retrieved */
    uint32_t                time_used; /* time it has fired */
#else
    uint32_t                record_idx; // current record number
    time_t                  timestamp;
    uint8_t                 header[8];
    uint8_t                 data[2048];
    Packet                  s_pkt[1];
#endif
    us_cid_t                event_id;  /* extracted from event original */
    uint32_t                event_second; /* extracted from event originale */
#ifndef SPOOLER_RECORD_RING
    struct _EventRecordNode *next;  /* reference to next event record */
#endif
} EventRecordNode;

typedef struct __EventEP
{
    uint8_t rid;
    EventRecordNode *ee;
    EventRecordNode *ep;
}EventEP;

typedef struct __EventGMCid
{
    uint8_t rid;
    us_cid_t cid;
    us_cid_t ms_cid;
}EventGMCid;

typedef enum
{
	RING_ON,
	RING_OFF,
	RING_PRE_ON,
}ring_swatch;

typedef struct __spooler_ring
{
    EventRecordNode         event_cache[SPOOLER_RING_SIZE];
    uint16_t                event_prod;
    uint16_t                event_top;
    uint16_t                event_coms;
    uint16_t                event_cnt;
    uint16_t                r_flag;
    uint32_t                i_sleep_cnt;
    uint32_t                o_sleep_cnt;
    us_cid_t                base_eventid;
    us_cid_t                prev_eventid;
    us_cid_t                rollon_cid;
    ring_swatch             r_switch;
}spooler_ring;

typedef struct _WaldoData
{
    char                    spool_dir[MAX_FILEPATH_BUF];
    char                    spool_filebase[MAX_FILEPATH_BUF];
    size_t                  spool_filebase_len;
    uint32_t                timestamp;
    uint32_t                record_idx;
} WaldoData;

typedef struct _Waldo
{
    int                     fd;                         // file descriptor of the waldo
    char                    filepath[MAX_FILEPATH_BUF]; // filepath to the waldo
    uint8_t                 mode;                       // read/write
    uint8_t                 state;
    uint8_t                 updated;
    pthread_mutex_t         lock_waldo;
    WaldoData               data;
} Waldo;

#define UNIFIED2_MAX_LOG_FILENAME       64
#define IN_MODIFY    0x00000002 /* File was modified.  */
#define IN_CREATE    0x00000100 /* Subfile was created.  */
#define IN_TOSEEK    0x10000000 /* Queue is full but still files.  */
#define U2_LOGSTATE_SET_MODIFY(watch)       ((watch.mask) |=  IN_MODIFY)
#define U2_LOGSTATE_ISSET_MODIFY(watch)     ((watch.mask) &   IN_MODIFY)
#define U2_LOGSTATE_UNSET_MODIFY(watch)     ((watch.mask) &= ~IN_MODIFY)
#define U2_LOGSTATE_SET_CREATE(watch)       ((watch.mask) |=  IN_CREATE)
#define U2_LOGSTATE_ISSET_CREATE(watch)     ((watch.mask) &   IN_CREATE)
#define U2_LOGSTATE_UNSET_CREATE(watch)     ((watch.mask) &= ~IN_CREATE)
#define U2_LOGSTATE_SET_TOSEEK(watch)       ((watch.mask) |=  IN_TOSEEK)
#define U2_LOGSTATE_ISSET_TOSEEK(watch)     ((watch.mask) &   IN_TOSEEK)
#define U2_LOGSTATE_UNSET_TOSEEK(watch)     ((watch.mask) &= ~IN_TOSEEK)

#define SPOOLER_WATCH_NS_MAX                (1<<7)//(1<<10)
#define SPOOLER_WATCH_NS_MASK               (SPOOLER_WATCH_NS_MAX-1)//0x3FF  //Corresponding to MAX

#define SPOOLER_WATCH_NS_FULL(watch)        ( SPOOLER_WATCH_NS_MAX <= (watch.ns_cnt) )
#define SPOOLER_WATCH_NS_EMPTY(watch)       ( 0 == (watch.ns_cnt) )
#define SPOOLER_WATCH_NS_T(watch)           (watch.newstamp[watch.ns_top])
#define SPOOLER_WATCH_NS_C(watch)           (watch.newstamp[watch.ns_cons])
#define SPOOLER_WATCH_NS_P(watch)           (watch.newstamp[watch.ns_prod])

#define SPOOLER_WATCH_NS_PROD(watch)        do{ \
                                                pthread_mutex_lock(&watch.t_lock);   \
                                                (watch.ns_top) = (watch.ns_prod);   \
                                                (watch.ns_prod) = ((watch.ns_prod)+1) & SPOOLER_WATCH_NS_MASK;   \
                                                if (0 == watch.ns_cnt)  \
                                                    U2_LOGSTATE_SET_CREATE(watch);  \
                                                watch.ns_cnt++;   \
                                                pthread_mutex_unlock(&watch.t_lock); \
                                            }while(0);

#define SPOOLER_WATCH_NS_CONS(watch)        do{ \
                                                pthread_mutex_lock(&watch.t_lock);   \
                                                (watch.ns_cons) = ((watch.ns_cons)+1) & SPOOLER_WATCH_NS_MASK;   \
                                                watch.ns_cnt--;   \
                                                if (0 == watch.ns_cnt)  \
                                                    U2_LOGSTATE_UNSET_CREATE(watch);  \
                                                pthread_mutex_unlock(&watch.t_lock); \
                                            }while(0);

#define SPOOLER_WATCH_NS_CLEAR(watch)       do{ \
                                                pthread_mutex_lock(&watch.t_lock);   \
                                                watch.ns_cnt = 0;   \
                                                watch.ns_cons = 0;  \
                                                watch.ns_prod = 0;  \
                                                watch.ns_top = 0;   \
                                                watch.mask = 0; \
                                                pthread_mutex_unlock(&watch.t_lock); \
                                            }while(0);


typedef struct __spooler_watch
{
    uint16_t                ns_prod;
    uint16_t                ns_cons;
    uint16_t                ns_top;
    uint16_t                ns_cnt;
    int                     fd;
    uint32_t                mask;
    uint32_t                newstamp[SPOOLER_WATCH_NS_MAX];
    pthread_mutex_t         t_lock;
    pthread_mutex_t         c_lock;
}spooler_watch;

typedef struct __spooler_r_para
{
    uint8_t                 rid;        //ring id
    uint8_t                 watch_start;
    uint32_t                watch_cts;   //watch current timestamp
    pthread_mutex_t         lock_ring;
    pthread_cond_t          watch_cond;
    spooler_ring            *sring;
    Waldo                   *waldo;
    pthread_t               *ptid_join;
    spooler_watch           swatch;
}spooler_r_para;

typedef struct _PacketRecordNode
{
    Packet                  *data;  /* packet information */
    struct _PacketRecordNode *next; /* reference to next event record */
} PacketRecordNode;

typedef struct _Spooler
{
    InputFuncNode           *ifn;       // Processing function of input file

#ifndef SPOOLER_FILE_STREAM
    int                     fd;         // file descriptor of input file
#else
    FILE                    *fp;		// file stream of input file
#endif
    char                    filepath[MAX_FILEPATH_BUF]; // file path of input file
    time_t                  timestamp;  // time stamp of input file
    uint32_t                state;      // current read state
    uint32_t                skip_offset;     // current file offest
    uint32_t                record_idx; // current record number

    uint32_t                magic;      


    Record                  record;     // data of current Record
#ifndef SPOOLER_RECORD_RING
    void                    *header;    // header of input file
    EventRecordNode         *event_cache; // linked list of cached events
    uint32_t                events_cached;
#else
    spooler_r_para          *spara;
#endif

    PacketRecordNode        *packet_cache; // linked list of concurrent packets
    uint32_t                packets_cached;
} Spooler;


int ProcessContinuous(Waldo *, spooler_r_para *);
int ProcessBatch(const char *, const char *);
int ProcessWaldoFile(const char *);
void spool_mult_init(void);
void* spoolerRecordRead_T(void * arg);
void* spoolerRecordOutput_T(void * arg);

Packet * spoolerRetrievePktData(Packet *, uint8_t *);

int spoolerReadWaldo(Waldo *);
void spoolerEventCacheFlush(Spooler *);
uint8_t RegisterSpooler(Spooler *, uint8_t);
uint8_t UnRegisterSpooler(Spooler *, uint8_t);

int spoolerCloseWaldo(Waldo *);
int spoolerClose(Spooler *);

#endif /* __SPOOLER_H__ */


