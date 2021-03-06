#ifndef __SPO_DATABASE_FM_H__
#define __SPO_DATABASE_FM_H__


#include <stdlib.h>

#include "util.h"
#include "spo_database.h"

uint8_t dbEventInfoFm_tsp(char *buf, int slen);
uint8_t dbEventInfoFm_tspdata(DatabaseData *data, char *buf, int slen,
		int sid, uint8_t rid, us_cid_t cid, SQLEvent *event, char sl_separator);
uint8_t dbEventInfoFm_icmp(char *buf, int slen, int detail);
uint8_t dbEventInfoFm_icmpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail);
uint8_t dbEventInfoFm_tcp(char *buf, int slen, int detail);
uint8_t dbEventInfoFm_tcpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail);
uint8_t dbEventInfoFm_udp(char *buf, int slen, int detail);
uint8_t dbEventInfoFm_udpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail);
uint8_t dbEventInfoFm_tcpopt(char *buf, int slen);
uint8_t dbEventInfoFm_tcpoptdata(DatabaseData*, SQLQueryEle*, int, int, uint8_t, us_cid_t, Packet*, char, uint8_t);
uint8_t dbEventInfoFm_ip(char *buf, int slen, int detail);
uint8_t dbEventInfoFm_ipdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail);
uint8_t dbEventInfoFm_ipopt(char *buf, int slen);
uint8_t dbEventInfoFm_ipoptdata(DatabaseData*, SQLQueryEle*, int, int, uint8_t, us_cid_t, Packet*, char, uint8_t);
uint8_t dbEventInfoFm_payload(char *buf, int slen);
uint8_t dbEventInfoFm_payloaddata(DatabaseData*, char*, int, int, uint8_t, us_cid_t, Packet*, char, uint8_t);
uint8_t dbEventInfoFm_raw(char *buf, int slen);
uint8_t dbEventInfoFm_rawdata(DatabaseData*, char*, int, int, uint8_t, us_cid_t, SQLPkt*, char, uint8_t);

#endif	/* __SPO_DATABASE_FM_H__ */
