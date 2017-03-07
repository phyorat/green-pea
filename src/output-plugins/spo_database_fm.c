
#include "spo_database_fm.h"
#include "../sf_protocols.h"



int dbProcessGetTimeStamp(DatabaseData *data, Unified2EventCommon *event, Packet *p, char *timestampHolder)
{
	/*
	 CHECKME: -elz We need to get this logic sorted out since event shouldn't be null
	 theorically and event time should be priorized
	 */
	/* Generate a default-formatted timestamp now */

	memset(timestampHolder, '\0', SMALLBUFFER);

	if (event != NULL) {
		if ((GetTimestampByComponent_STATIC(
				ntohl(event->event_second),
				ntohl(event->event_microsecond),
				data->tz, timestampHolder))) {
			return 1;
		}
	} else if (p != NULL) {
		if ((GetTimestampByStruct_STATIC((struct timeval *) &p->pkth->ts,
				data->tz, timestampHolder))) {
			return 1;
		}
	} else {
		if (GetCurrentTimestamp_STATIC(timestampHolder)) {
			return 1;
		}
	}

	switch (data->dbtype_id) {
	case DB_MSSQL:
	case DB_MYSQL:
	case DB_ORACLE:
	case DB_ODBC:
		if (strlen(timestampHolder) > 20) {
			timestampHolder[19] = '\0';
		}
		break;

	case DB_POSTGRESQL:
	default:
		if (strlen(timestampHolder) > 24) {
			timestampHolder[23] = '\0';
		}
		break;
	}

	return 0;
}

static int dbProcessEncodePayload(DatabaseData *data, Packet *p, uint8_t q_ins)
{
	if (data->encoding == ENCODING_BASE64) {
		if (base64_STATIC(p->data, p->dsize,
				data->PacketDataNotEscaped[q_ins])) {
			return 1;
		}
	} else if (data->encoding == ENCODING_ASCII) {
		if (ascii_STATIC(p->data, p->dsize,
				data->PacketDataNotEscaped[q_ins])) {
			return 1;
		}
	} else {
		if ((fasthex_STATIC(p->data, p->dsize,
				data->PacketDataNotEscaped[q_ins]))) {
			return 1;
		}
	}

	if (snort_escape_string_STATIC( data->PacketDataNotEscaped[q_ins], data->sanitize_buffer[q_ins],
			strlen(data->PacketDataNotEscaped[q_ins]) + 1, data)) {
		return 1;
	}

	return 0;
}

static int dbProcessEncodeRaw(DatabaseData *data, void *raw, uint32_t rawlen, uint8_t q_ins)
{
    if (data->encoding == ENCODING_BASE64) {
        if (base64_STATIC(raw, rawlen,
                data->PacketDataNotEscaped[q_ins])) {
            return 1;
        }
    } else if (data->encoding == ENCODING_ASCII) {
        if (ascii_STATIC(raw, rawlen,
                data->PacketDataNotEscaped[q_ins])) {
            return 1;
        }
    } else {
        if ((fasthex_STATIC(raw, rawlen,
                data->PacketDataNotEscaped[q_ins]))) {
            return 1;
        }
    }

    if (snort_escape_string_STATIC( data->PacketDataNotEscaped[q_ins], data->sanitize_buffer[q_ins],
            strlen(data->PacketDataNotEscaped[q_ins]) + 1, data)) {
        return 1;
    }

    return 0;
}

static unsigned long dbProcessEscapeRaw(DatabaseData *data, void *raw, uint32_t rawlen, uint8_t q_ins)
{
    //return mysql_real_escape_string(data->m_dbins[SPO_DB_DEF_INS].m_sock, data->sanitize_buffer, raw, rawlen);
    return mysql_escape_string(data->sanitize_buffer[q_ins], raw, rawlen);
}

uint8_t dbEventInfoFm_tsp(char *buf, int slen)
{
	if (SnortSnprintf(buf, slen,
			"INSERT INTO "
			"event (sid,bid,cid,signature,timestamp) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
		LogMessage("%s: Failed\n", __func__);
		return 0;
	}

	return 1;
}

uint8_t dbEventInfoFm_tspdata(DatabaseData *data, char *buf, int slen,
		int sid, uint8_t rid, us_cid_t cid, SQLEvent *ele, char sl_separator)
{
	char timestampHolder[SMALLBUFFER];

	dbProcessGetTimeStamp(data, ele->event, ele->p, timestampHolder);

	switch (data->dbtype_id) {
	case DB_ORACLE:
		if ((data->DBschema_version >= 105)) {
			if ((SnortSnprintf(buf, slen,
					"%c(%u, %u, %lu, %u, TO_DATE('%s', 'YYYY-MM-DD HH24:MI:SS'))",
					sl_separator, sid, rid, cid, ele->i_sig_id, timestampHolder))
					!= SNORT_SNPRINTF_SUCCESS ) {
				LogMessage("%s: Failed\n", __func__);
				return 0;
			}
		} else {
			if ((SnortSnprintf(buf, slen,
					"%c(%u, %u, %lu, %u, '%s')",
					sl_separator, sid, rid, cid, ele->i_sig_id, timestampHolder))
					!= SNORT_SNPRINTF_SUCCESS ) {
				LogMessage("%s: Failed\n", __func__);
				return 0;
			}
		}
		break;
	case DB_MSSQL:
	case DB_MYSQL:
	case DB_POSTGRESQL:
	case DB_ODBC:
	default:
		if ((SnortSnprintf(buf, slen,
				"%c(%u, %u, %lu, %u, '%s')",
				sl_separator, sid, rid, cid, ele->i_sig_id, timestampHolder))
				!= SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
		break;
	}

	return 1;
}

uint8_t dbEventInfoFm_icmp(char *buf, int slen, int detail)
{
	if ( detail ) {
		if (SnortSnprintf(buf, slen,
				"INSERT INTO "
				"icmphdr (sid, bid, cid, icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq) "
				"VALUES ") != SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if (SnortSnprintf(buf, slen,
				"INSERT INTO "
				"icmphdr (sid, bid, cid, icmp_type, icmp_code) VALUES ") != SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_icmpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail)
{
	if ( detail ) {
		if ( (SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%u,%u,%u,%u,%u)", sl_separator,
				sid, rid, cid, p->icmph->type, p->icmph->code,
				ntohs(p->icmph->csum), ntohs(p->icmph->s_icmp_id),
				ntohs(p->icmph->s_icmp_seq)))
				!= SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if ((SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%u,%u)", sl_separator,
				sid, rid, cid, p->icmph->type, p->icmph->code))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_tcp(char *buf, int slen, int detail)
{
	if ( detail ) {
		if (SnortSnprintf(buf, slen,
				"INSERT INTO "
				"tcphdr (sid, bid, cid, tcp_sport, tcp_dport, "
				"tcp_seq, tcp_ack, tcp_off, tcp_res, "
				"tcp_flags, tcp_win, tcp_csum, tcp_urp) VALUES " ) != SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if (SnortSnprintf(buf, slen,
				"INSERT INTO "
				"tcphdr (sid,bid,cid,tcp_sport,tcp_dport,tcp_flags) VALUES ") != SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_tcpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail)
{
	if ( detail ) {
		if ( SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u)", sl_separator,
				sid, rid, cid,
				ntohs(p->tcph->th_sport), ntohs(p->tcph->th_dport),
				(u_long) ntohl(p->tcph->th_seq), (u_long) ntohl(p->tcph->th_ack),
				TCP_OFFSET(p->tcph), TCP_X2(p->tcph), p->tcph->th_flags, ntohs(p->tcph->th_win),
				ntohs(p->tcph->th_sum), ntohs(p->tcph->th_urp))
				!= SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else{
		if ((SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%u,%u,%u)", sl_separator,
				sid, rid, cid,
				ntohs(p->tcph->th_sport), ntohs(p->tcph->th_dport), p->tcph->th_flags))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_udp(char *buf, int slen, int detail)
{
	if ( detail ) {
		if ( SnortSnprintf(buf, slen,
				"INSERT INTO "
				"udphdr (sid, bid, cid, udp_sport, udp_dport, udp_len, udp_csum)"
				" VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if ( SnortSnprintf(buf, slen,
				"INSERT INTO "
				"udphdr (sid, bid, cid, udp_sport, udp_dport) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_udpdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail)
{
	if ( detail ) {
		if ( SnortSnprintf(buf, slen,
				"%c(%u, %u, %lu, %u, %u, %u, %u)", sl_separator,
				sid, rid, cid,
				ntohs(p->udph->uh_sport), ntohs(p->udph->uh_dport),
				ntohs(p->udph->uh_len), ntohs(p->udph->uh_chk))
				!= SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if (SnortSnprintf(buf, slen,
				"%c(%u, %u, %lu, %u, %u)", sl_separator,
				sid, rid, cid, ntohs(p->udph->uh_sport), ntohs(p->udph->uh_dport))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_tcpopt(char *buf, int slen)
{
	if ( SnortSnprintf(buf, slen,
			"INSERT INTO "
			"opt (sid,bid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
			"VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
		LogMessage("%s: Failed\n", __func__);
		return 0;
	}

	return 1;
}

uint8_t dbEventInfoFm_tcpoptdata(DatabaseData *data,
        SQLQueryEle *squery,
        int slen,
        int sid,
        uint8_t rid,
        us_cid_t cid,
        Packet *p,
        char sl_separator,
        uint8_t q_ins)
{
	char sl_separ_end = sl_separator;
	uint8_t i;
	char sl_buf[256];

	for (i = 0; i < p->tcp_option_count; i++) {
		if (!(&p->tcp_options[i]) || (0 == p->tcp_options[i].len)) {
			continue;
		}

		if ((data->encoding == ENCODING_HEX)
				|| (data->encoding == ENCODING_ASCII)) {
			if (fasthex_STATIC(p->tcp_options[i].data,
					p->tcp_options[i].len, data->PacketData[q_ins])) {
				LogMessage("%s: fasthex_STATIC Failed\n", __func__);
				return 0;
			}
		} else {
			if (base64_STATIC(p->tcp_options[i].data,
					p->tcp_options[i].len, data->PacketData[q_ins])) {
				LogMessage("%s: base64_STATIC Failed\n", __func__);
				return 0;
			}
		}

/*		if ( (';'==sl_separator) && (i==(p->tcp_option_count-1)) )
			sl_separ_end = ';';*/

		if (data->dbtype_id == DB_ORACLE) {
			/* Oracle field BLOB type case. We append unescaped
			 * opt_data data after query, which later in Insert()
			 * will be cut off and uploaded with OCIBindByPos().
			*/
			if ( SnortSnprintf(sl_buf, sizeof(sl_buf),
					"%c(%u,%u,%lu,%u,%u,%u,%u,:1)|%s", sl_separ_end,	//??????????????????WTF
					sid, rid, cid, i, 6,
					p->tcp_options[i].code, p->tcp_options[i].len, data->PacketData[q_ins])
					!= SNORT_SNPRINTF_SUCCESS) {
				LogMessage("%s: SnortSnprintf Failed\n", __func__);
				return 0;
			}
		}
		else {
			if ((SnortSnprintf(sl_buf, sizeof(sl_buf),
					"%c(%u,%u,%lu,%u,%u,%u,%u,'%s')", sl_separ_end,
					sid, rid, cid, i, 6,
					p->tcp_options[i].code, p->tcp_options[i].len, data->PacketData[q_ins]))
					!= SNORT_SNPRINTF_SUCCESS) {
				LogMessage("%s: SnortSnprintf Failed\n", __func__);
				return 0;
			}
		}

		squery->valid = 1;
		sl_separ_end = ',';
		strncat(squery->string, sl_buf, slen);
	}

	return 1;
}

uint8_t dbEventInfoFm_ip(char *buf, int slen, int detail)
{
	if ( detail ) {
		if ( SnortSnprintf(buf, slen,
				"INSERT INTO "
				"iphdr (sid, bid, cid, ip_src, ip_dst, ip_ver, ip_hlen, "
				"ip_tos, ip_len, ip_id, ip_flags, ip_off,"
				"ip_ttl, ip_proto, ip_csum) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else{
		if ( SnortSnprintf(buf, slen,
				"INSERT INTO "
				"iphdr (sid, bid, cid, ip_src, ip_dst, ip_proto) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_ipdata(char *buf, int slen, int sid, uint8_t rid, us_cid_t cid, Packet *p, char sl_separator, int detail)
{
	if ( detail ) {
		if ( SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)",
				sl_separator, sid, rid, cid,
				(u_long) ntohl(p->iph->ip_src.s_addr), (u_long) ntohl(p->iph->ip_dst.s_addr),
				IP_VER(p->iph), IP_HLEN(p->iph), p->iph->ip_tos, ntohs(p->iph->ip_len),
				ntohs(p->iph->ip_id), p->frag_flag, ntohs(p->frag_offset), p->iph->ip_ttl,
				p->iph->ip_proto, ntohs(p->iph->ip_csum))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}
	else {
		if ( SnortSnprintf(buf, slen,
				"%c(%u,%u,%lu,%lu,%lu,%u)",
				sl_separator, sid, rid, cid,
				(u_long) ntohl(p->iph->ip_src.s_addr), (u_long) ntohl(p->iph->ip_dst.s_addr),
				GET_IPH_PROTO(p))
				!= SNORT_SNPRINTF_SUCCESS ) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
	}

	return 1;
}

uint8_t dbEventInfoFm_ipopt(char *buf, int slen)
{
	if ( SnortSnprintf(buf, slen,
			"INSERT INTO "
			"opt (sid,bid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
			"VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
		LogMessage("%s: Failed\n", __func__);
		return 0;
	}

	return 1;
}

uint8_t dbEventInfoFm_ipoptdata(DatabaseData *data,
        SQLQueryEle *squery,
        int slen,
        int sid,
        uint8_t rid,
        us_cid_t cid,
        Packet *p,
        char sl_separator,
        uint8_t q_ins)
{
	char sl_separ_end = sl_separator;
	uint8_t i;
	char sl_buf[256];

	for (i = 0; i < p->ip_option_count; i++) {
		if ( !(&p->ip_options[i]) || (0==p->ip_options[i].len)) {
			LogMessage("%s: skip this option\n", __func__);
			continue;
		}

		if ((data->encoding == ENCODING_HEX)
				|| (data->encoding == ENCODING_ASCII)) {
			if (fasthex_STATIC(p->ip_options[i].data,
					p->ip_options[i].len, data->PacketData[q_ins])) {
				LogMessage("%s: fasthex_STATIC Failed\n", __func__);
				return 0;
			}
		} else {
			if (base64_STATIC(p->ip_options[i].data,
					p->ip_options[i].len, data->PacketData[q_ins])) {
				LogMessage("%s: base64_STATIC Failed\n", __func__);
				return 0;
			}
		}

		if (data->dbtype_id == DB_ORACLE) {
			/* Oracle field BLOB type case. We append unescaped
			 * opt_data data after query, which later in Insert()
			 * will be cut off and uploaded with OCIBindByPos().
			*/

			if ((SnortSnprintf(sl_buf, sizeof(sl_buf),
					"(%u,%u,%lu,%u,%u,%u,%u,:1)%c|%s",	//??????????????????WTF
					sid, rid, cid, i, 0,
					p->ip_options[i].code, p->ip_options[i].len, sl_separ_end, data->PacketData[q_ins]))
					!= SNORT_SNPRINTF_SUCCESS) {
				LogMessage("%s: SnortSnprintf Failed\n", __func__);
				return 0;
			}
		}
		else {
			if ((SnortSnprintf(sl_buf, sizeof(sl_buf),
					"%c(%u,%u,%lu,%u,%u,%u,%u,'%s')",
					sl_separ_end, sid, rid, cid, i, 0,
					p->ip_options[i].code, p->ip_options[i].len, data->PacketData[q_ins]))
					!= SNORT_SNPRINTF_SUCCESS) {
				LogMessage("%s: SnortSnprintf Failed\n", __func__);
				return 0;
			}
		}

		sl_separ_end = ',';
		squery->valid = 1;
		strncat(squery->string, sl_buf, slen);
	}

	return 1;
}

uint8_t dbEventInfoFm_payload(char *buf, int slen)
{
	if ( SnortSnprintf(buf, slen,
			"INSERT INTO "
			"packet (sid,bid,cid,type,pkt) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
		LogMessage("%s: Failed\n", __func__);
		return 0;
	}

	return 1;
}

uint8_t dbEventInfoFm_payloaddata(DatabaseData *data,
        char *sbuf,
        int slen,
        int sid,
        uint8_t rid,
        us_cid_t cid,
        Packet *p,
        char sl_separator,
        uint8_t q_ins)
{
	dbProcessEncodePayload(data, p, q_ins);
	dbProcessEncodeRaw(data, p, 1, q_ins);

	switch (data->dbtype_id) {
	case DB_ORACLE:
		/* Oracle field BLOB type case. We append unescaped
		 * packet_payload data after query, which later in Insert()
		 * will be cut off and uploaded with OCIBindByPos().
		*/
		if ((SnortSnprintf(sbuf, slen,
				"(%u,%u,%lu,%u:1)%c|%s",
				//sid, cid, sl_separator, data->PacketDataNotEscaped))
				sid, rid, cid, 1, sl_separator, data->PacketDataNotEscaped[q_ins]))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
		break;
	default:
		if ((SnortSnprintf(sbuf, slen,
				"(%u,%u,%lu,%u,'%s')%c",
				//sid, cid, data->sanitize_buffer, sl_separator))
		        sid, rid, cid, 1, data->sanitize_buffer[q_ins], sl_separator))
				!= SNORT_SNPRINTF_SUCCESS) {
			LogMessage("%s: Failed\n", __func__);
			return 0;
		}
		break;
	}

	return 1;
}

uint8_t dbEventInfoFm_raw(char *buf, int slen)
{
    if ( SnortSnprintf(buf, slen,
            "INSERT INTO "
            "packet (sid,bid,cid,pro,port,pkt) VALUES ") != SNORT_SNPRINTF_SUCCESS ) {
        LogMessage("%s: Failed\n", __func__);
        return 0;
    }

    return 1;
}

uint8_t dbEventInfoFm_rawdata(DatabaseData *data,
        char *sbuf, int slen,
        int sid, uint8_t rid, us_cid_t cid,
        SQLPkt *adp, char sl_separator,
        uint8_t q_ins)
{
    int len;
    char in_buf[8];
    PROTO_ID proto = PROTO_ETH; //default

    //dbProcessEncodeRaw(data, adp->u2raw_data, adp->u2raw_datalen);
    adp->u2raw_esc_len = dbProcessEscapeRaw(data, adp->u2raw_data, adp->u2raw_datalen, q_ins);

    if (adp->p->next_layer > 0) {
        proto = adp->p->layers[adp->p->next_layer-1].proto;
    }

    switch (data->dbtype_id) {
    case DB_ORACLE:
        /* Oracle field BLOB type case. We append unescaped
         * packet_payload data after query, which later in Insert()
         * will be cut off and uploaded with OCIBindByPos().
        */
        if ((SnortSnprintf(sbuf, slen,
                "(%u,%u,%lu,%u,%u:1)%c|%s",
                //sid, cid, sl_separator, data->PacketDataNotEscaped))
                sid, rid, cid, proto, adp->p->dp, sl_separator, data->PacketDataNotEscaped[q_ins]))
                != SNORT_SNPRINTF_SUCCESS) {
            LogMessage("%s: Failed\n", __func__);
            return 0;
        }
        break;
    default:
        if ((SnortSnprintf(sbuf, slen,
                "(%u,%u,%lu,%u,%u,'",
                //sid, cid, data->sanitize_buffer, sl_separator))
                sid, rid, cid, proto, adp->p->dp))
                != SNORT_SNPRINTF_SUCCESS) {
            LogMessage("%s: Failed\n", __func__);
            return 0;
        }

        len = strlen(sbuf);
        memcpy(sbuf+len, data->sanitize_buffer[q_ins], adp->u2raw_esc_len);
        len += adp->u2raw_esc_len;

        if ((SnortSnprintf(in_buf, sizeof(in_buf),
                "')%c",
                //sid, cid, data->sanitize_buffer, sl_separator))
                sl_separator))
                != SNORT_SNPRINTF_SUCCESS) {
            LogMessage("%s: Failed\n", __func__);
            return 0;
        }

        memcpy(sbuf+len, in_buf, 3);

        len += 3;
        adp->u2raw_esc_len = len;

        break;
    }

    return 1;
}



