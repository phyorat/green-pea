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


/*
** INCLUDES
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SOLARIS
    #include <strings.h>
#endif
#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/inotify.h>
#include <limits.h>
//#include <error.h>
#include <pthread.h>

#include "squirrel.h"
#include "debug.h"
#include "plugbase.h"
#include "spi_unified2.h"
#include "spooler.h"
#include "strlcpyu.h"
#include "util.h"
#include "unified2.h"

/*
** PROTOTYPES
*/
void Unified2Init(char *);

/* processing functions  */
int Unified2ReadRecordHeader(void *);
int Unified2ReadRecord(void *);

int Unified2ReadEventRecord(void *);
int Unified2ReadEvent6Record(void *);
int Unified2ReadPacketRecord(void *);

void Unified2PrintCommonRecord(Unified2EventCommon *);
void Unified2PrintEventRecord(Unified2IDSEvent_legacy *);
void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *);
void Unified2PrintPacketRecord(Unified2Packet *);

/* restart/shutdown functions */
void Unified2CleanExitFunc(int, void *);
void Unified2RestartFunc(int, void *);


void Unified2PrintEventRecord(Unified2IDSEvent_legacy *);
void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *);

void Unified2_Archive(Waldo* waldo, uint32_t timestamp)
{
    char filepath[MAX_FILEPATH_BUF];

    if ( 0 == timestamp )
        return;

    SnortSnprintf(filepath, sizeof(filepath), "%s/%s.%u",
            waldo->data.spool_dir,
            waldo->data.spool_filebase,
            timestamp);

    LogMessage("%s: %s\n", __func__, filepath);

    if( access( filepath, F_OK ) != -1 ) {
        remove(filepath);
    }
}

int Unified2DirAddWatch(char *filepath, int *fd)
{
    if ((*fd = inotify_init()) < 0) {
        LogMessage("failed to initialize inotify instance, errno %d\n", errno);
        return 1;
    }

    if ( inotify_add_watch(*fd, filepath, IN_MODIFY | IN_CREATE) < 0 ) {
        *fd = -1;
        LogMessage("failed to add inotify watch for '%s', errno %d\n", filepath, errno);
        return 1;
    }

    LogMessage("Watching %s, fd %d\n", filepath, *fd);

    return 0;
}

void* Unified2DirEvent(void * arg)
{
    uint32_t event_pos, event_len;
    char *filebase;
    char *endptr;
    size_t filebase_len;
    Waldo* waldo;
    uint32_t file_timestamp;
    char buf[sizeof(struct inotify_event) + PATH_MAX];
    spooler_r_para *sr_para = (spooler_r_para*) arg;
    uint32_t timestamp;
    //uint32_t *extension;

    if ( sr_para->swatch.fd < 0 ) {
        LogMessage("Invalid watching file descriptor!\n");
        return NULL;
    }

    waldo = sr_para->waldo;
    filebase = waldo->data.spool_filebase;
    filebase_len = waldo->data.spool_filebase_len;

    pthread_mutex_lock(&sr_para->swatch.c_lock);
    while (!sr_para->watch_start) {
          LogMessage("Watch thread %d blocked\n", sr_para->rid);
          pthread_cond_wait(&sr_para->watch_cond, &sr_para->swatch.c_lock);
    }
    pthread_mutex_unlock(&sr_para->swatch.c_lock);

    LogMessage("Watching thread, fd %d\n", sr_para->swatch.fd);

    while ((event_len = read(sr_para->swatch.fd, buf, sizeof(buf))) > 0) {
        event_pos = 0;
        timestamp = sr_para->watch_cts;
        while (event_pos < event_len) {
            struct inotify_event *ie = (struct inotify_event*) &buf[event_pos];
            DEBUG_U_WRAP(LogMessage("event occured, mask 0x%x, ", ie->mask));
            if ( (ie->mask&IN_MODIFY) && (ie->len>0) )      //Modify
            {
                if ( !strncmp(filebase, ie->name, filebase_len) ) {
                    file_timestamp = strtol(ie->name+filebase_len+1, &endptr, 10);
                    if ((errno != ERANGE) && ('\0' == *endptr) && (file_timestamp==timestamp)) {
                        DEBUG_U_WRAP(LogMessage("%s: %s was modified\n", __func__, ie->name));
                        U2_LOGSTATE_SET_MODIFY(sr_para->swatch);
                    }
                }
            }
            else if ( (ie->mask&IN_CREATE) && (ie->len>0) ) //Create
            {
                if ( U2_LOGSTATE_ISSET_TOSEEK(sr_para->swatch) ) {
                    LogMessage("%s: %s was created, but watch_queue will seek whole folder.\n",
                            __func__, ie->name);
                    event_pos += sizeof(struct inotify_event) + ie->len;
                    continue;
                }

                if ( SPOOLER_WATCH_NS_FULL(sr_para->swatch) ) {
                    LogMessage("%s: %s was created, but watch_queue is full, to seek.\n",
                            __func__, ie->name);
                    U2_LOGSTATE_SET_TOSEEK(sr_para->swatch);
                    event_pos += sizeof(struct inotify_event) + ie->len;
                    continue;
                }

                if ( !strncmp(filebase, ie->name, filebase_len) ){
                    file_timestamp = strtol(ie->name+filebase_len+1, &endptr, 10);
                    if ((errno != ERANGE) && ('\0' == *endptr)
                            && (file_timestamp > SPOOLER_WATCH_NS_T(sr_para->swatch))) {
                        LogMessage("%s: %s was created\n", __func__, ie->name);
                        Unified2_Archive(waldo, SPOOLER_WATCH_NS_P(sr_para->swatch));
                        SPOOLER_WATCH_NS_P(sr_para->swatch) = file_timestamp;
                        SPOOLER_WATCH_NS_PROD(sr_para->swatch);
                    }
                }
            }
            else if (ie->mask & IN_DELETE)
            {
                LogMessage("%s: %s was deleted\n", __func__, ie->name);
            }
            else
            {
                DEBUG_U_WRAP(LogMessage("unexpected event, mask 0x%x\n", ie->mask ));
            }

            event_pos += sizeof(struct inotify_event) + ie->len;
        }
    }

    return NULL;
}

/*
 * Function: UnifiedLogSetup()
 *
 * Purpose: Registers the input plugin keyword and initialization function
 *          into the input plugin list.  This is the function that gets called
 *          InitInputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void Unified2Setup(void)
{
    /* link the input keyword to the init function in the input list */
    RegisterInputPlugin("unified2", Unified2Init);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Input plugin: Unified2 is setup...\n"););
}

void Unified2Init(char *args)
{
    /* parse the argument list from the rules file */
    //data = ParseAlertTestArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking UnifiedLog functions to call lists...\n"););

    /* Link the input processor read/process functions to the function list */
    AddReadRecordHeaderFuncToInputList("unified2", Unified2ReadRecordHeader);
    AddReadRecordFuncToInputList("unified2", Unified2ReadRecord);

    /* Link the input processor exit/restart functions into the function list */
    AddFuncToCleanExitList(Unified2CleanExitFunc, NULL);
    AddFuncToRestartList(Unified2RestartFunc, NULL);
}

inline int Unified2ReadFile(Spooler *spooler)
{
	ssize_t bytes_read;

	spooler->record.data_pos = 0;
	spooler->record.data_end = 0;

/*
	if( fread(spooler->record.data, SPOOLER_RBUF_SIZE, 1, spooler->fp) ) {
		spooler->record.data_end = SPOOLER_RBUF_SIZE;
	}
	else {*/
		bytes_read = fread(spooler->record.data, 1, SPOOLER_RBUF_SIZE, spooler->fp);
		if ( 0 == bytes_read ) {
		    DEBUG_U_WRAP(LogMessage("%s: bytes_read from file is zero.\n", __func__));
			return BARNYARD2_READ_EOF;
		}
		spooler->record.data_end = bytes_read;

		DEBUG_U_WRAP(LogMessage("%s: d_pos %d, d_end %d, e_cur %d\n", __func__,
				spooler->record.data_pos, spooler->record.data_end, spooler->spara->sring->event_cur));
//	}

	DEBUG_U_WRAP(LogMessage("%s: bytes_read from file: %d\n", __func__, bytes_read));

	return BARNYARD2_SUCCESS;
}

inline int Unified2GetRecFromBuf(Spooler *spooler, uint8_t *buf, uint16_t r_len)
{
	uint32_t *data_pos = &(spooler->record.data_pos);
	uint32_t *data_end = &(spooler->record.data_end);

	DEBUG_U_WRAP(LogMessage("%s: d_pos %d, d_end %d, e_cur %d\n", __func__,
			spooler->record.data_pos, spooler->record.data_end, spooler->spara->sring->event_cur));

	if ( *data_pos >= *data_end ) {
		return 0;
	}

	if ( (*data_pos+r_len) <= *data_end ) {
		DEBUG_U_WRAP(LogMessage("%s: read sufficient data, len %d\n", __func__, r_len));
		memcpy(buf, &(spooler->record.data[*data_pos]), r_len);
		*data_pos += r_len;
	}
	else {
		r_len = *data_end - *data_pos;
		DEBUG_U_WRAP(LogMessage("%s: read insufficient data, len %d\n", __func__, r_len));
		memcpy(buf, &(spooler->record.data[*data_pos]), r_len);
		*data_pos = *data_end;
	}

	return r_len;
}

uint16_t Unified2RetrieveRecordHeader(Spooler *spooler, uint16_t r_len)
{
	uint16_t ret_len;
	uint8_t *pbuf;

	DEBUG_U_WRAP(LogMessage("%s: event_cur %d, event_top %d\n", __func__,
	        spooler->spara->sring->event_cur, spooler->spara->sring->event_top));

	pbuf = spooler->spara->sring->event_cache[spooler->spara->sring->event_cur].header;
	ret_len = Unified2GetRecFromBuf(spooler, pbuf, r_len);

	if ( ret_len < r_len ) {
		if ( BARNYARD2_SUCCESS == Unified2ReadFile(spooler) ) {
			r_len -= ret_len;
			pbuf += ret_len;
			ret_len += Unified2GetRecFromBuf(spooler, pbuf, r_len);
		}
	}

	return ret_len;
}

uint16_t Unified2RetrieveRecord(Spooler *spooler, uint16_t r_len)
{
	uint16_t ret_len;
	uint8_t *pbuf;

	pbuf = spooler->spara->sring->event_cache[spooler->spara->sring->event_cur].data;
	ret_len = Unified2GetRecFromBuf(spooler, pbuf, r_len);

	if ( ret_len < r_len ) {
		if ( BARNYARD2_SUCCESS == Unified2ReadFile(spooler) ) {
			r_len -= ret_len;
			pbuf += ret_len;
			ret_len += Unified2GetRecFromBuf(spooler, pbuf, r_len);
		}
	}

	return ret_len;
}

/* Partial reads should rarely, if ever, happen.  Thus we should not actually
   call lseek very often
 */
int Unified2ReadRecordHeader(void *sph)
{
    ssize_t             bytes_read;
    Spooler             *spooler = (Spooler *)sph;

#ifndef SPOOLER_FIXED_BUF
    if( NULL == spooler->record.header )
    {
        // SnortAlloc will FatalError if memory can't be assigned.
        spooler->record.header = SnortAlloc(sizeof(Unified2RecordHeader));
    }
#else
    if (SPOOLER_RING_FULL(spooler->spara->sring)) {
    	LogMessage("%s: Event RING buffer is full!\n", __func__);
    	return BARNYARD2_RING_FULL;
    }
#endif

    /* read the first portion of the unified log reader */
#if 0//DEBUG
    int position = lseek(spooler->fd, 0, SEEK_CUR);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Reading at byte position %u\n", position););
#endif

#ifndef SPOOLER_FILE_STREAM
    bytes_read = read( spooler->fd, spooler->record.header + spooler->offset, sizeof(Unified2RecordHeader) - spooler->offset);

    if (bytes_read == -1)
    {
        LogMessage("ERROR: Read error: %s\n", strerror(errno));
        return BARNYARD2_FILE_ERROR;
    }

    if (bytes_read + spooler->offset != sizeof(Unified2RecordHeader))
    {
        if(bytes_read + spooler->offset == 0)
        {
            return BARNYARD2_READ_EOF;
        }

        spooler->offset += bytes_read;
        return BARNYARD2_READ_PARTIAL;
    }
#else
/*    bytes_read = fread( spooler->event_cache[spooler->event_cur].header,
    		1, sizeof(Unified2RecordHeader), spooler->fp);
    if (0 == bytes_read)
    {
        LogMessage("ERROR: Read error: %s\n", strerror(errno));
        return BARNYARD2_FILE_ERROR;
    }*/
    bytes_read = Unified2RetrieveRecordHeader(spooler, sizeof(Unified2RecordHeader));
    DEBUG_U_WRAP(LogMessage("%s: bytes_read %d, type %d, length %d\n", __func__, bytes_read,
    	    ntohl(((Unified2RecordHeader *)spooler->spara->sring->event_cache[spooler->spara->sring->event_cur].header)->type),
    	    ntohl(((Unified2RecordHeader *)spooler->spara->sring->event_cache[spooler->spara->sring->event_cur].header)->length)));
    if (bytes_read != sizeof(Unified2RecordHeader))
    {
/*        if(bytes_read + spooler->offset == 0)
        {
            return BARNYARD2_READ_EOF;
        }

        spooler->offset += bytes_read;*/
        return BARNYARD2_READ_PARTIAL;
    }
#endif
/*
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Type=%u (%u bytes)\n",
                ntohl(((Unified2RecordHeader *)spooler->record.header)->type),
                ntohl(((Unified2RecordHeader *)spooler->record.header)->length)););*/

    return 0;
}

int Unified2ReadRecord(void *sph)
{
    ssize_t             bytes_read;
    uint32_t            record_type;
    uint32_t            record_length;
    Spooler             *spooler = (Spooler *)sph;
    EventRecordNode     *ernCache;

    /* convert once */
    ernCache = &(spooler->spara->sring->event_cache[spooler->spara->sring->event_cur]);
    record_type = ntohl(((Unified2RecordHeader *)ernCache->header)->type);
    record_length = ntohl(((Unified2RecordHeader *)ernCache->header)->length);

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Reading record type=%u (%u bytes)\n",
                record_type, record_length););

#ifndef SPOOLER_FIXED_BUF
    if(!spooler->record.data)
    {
        /* SnortAlloc will FatalError if memory can't be assigned */
        spooler->record.data = SnortAlloc(record_length);
    }
#else
    if (SPOOLER_RING_FULL(spooler->spara->sring)) {
    	LogMessage("%s: Event RING buffer is full!\n", __func__);
    	return BARNYARD2_RING_FULL;
    }
#endif

    if (1)
    {
#if 0//DEBUG
        int position = lseek(spooler->fd, 0, SEEK_CUR);
        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Record: Reading at byte position %u\n", position););
#endif
        /* in case we don't have it already */

#ifndef SPOOLER_FILE_STREAM
        bytes_read = read(spooler->fd, spooler->record.data + spooler->offset,
                    record_length - spooler->offset);

        if (bytes_read == -1)
        {
            LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
        }

        if (bytes_read + spooler->offset != record_length)
        {
            spooler->offset += bytes_read;
            return BARNYARD2_READ_PARTIAL;
        }
#else
/*        bytes_read = fread(spooler->event_cache[spooler->event_cur].data,
                    1, record_length, spooler->fp);

        if (0 == bytes_read)
        {
            LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
        }*/

        bytes_read = Unified2RetrieveRecord(spooler, record_length);
        DEBUG_U_WRAP(LogMessage("%s: bytes_read %d, record_type %d\n", __func__, bytes_read, record_type));
        if (bytes_read != record_length)
        {
/*            if(bytes_read + spooler->offset == 0)
            {
                return BARNYARD2_READ_EOF;
            }???
            spooler->offset += bytes_read;*/
            return BARNYARD2_READ_PARTIAL;
        }

        ernCache->type = record_type;
        ernCache->event_id = ntohl(((Unified2CacheCommon*)ernCache->data)->event_id);

        switch (record_type) {
        case UNIFIED2_PACKET:   //Packet
            {
                DEBUG_U_WRAP(LogMessage("%s: parse pkt, ernCache->data %x\n", __func__, ernCache->data));
                spoolerRetrievePktData(ernCache->s_pkt, ernCache->data);
            }
            break;
        case UNIFIED2_EXTRA_DATA:
            break;
        default:    //Event
            {
    			/* Ready to throw record into ring, if e_id is smaller than expect from Database, move forward. */
            	if ( RING_PRE_ON == spooler->spara->sring->r_switch ) {	//Let's Roll
            		if ( (spooler->spara->sring->base_eventid+ernCache->event_id)
            				<= spooler->spara->sring->rollon_cid ) {
            			spooler->spara->sring->base_eventid =
            					spooler->spara->sring->rollon_cid - ernCache->event_id + 1;
                		LogMessage("%s: promote(rollon) base_eventid to %lu, cur %lu, rollon %lu\n", __func__,
                				spooler->spara->sring->base_eventid, ernCache->event_id, spooler->spara->sring->rollon_cid);
            		}
            		spooler->spara->sring->r_switch = RING_ON;
            	}
                else {
                    /* Check if it's new start of record id, move forward to match [WILD] packet event id */
                    if ( 1 == ernCache->event_id ) {
                        spooler->spara->sring->base_eventid += spooler->spara->sring->prev_eventid;
                        LogMessage("%s: promote base_eventid to %lu\n", __func__, spooler->spara->sring->base_eventid);
                    }
                    else if ( ernCache->event_id <= spooler->spara->sring->prev_eventid ) {
                        spooler->spara->sring->base_eventid +=
                                (spooler->spara->sring->prev_eventid - ernCache->event_id) + 1;
                        LogMessage("%s: promote(jump) base_eventid to %lu, prev %lu, cur %lu\n", __func__,
                                spooler->spara->sring->base_eventid, spooler->spara->sring->prev_eventid, ernCache->event_id);
                    }
                }
            	/* Save previous event id */
                spooler->spara->sring->prev_eventid = ernCache->event_id;
            }
            break;
        }

        ernCache->event_id += spooler->spara->sring->base_eventid;
        DEBUG_U_WRAP_DEEP(LogMessage("%s: Proceed with evnet_id=%u, ms_cid[%d] %u, prev_eid %u\n", __func__,
                ernCache->event_id, spooler->spara->rid,
                spooler->spara->sring->base_eventid, spooler->spara->sring->prev_eventid));

#endif

#ifdef DEBUG
        switch (record_type)
        {
            case UNIFIED2_IDS_EVENT:
                Unified2PrintEventRecord((Unified2IDSEvent_legacy *)spooler->record.data);
                break;
            case UNIFIED2_IDS_EVENT_IPV6:
                Unified2PrintEvent6Record((Unified2IDSEventIPv6_legacy *)spooler->record.data);
                break;
            case UNIFIED2_PACKET:
                Unified2PrintPacketRecord((Unified2Packet *)spooler->record.data);
                break;
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            default:
                DEBUG_WRAP(DebugMessage(DEBUG_LOG,"No debug available for record type: %u\n", record_type););
                break;
        }
#endif

        return BARNYARD2_SUCCESS;
    }

    return -1;
}

void Unified2CleanExitFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2CleanExitFunc\n"););
    return;
}

void Unified2RestartFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2RestartFunc\n"););
    return;
}


#ifdef DEBUG
void Unified2PrintEventCommonRecord(Unified2EventCommon *evt)
{
    if(evt == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "Type: Event -------------------------------------------\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  sensor_id          = %d\n", ntohl(evt->sensor_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  event_id           = %d\n", ntohl(evt->event_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  event_second       = %lu\n", ntohl(evt->event_second)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  event_microsecond  = %lu\n", ntohl(evt->event_microsecond)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  generator_id       = %d\n", ntohl(evt->generator_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  signature_id       = %d\n", ntohl(evt->signature_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  signature_revision = %d\n", ntohl(evt->signature_revision)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  classification_id  = %d\n", ntohl(evt->classification_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  priority_id        = %d\n", ntohl(evt->priority_id)););
}

void Unified2PrintEventRecord(Unified2IDSEvent_legacy *evt)
{
    char                sip4[INET_ADDRSTRLEN];
    char                dip4[INET_ADDRSTRLEN];

    if(evt == NULL)
        return;

    Unified2PrintEventCommonRecord((Unified2EventCommon *)evt);

    inet_ntop(AF_INET, &(evt->ip_source), sip4, INET_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"  %-18s = %s\n", "ip_source", sip4););

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  sport_itype        = %d\n", ntohs(evt->sport_itype)););
    inet_ntop(AF_INET, &(evt->ip_destination), dip4, INET_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  ip_destination     = %s\n", dip4););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  dport_icode        = %d\n", ntohs(evt->dport_icode)););

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  ip_protocol        = %d\n", evt->protocol););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  impact             = %d\n", evt->impact_flag););
}

void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *evt)
{
    char                sip6[INET6_ADDRSTRLEN];
    char                dip6[INET6_ADDRSTRLEN];

    if(evt == NULL)
        return;

    Unified2PrintEventCommonRecord((Unified2EventCommon *)evt);

    inet_ntop(AF_INET6, &(evt->ip_source), sip6, INET6_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"  %-18s = %s\n", "ip_source", sip6););

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  sport_itype        = %d\n", ntohs(evt->sport_itype)););
    inet_ntop(AF_INET6, &(evt->ip_destination), dip6, INET6_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  ip_destination     = %s\n", dip6););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  dport_icode        = %d\n", ntohs(evt->dport_icode)););

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  ip_protocol        = %d\n", evt->protocol););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  impact             = %d\n", evt->impact_flag););
}

void Unified2PrintPacketRecord(Unified2Packet *pkt)
{
    if(pkt == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "Type: Packet ------------------------------------------\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "  %-16s %-16s\n", "sensor id:",    ntohl(pkt->sensor_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "  %-16s %-16lu\n", "event id:",     ntohl(pkt->event_id)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "  %-16s %-16lu\n", "event second:", ntohl(pkt->event_second)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  linktype           = %d\n", ntohl(pkt->linktype)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  packet_second      = %lu\n", ntohl(pkt->packet_second)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  packet_microsecond = %lu\n", ntohl(pkt->packet_microsecond)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  packet_length      = %d\n", ntohl(pkt->packet_length)););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
        "  packet             = %02x %02x %02x %02x\n",pkt->packet_data[1],
                                                       pkt->packet_data[2],
                                                       pkt->packet_data[3],
                                                       pkt->packet_data[4]););

}
#endif

