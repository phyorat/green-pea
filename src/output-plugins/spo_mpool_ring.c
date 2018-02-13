
#include "sp_mpool.h"
#include "spo_common.h"
#include "spo_database.h"
#include "spo_database_cache.h"
#include "spo_mpool_ring.h"
#include "spo_database_es.h"

/*******************************************************************************
 * Function: spo_mr_setup()
 *
 * Purpose: Registers the output plugin keyword and initialization
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ******************************************************************************/
void spo_mr_setup(void)
{
    /* link the preprocessor keyword to the init function in
     the preproc list */

    RegisterOutputPlugin("mpool_ring", OUTPUT_TYPE_FLAG__ALERT, spo_mr_init);

    //DEBUG_WRAP(DebugMessage(DEBUG_INIT, "database(debug): database plugin is registered...\n"););
}

static void spo_mr_parse_args(DatabaseData *data)
{
//    char *dbarg;
//    char *a1;
    char *type;
    char *facility;

    if (data->args == NULL) {
        ErrorMessage(
                "ERROR mr_arg_parse: you must supply arguments for database plugin\n");
        SPO_PrintUsage();
        FatalError("");
    }

    facility = strtok(data->args, ", ");
    if (facility != NULL) {
        if ((!strncasecmp(facility, "mmap", 3))) {
            data->facility = facility;
        }
        else {
            ErrorMessage(
                    "ERROR mr_arg_parse: The first argument needs to be the output facility\n");
            SPO_PrintUsage();
            FatalError("");
        }
    } else {
        ErrorMessage("ERROR mr_arg_parse: Invalid format for first argment\n");
        SPO_PrintUsage();
        FatalError("");
    }

    type = strtok(NULL, ", ");

    if (type == NULL) {
        ErrorMessage(
                "ERROR mr_arg_parse: you must enter the mpool_ring type in configuration "
                        "file as the second argument\n");
        SPO_PrintUsage();
        FatalError("");
    }

    if (!strncasecmp(type, KEYWORD_MR_DPDK, strlen(KEYWORD_MR_DPDK))) {
        data->dbtype_id = MR_DPDK_MMAP;
    }
    else {
        ErrorMessage(
                "ERROR mr_arg_parse: mpool_ring %s is currently not supported by this build.",
                type);
        SPO_PrintUsage();
        FatalError("");
    }

    //dbarg = strtok(NULL, " =");
    //while (dbarg != NULL) {
    //}
}

/*******************************************************************************
 * Function: spo_mr_init(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 ******************************************************************************/
void spo_mr_init(char *args)
{
    DatabaseData *data;

    if (args == NULL) {
        ErrorMessage(
                "ERROR mr_init: you must supply arguments for mpool_ring plugin\n");
        SPO_PrintUsage();
        FatalError("");
    }

    data = (DatabaseData *) SnortAlloc(sizeof(DatabaseData));
    data->args = SnortStrdup(args);
    data->tz = GetLocalTimezone();
    spo_mr_parse_args(data);

    /* Add the processor function into the function list */
    if (strncasecmp(data->facility, "log", 3) == 0) {
        AddFuncToOutputList(spo_mpool_ring, OUTPUT_TYPE__LOG, data);
    } else {
        AddFuncToOutputList(spo_mpool_ring, OUTPUT_TYPE__ALERT, data);
    }

    AddFuncToOutputList(spo_mpool_ring, OUTPUT_TYPE__FLUSH, data);

#ifdef ENABLE_ES
    AddFuncToRestartList(spo_mr_clean_exit, data);
    AddFuncToCleanExitList(spo_mr_clean_exit, data);
    AddFuncToPostConfigList(spo_mr_init_finalize, data);
#else
    AddFuncToRestartList(SpoDatabaseCleanExitFunction, data);
    AddFuncToCleanExitList(SpoDatabaseCleanExitFunction, data);
    AddFuncToPostConfigList(DatabaseInitFinalize, data);
#endif
}

static void spo_mr_get_sid(DatabaseData *spo_data, EventMbufIds *embuf_ids, void *event_data)
{
    uint8_t lQ_ins = 0;

    if ( spo_mr_sync_siginfo(spo_data,
            event_data, embuf_ids, lQ_ins) ) {
        //setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
        FatalError("[spo_mr_get_sid()]: Failed, stopping processing \n");
    }

    //Trace CID
/*    if ( lQ_ele->event_id > spo_data->cid[lQ_ele->rid] ) {
        DEBUG_U_WRAP_SP_QUERY(LogMessage("%s: update cid[%d] - %d\n", __func__,
                lQ_ele->rid, lQ_ele->event_id));
        spo_data->cid[lQ_ele->rid] = lQ_ele->event_id;
    }*/
}

void spo_mpool_ring(Packet *p, void *event, uint32_t event_type, void *arg)
{
    uint8_t rid, log_sta = 0;
    int r_ret;
//    int da2qe_w;//, qe2da_r;
//    us_cid_t event_id;
    DatabaseData *data = (DatabaseData *) arg;
    Unified2Packet *pdata;
//    struct timespec t_elapse;
    //MREvent mr_event;
    //MRPkt mr_pkt;
    EventMBuf *buf_send;
    EventGMCid *eCidcur;

    if ( NULL == data ) {
        FatalError("database [%s()]: Called with a NULL DatabaseData Argument, can't process \n",
                __FUNCTION__);
        return;
    }

//    t_elapse.tv_sec = 0;
//    t_elapse.tv_nsec = 10;

    switch (event_type) {
    case UNIFIED2_IDS_GET_MCID:
        {
            if ( NULL != event ) {
                rid = ((EventGMCid*)event)->rid;
                ((EventGMCid*)event)->cid = data->cid[rid];
                ((EventGMCid*)event)->ms_cid = data->ms_cid[rid];
            }
            return;
        }
        break;
    case UNIFIED2_IDS_SET_MCID:
        {
            if ( NULL != event ) {
                rid = ((EventGMCid*)event)->rid;
                data->ms_cid[rid] = ((EventGMCid*)event)->ms_cid;
                data->refresh_mcid = 1;
            }
            return;
        }
        break;
    case UNIFIED2_IDS_SET_CIDS:
        {
            if ( NULL != event ) {
                eCidcur = (EventGMCid*)event;
                for (rid=0; rid<BY_MUL_TR_DEFAULT; rid++,eCidcur++) {
                    if ( data->cid[rid] < eCidcur->cid )
                        data->cid[rid] = eCidcur->cid;
                }
            }
            return;
        }
        break;
    case UNIFIED2_IDS_UPD_MCID:
        {
            if ( NULL != event ) {
                rid = ((EventGMCid*)event)->rid;
                data->ms_cid[rid] = ((EventGMCid*)event)->ms_cid;
                //UpdateLastCid(data, 0);
                spo_mr_sync_eventid_intodb(data);
                data->refresh_mcid = 1;
            }
            return;
        }
        break;
    case UNIFIED2_IDS_SET_RINGS:
        {
            if ( NULL != event ) {
                data->spo_ring = ((EventSpoMR*)event)->ring_snd;
                //data->spo_ring_ret = ((EventSpoRings*)event)->ring_ret;
            }
            return;
        }
        break;
    case UNIFIED2_IDS_GET_ELEQUE_INS:
    case UNIFIED2_IDS_SPO_EXIT:
    case UNIFIED2_IDS_FLUSH_OUT:
    case UNIFIED2_IDS_FLUSH:
        {
            return;
        }
        break;
    default:
        {
            if (event == NULL || p == NULL) {
                LogMessage("WARNING spo_mpool [%s()]: Called with Event[0x%x] "
                        "Event Type [%u] (P)acket [0x%x], information has not been outputed. \n",
                        __FUNCTION__, event, event_type, p);
                return;
            }

            if ( (p->frag_flag) || (!IPH_IS_VALID(p)) ) {
                LogMessage("WARNING spo_mpool [%s()]: Invalid Packet.\n",
                        __FUNCTION__);
                return;
            }

            ((EventEP*)event)->ep->mbuf_turn2base = 0;
            buf_send = ((EventEP*)event)->ep->mbuf_data;
            buf_send->type = event_type;
            buf_send->sid = data->sid;
            buf_send->bid = ((EventEP*)event)->rid;
            buf_send->cid = ((EventEP*)event)->ep->event_id;
            buf_send->evn_pkt.ip_src = ntohl(p->iph->ip_src.s_addr);
            buf_send->evn_pkt.ip_dst = ntohl(p->iph->ip_dst.s_addr);
            buf_send->evn_pkt.proto = p->iph->ip_proto;
            buf_send->evn_pkt.sp = 0;
            buf_send->evn_pkt.dp = 0;
            switch (p->iph->ip_proto) {
            case IPPROTO_TCP:
                if ( NULL != p->tcph ) {
                    buf_send->evn_pkt.sp = ntohs(p->tcph->th_sport);
                    buf_send->evn_pkt.dp = ntohs(p->tcph->th_dport);
                }
                break;
            case IPPROTO_UDP:
                if ( NULL != p->udph ) {
                    buf_send->evn_pkt.sp = ntohs(p->udph->uh_sport);
                    buf_send->evn_pkt.dp = ntohs(p->udph->uh_dport);
                }
                break;
            default:
                break;
            }

            pdata = (Unified2Packet *)((EventEP*)event)->ep->data;
            buf_send->evn_pkt.timestamp = ntohl(pdata->event_second);
            buf_send->evn_pkt.pkt_raw = pdata->packet_data;
            buf_send->evn_pkt.pkt_rawlen = ntohl(pdata->packet_length);

            if ( UNIFIED2_PACKET != event_type ) {
/*                event_id = ((EventEP*)event)->ee->event_id;

                mr_event.event_id = event_id;
                mr_event.event_type = event_type;
                mr_event.event = ;
                mr_event.rid = ((EventEP*)event)->rid;
                mr_event.p = p;*/

                spo_mr_get_sid(data, &buf_send->evn_ids, ((EventEP*)event)->ee->data);///.........................
                buf_send->type = SP_EVENT_PKT;
            }
            else {
                memset(&buf_send->evn_ids, 0, sizeof(buf_send->evn_ids));
                buf_send->type = SP_PACKET;
            }

            /*uint8_t *pmac = (uint8_t*)buf_send->evn_pkt.pkt_raw;
            LogMessage("%s: mac %x %x %x %x %x %x\n", __func__,
                    pmac[0], pmac[1], pmac[2],
                    pmac[3], pmac[4], pmac[5]);*/

            //if ( !dbProcessMultiEventInfo(data, spo_db_event_queue[q_ins], q_ins) ) {
                //setTransactionCallFail(&spo_data->m_dbins[SPO_DB_DEF_INS]);
                //FatalError("[dbProcessMultiEventInfo()]: Failed, stoping processing \n");
            //}

            data->send_cnt++;

            /*            if ( NULL == buf_send->evn_pkt.pkt_raw
                                || buf_send->evn_pkt.pkt_rawlen > 1000 )//(buf_send->cid & 0xff) == 0x10 )*/
            /*LogMessage("%s: Ring(0x%lx) (sum: %d) event-pkt(type %d), pkt 0x%lx, pkt_len %d, event[%d]_id %d, sig_id %d\n", __func__,
                    (unsigned long)(data->spo_ring), data->send_cnt,
                    event_type, (unsigned long)(buf_send->evn_pkt.pkt_raw), buf_send->evn_pkt.pkt_rawlen,
                    buf_send->bid, buf_send->cid, buf_send->evn_ids.sig_id);*/

#ifndef SPO_MPOOL_DEBUG
            do {
                r_ret = rte_ring_enqueue(data->spo_ring, (void*)buf_send);
                if ( -ENOBUFS == r_ret ) {
                    if ( !log_sta ) {
                        LogMessage("%s: ring full for event transfer\n", __func__);
                        log_sta = 1;
                    }
                    usleep(1);
                }
                else if ( -EDQUOT == r_ret ) {
                    LogMessage("%s: Quota exceeded mbuf to event transfer\n", __func__);
                    break;
                }
            } while ( r_ret && (0==exit_signal) );

            if ( r_ret && (0!=exit_signal) ) {
                ((EventEP*)event)->ep->mbuf_turn2base = 1;
                LogMessage("%s: event transfer fail(exiting), return to base\n", __func__);
            }
            else if ( log_sta ) {
                LogMessage("%s: event transfer wait(ring full) done\n", __func__);
            }
#endif
        }
        break;
    }

    return;
}


