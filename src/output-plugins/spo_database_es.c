
#include "jhash.h"
#include "spo_database_es.h"
#include "spo_database_cache.h"
#include "spo_mpool_ring.h"
#include "squirrel.h"
#include "es_action.h"


u_int32_t spo_mr_dbsign_Info_update(DatabaseData *data,
        cacheSignatureObj *iUpdateSig, uint8_t q_sock)
{
    u_int32_t db_sig_id = 0;
    uint8_t isupdate = 0;

    if ((data == NULL) || (iUpdateSig == NULL)) {
        return 1;
    }

    if ( iUpdateSig->flag & CACHE_DATABASE ) {
        isupdate = 1;
        /* PUT : UPDATE signature SET "       \
        "sig_class_id = '%u',"                      \
        "sig_priority = '%u',"                      \
        "sig_rev = '%u' "                       \
        "WHERE sig_id = '%u'; "*/
/*        SQL_UPDATE_SPECIFIC_SIGNATURE, iUpdateSig->obj.class_id,
                iUpdateSig->obj.priority_id, iUpdateSig->obj.rev,
                iUpdateSig->obj.db_id))*/
    } else {
        /* POST: INSERT INTO signature (sig_sid, sig_gid, sig_rev, sig_class_id, sig_priority, sig_name) VALUES ('%u','%u','%u','%u','%u','%s');*/
        /*iUpdateSig->obj.sid, iUpdateSig->obj.gid,
                iUpdateSig->obj.rev, iUpdateSig->obj.class_id,
                iUpdateSig->obj.priority_id, iUpdateSig->obj.message))*/
    }

    if (isupdate){
        db_sig_id = iUpdateSig->obj.db_id;
        LogMessage("%s: Last query(update) sig_id %d\n", __func__, db_sig_id);
/*        if ( db_sig_id != iUpdateSig->obj.db_id ) {
            LogMessage("ERROR database: Returned signature_id [%u] "
                    "is not equal to updated signature_id [%u] in [%s()] \n",
                    db_sig_id, iUpdateSig->obj.db_id, __FUNCTION__);
            return 1;
        }*/
    }
    else{
        /* GET : DOC ID */
        //db_sig_id = mysql_insert_id(data->m_dbins[q_sock].m_sock);
        db_sig_id = 1;

        LogMessage("%s: Last query(insert) auto_increament id %d\n", __func__, db_sig_id);

        iUpdateSig->flag |= CACHE_DATABASE;
        iUpdateSig->obj.db_id = db_sig_id;
    }

    return 0;
}

int spo_mr_sync_siginfo(DatabaseData *data, void *event,
        EventMbufIds *embuf_ids, uint8_t q_sock)
{
    cacheSignatureObj unInitSig;
    dbSignatureObj sigInsertObj = { 0 };
    dbSignatureHashKey sigHashKey;
    dbSignatureObj *psigObj;
    cacheSignatureObj* pcacheSig;
    u_int32_t i = 0;
    u_int32_t db_classification_id = 0;
    u_int32_t sigMatchCount = 0;
    u_int32_t sid = 0;
    u_int32_t gid = 0;
    u_int32_t revision = 0;
    u_int32_t priority = 0;
    u_int32_t classification = 0;
    u_int32_t sigMsgLen = 0;
    uint32_t ha_idx;
    u_int8_t reuseSigMsg = 0;

    if ((data == NULL) || (event == NULL) || (embuf_ids == NULL)) {
        return 1;
    }

    memset(&unInitSig, '\0', sizeof(cacheSignatureObj));

    embuf_ids->sig_ref_id = 0;
    embuf_ids->sig_id = ntohl(((Unified2EventCommon *) event)->signature_id);
    embuf_ids->sig_gid = ntohl(((Unified2EventCommon *) event)->generator_id);
    embuf_ids->sig_rev = ntohl(((Unified2EventCommon *) event)->signature_revision);
    embuf_ids->class_id = ntohl(((Unified2EventCommon *) event)->classification_id);
    embuf_ids->sig_prio = ntohl(((Unified2EventCommon *) event)->priority_id);

    return 0;

    revision = ntohl(((Unified2EventCommon *) event)->signature_revision);
    if ( 0 == revision ) {
        LogMessage("%s: Invalid rev, set as default 1.\n", __func__);
        revision = 1;  //Set Default as 1
    }
    priority = ntohl(((Unified2EventCommon *) event)->priority_id);
    classification = ntohl(((Unified2EventCommon *) event)->classification_id);
    /* NOTE: elz
     * For sanity purpose the sig_class table SHOULD have internal classification id to prevent possible
     * miss classification tagging ... but this is not happening with the old schema.
     */
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], Classification cachelookup [class_id: %u]\n",
                    __FUNCTION__,
                    classification));
#endif
    db_classification_id = cacheEventClassificationLookup(
            data->mc.cacheClassificationHead, classification);

    /*
     * This is now only needed for backward compatible with old sid-msg.map file.
     * new version has gid || sid || revision || msg || etc..
     */
    if (BcSidMapVersion() == SIDMAPV1) {
        if (gid == 3) {
            gid = 1;
        }
    }

    /*
     * This function comes with a little twist where it return the number of matching couple for
     * gid sid up to a maximum of 255 (arbitrary defined) this is a static buffer  and it is cleaned every call
     * from there if its traversed and compared with revision and priority and classification
     * if one or both differs its reported and inserted ....
     */

#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], Signature cachelookup [gid: %u] [sid: %u]\n",
                    __FUNCTION__,
                    gid,
                    sid));
#endif

    sigHashKey.gid = gid;
    sigHashKey.sid = sid;
    ha_idx = jhash(&sigHashKey, sizeof(sigHashKey), 0) & SIG_HASHSZ_MASK;

    if ((sigMatchCount = cacheEventSignatureLookup(data->mc.cacheSigHashMap[ha_idx],//cacheSignatureHead
            data->mc.plgSigCompare, gid, sid)) > 0) {
        for (i = 0; i < sigMatchCount; i++) {
            psigObj = &(data->mc.plgSigCompare[i].cacheSigObj->obj);
            if (psigObj->rev == revision
                    && psigObj->class_id == db_classification_id
                    && psigObj->priority_id == priority) {
                assert(psigObj->db_id != 0);
                embuf_ids->sig_ref_id = psigObj->db_id;
                return 0;
            }

            /* If we have an "uninitialized signature save it */
            if ( (0==psigObj->rev)
                || (psigObj->rev < revision)
                /* So we have a signature that was inserted, probably a preprocessor signature,
                 * but it has probably never been logged before lets set it as a temporary unassigned signature */
                || (psigObj->rev == revision
                        && (psigObj->class_id!=db_classification_id || psigObj->priority_id!=priority)))
            {
                memcpy(&unInitSig, data->mc.plgSigCompare[i].cacheSigObj, sizeof(cacheSignatureObj));
                /*
                 * We assume that we have the same signature, but with a smaller revision
                 * set the unInitSig db_id to 0 for post processing if we do not find a matching
                 * signature, and get the lastest revision
                 */

                if ( psigObj->rev < revision ) {// || psigObj->rev > unInitSig.obj.rev ) {
                    unInitSig.obj.db_id = 0;
                }
                else {
                    psigObj->class_id = db_classification_id;
                    psigObj->priority_id = priority;
                }
            }
        }
    }

    if (BcSidMapVersion() == SIDMAPV1) {

        LogMessage("%s: sid_ver v1, db_id %d, sid %d, gid %d, rev %d, class %d, prio_id %d\n", __func__,
                unInitSig.obj.db_id,
                sid, gid, revision, db_classification_id, priority);

        if (unInitSig.obj.db_id != 0) {
#if DEBUG
            DEBUG_WRAP(DebugMessage(DB_DEBUG,
                    "[%s()], [%u] signatures where found in cache for [gid: %u] [sid: %u] but non matched event criteria.\n"
                    "Updating database [db_sig_id: %u] FROM  [rev: %u] classification [ %u ] priority [%u] "
                    "                                  TO    [rev: %u] classification [ %u ] priority [%u]\n",
                    __FUNCTION__,
                    sigMatchCount,
                    gid,
                    sid,
                    unInitSig.obj.db_id,
                    unInitSig.obj.rev,unInitSig.obj.class_id,unInitSig.obj.priority_id,
                    revision,db_classification_id,priority));
#endif

            unInitSig.obj.rev = revision;
            unInitSig.obj.class_id = db_classification_id;
            unInitSig.obj.priority_id = priority;

            if ((spo_mr_dbsign_Info_update(data, &unInitSig, q_sock))) {
                LogMessage(
                        "[%s()] Line[%u], call to dbSignatureInformationUpdate failed for : \n"
                                "[gid :%u] [sid: %u] [upd_rev: %u] [upd class: %u] [upd pri %u]\n",
                        __FUNCTION__,
                        __LINE__, gid, sid, revision, db_classification_id,
                        priority);
                return 1;
            }

            assert(unInitSig.obj.db_id != 0);
            embuf_ids->sig_ref_id = unInitSig.obj.db_id;
            return 0;
        }
    }

    /*
     * To avoid possible collision with an older barnyard process or
     * avoid signature insertion race condition we will look in the
     * database if the signature exist, if it does, we will insert it in
     * cache else we will insert in db and cache
     */

    sigInsertObj.sid = sid;
    sigInsertObj.gid = gid;
    sigInsertObj.rev = revision;
    sigInsertObj.class_id = db_classification_id;
    sigInsertObj.priority_id = priority;

    if (1)//SignatureLookupDatabase(data, &sigInsertObj, q_sock))
    {
        if (unInitSig.obj.sid != 0 && unInitSig.obj.gid != 0) {
            sigMsgLen = strlen(unInitSig.obj.message);

            if ((sigMsgLen > 1) && (sigMsgLen < SIG_MSG_LEN)) {
                reuseSigMsg = 1;
            }
        }

        if (reuseSigMsg) {
            /* The signature was not found we will have to insert it */
/*          LogMessage(
                    "INFO [%s()]: [Event: %u] with [gid: %u] [sid: %u] [rev: %u] [classification: %u] [priority: %u] Signature Message -> \"[%s]\"\n"
                            "\t was not found in squirrel signature cache, this could mean its is the first time the signature is processed, and will be inserted\n"
                            "\t in the database with the above information, this message should only be printed once for each signature that is not  present in the database\n"
                            "\t The new inserted signature will not have its information present in the sig_reference table,it should be present on restart\n"
                            "\t if the information is present in the sid-msg.map file. \n"
                            "\t You can always update the message via a SQL query if you want it to be displayed correctly by your favorite interface\n\n",
                    __FUNCTION__,
                    ntohl(((Unified2EventCommon *) event)->event_id), gid, sid,
                    revision, db_classification_id, priority,
                    unInitSig.obj.message);*/

            if (SnortSnprintf(sigInsertObj.message, SIG_MSG_LEN, "%s",
                    unInitSig.obj.message)) {
                return 1;
            }
        } else {
            /* The signature does not exist we will have to insert it */
/*          LogMessage(
                    "INFO [%s()]: [Event: %u] with [gid: %u] [sid: %u] [rev: %u] [classification: %u] [priority: %u]\n"
                            "\t was not found in squirrel signature cache, this could lead to display inconsistency.\n"
                            "\t To prevent this warning, make sure that your sid-msg.map and gen-msg.map file are up to date with the snort process logging to the spool file.\n"
                            "\t The new inserted signature will not have its information present in the sig_reference table. \n"
                            "\t Note that the message inserted in the signature table will be snort default message \"Snort Alert [gid:sid:revision]\" \n"
                            "\t You can always update the message via a SQL query if you want it to be displayed correctly by your favorite interface\n\n",
                    __FUNCTION__,
                    ntohl(((Unified2EventCommon *) event)->event_id), gid, sid,
                    revision, db_classification_id, priority);*/

            if (SnortSnprintf(sigInsertObj.message, SIG_MSG_LEN,
                    "Snort Alert [%u:%u:%u]", gid, sid, revision)) {
                return 1;
            }
        }

        if ( NULL == (pcacheSig=SignatureCacheInsertObj(&sigInsertObj, &data->mc, 0, ha_idx)) ) {
            LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
                    __FUNCTION__);
            goto func_err;
        }

        /*
         * There is some little overhead traversing the list once
         * the insertion is done on the HEAD so
         * unless you run 1M rules and still there it should
         * complete in just a few more jiffies, also its better this way
         * than to query the database everytime isin't.
         */
//      if (SignaturePopulateDatabase(data, data->mc.cacheSignatureHead, 1, q_sock)) {
        if ((spo_mr_dbsign_Info_update(data, pcacheSig, q_sock))) {
            LogMessage("[%s()]: ERROR inserting new signature \n",
                    __FUNCTION__);
            goto func_err;
        }
    }
/*  else {
        LogMessage("%s: is in database\n", __func__);
        if ( NULL == (pcacheSig=SignatureCacheInsertObj(&sigInsertObj, &data->mc, 1)) ) {
            LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
                    __FUNCTION__);
            goto func_err;
        }
    }*/

    /* Added for bugcheck */
/*  assert(data->mc.cacheSignatureHead->obj.db_id != 0);
    *psig_id = data->mc.cacheSignatureHead->obj.db_id;*/

    assert(pcacheSig->obj.db_id != 0);
    embuf_ids->sig_ref_id = pcacheSig->obj.db_id;

    return 0;

func_err:
    return 1;
}

u_int32_t spo_mr_initdb_sensor(DatabaseData *data)
{
    int i;
    u_int32_t retval = 0;
/*    char * escapedSensorName = NULL;
    char * escapedInterfaceName = NULL;
    char * escapedBPFFilter = NULL;*/

    if (data == NULL) {
        return 1;
    }

    /* find a unique name for sensor if one was not supplied as an option */
    if (!data->sensor_name) {
        data->sensor_name = GetUniqueName(
                PRINT_INTERFACE(barnyard2_conf->interface));
        if (data->sensor_name) {
            if (data->sensor_name[strlen(data->sensor_name) - 1] == '\n') {
                data->sensor_name[strlen(data->sensor_name) - 1] = '\0';
            }
        }
    }

/*    escapedSensorName = snort_escape_string(data->sensor_name, data);
    escapedInterfaceName = snort_escape_string(
            PRINT_INTERFACE(barnyard2_conf->interface), data);*/

    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
//        if (data->ignore_bpf == 0) {
//            if (barnyard2_conf->bpf_filter == NULL) {
        if ( /*exist*/1 ) {
            /* put : ("sid,hostname, interface, bid, filter, detail, encoding, last_cid, last_mcid) "
                                "VALUES (%u,'%s','%s',%u,'%s',%u,%u, 0, 0);",
                        1, escapedSensorName, escapedInterfaceName, i, escapedBPFFilter,
                        data->detail, data->encoding)
                        */
        }
        else {
            /* get : (get last_cid, last_mcid     " WHERE bid = %u "
                        , i)
                        */
        }

        /* No check here */
        //Select(data->SQL_SELECT[SPO_DB_DEF_INS], data, (u_int32_t *) &data->sid, SPO_DB_DEF_INS);
    }

    return retval;
}

u_int32_t spo_mr_sync_eventid_fromdb(DatabaseData *data)
{
    int i;
    char doc_type[16];
    char doc_id[4];
    json_object *sp_object;
    json_object *val_obj = NULL;
    json_object *get_obj = NULL;

    if (data == NULL) {
        return 1;
    }

    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
        data->cid[i] = 0;
        data->ms_cid[i] = 0;

        /* GET : last_cid FROM sensor WHERE sid = %u AND bid = %u;", data->sid, i)*/
        /* GET : last_mcid FROM sensor WHERE sid = %u AND bid = %u;", data->sid, i)*/
        snprintf(doc_type, sizeof(doc_type), "accum_ids_%d", data->sid);
        snprintf(doc_id, sizeof(doc_id), "%d", i);
        sp_object = es_get("spooler_accumid", doc_type, doc_id);
        if( NULL == sp_object ) {
            LogMessage("%s: Fail to get spooler (m)cid[%d]!\n", __func__, i);
            continue;
        }

        if ( json_object_object_get_ex(sp_object, "_source", &val_obj) ) {
            if ( json_object_object_get_ex(val_obj, "spo_cid", &get_obj) )
                data->cid[i] = json_object_get_int64(get_obj);
            if ( json_object_object_get_ex(val_obj, "spo_mcid", &get_obj) )
                data->ms_cid[i] = json_object_get_int64(get_obj);
        }
        LogMessage("%s: Get sid %d, bid %d, cid %lu, mcid %lu, \n", __func__, data->sid, i, data->cid[i], data->ms_cid[i]);

        json_object_put(sp_object);
    }

    //GetLastCid(data);
    //GetLastCidFromTable(data);

    return 0;
}

u_int32_t spo_mr_sync_eventid_intodb(DatabaseData *data)
{
    int i;
    char doc_type[16];
    char doc_id[4];
    json_object *sp_object;
    const char *putd;

    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
        /* PUT : UPDATE sensor SET last_cid = %lu, last_mcid = %lu WHERE sid = %u AND bid = %u;",
         data->cid[i], data->ms_cid[i], data->sid, i) */
        sp_object = json_object_new_object();
        if( NULL == sp_object ){
            LogMessage("%s: failed to new json object\n", __FUNCTION__);
            return -1;
        }

        //json_object_object_add(sp_object, "sid", json_object_new_int(data->sid));
        //json_object_object_add(sp_object, "bid", json_object_new_int(i));
        json_object_object_add(sp_object, "spo_cid", json_object_new_int(data->cid[i]));
        json_object_object_add(sp_object, "spo_mcid", json_object_new_int(data->ms_cid[i]));
        putd = json_object_to_json_string(sp_object);
        snprintf(doc_type, sizeof(doc_type), "accum_ids_%d", data->sid);
        snprintf(doc_id, sizeof(doc_id), "%d", i);
        if(!es_put("spooler_accumid", doc_type, doc_id, putd))
            LogMessage("%s: update sid %d, bid %d, cid %lu, mcid %lu\n", __func__,
                        data->sid, i, data->cid[i], data->ms_cid[i]);
        else
            LogMessage("%s: Fail to update spooler (m)cid[%d]!\n", __func__, i);

        json_object_put(sp_object);
    }

    return 0;
}

u_int32_t spo_mr_class_pulldata(DatabaseData *data,
        dbClassificationObj **iArrayPtr, u_int32_t *array_length)
{
    u_int32_t curr_row = 0, num_row;
//    u_int32_t queryColCount = 0;
//    int result = 0;

    if ((data == NULL) || ((iArrayPtr == NULL) && (*iArrayPtr != NULL))
            || (array_length == NULL)) {
        LogMessage(
                "[%s()], Call failed DataBaseData[0x%x] dbClassificationObj **[0x%x] u_int32_t *[0x%x] \n",
                __FUNCTION__, data, iArrayPtr, array_length);
        return 1;
    }

    /* GET : SELECT sig_class_id, sig_class_name FROM sig_class ORDER BY sig_class_id ASC; */

//    unsigned int i = 0;
    num_row = 1;//Get DOC Count

    if ( num_row > 0) {
        if ((*iArrayPtr = SnortAlloc((sizeof(dbClassificationObj) * num_row))) == NULL) {
            FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                    __FUNCTION__);
        }
    }
    else {
        LogMessage("[%s()]: No Classification found in database ... \n",
                __FUNCTION__);
        return 0;
    }

    *array_length = num_row;
//    queryColCount = NUM_ROW_CLASSIFICATION;//mysql_num_fields(data->m_dbins[SPO_DB_DEF_INS].m_result);

    while ((curr_row < num_row)) {
            //&& (row = mysql_fetch_row(data->m_dbins[SPO_DB_DEF_INS].m_result))) {
        //process DOC content:
        dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];

        cPtr->db_sig_class_id = strtoul("1"/*row[i]*/, NULL, 10);
        strncpy(cPtr->sig_class_name, "asd"/*row[i]*/, ES_CLASS_NAME_LEN);
        cPtr->sig_class_name[ES_CLASS_NAME_LEN - 1] = '\0'; //safety

        //if ((snort_escape_string_STATIC(cPtr->sig_class_name, data->sanitize_buffer[0],
        //                                CLASS_NAME_LEN, data))) {
        curr_row++;
    }

    return 1;
}

u_int32_t spo_mr_class_popdatabase(DatabaseData *data,
        cacheClassificationObj *cacheHead)
{
    u_int32_t db_class_id;

    if ((data == NULL) || (cacheHead == NULL)) {
        return 1;
    }

    while (cacheHead != NULL) {
        if ( !(cacheHead->flag & CACHE_DATABASE) ) {

            /*PUT : INSERT INTO sig_class (sig_class_name) VALUES ('%s'); cacheHead->obj.sig_class_name)*/
            db_class_id = 1; //ID return from ES

            cacheHead->obj.db_sig_class_id = db_class_id;
            cacheHead->flag |= CACHE_DATABASE;
        }
        cacheHead = cacheHead->next;
    }

    return 0;
}

u_int32_t spo_mr_class_cache_sync(DatabaseData *data,
        cacheClassificationObj **cacheHead)
{
    dbClassificationObj *dbClassArray = NULL;
    u_int32_t array_length = 0;

    if ((data == NULL) || (cacheHead == NULL)) {
        return 1;
    }

    if ( (spo_mr_class_pulldata(data, &dbClassArray, &array_length)) ) {
        return 1;
    }

    if (array_length > 0) {
        if ((ClassificationCacheUpdateDBid(dbClassArray, array_length,
                cacheHead))) {
            if (dbClassArray != NULL) {
                free(dbClassArray);
                dbClassArray = NULL;
                array_length = 0;
            }

            LogMessage("[%s()], Call to ClassificationCacheUpdateDBid() failed \n",
                    __FUNCTION__);
            return 1;
        }

        if (dbClassArray != NULL) {
            free(dbClassArray);
            dbClassArray = NULL;
        }
        array_length = 0;
    }

    if (*cacheHead == NULL) {
        LogMessage("\n[%s()]: Make sure that your "
                "(config classification_config argument in your barnyard2 configuration file) "
                "or --classification or -C argument point \n"
                "\t to a file containing at least some valid classification or that that your database sig_class table contain data\n\n",
                __FUNCTION__);
        return 1;
    }

    if (*cacheHead != NULL) {
        if (spo_mr_class_popdatabase(data, *cacheHead)) {
            LogMessage("[%s()], Call to ClassificationPopulateDatabase() failed \n",
                    __FUNCTION__);

            return 1;
        }
    }

    /* out list will behave now */
    return 0;
}

u_int32_t spo_mr_sig_pulldata(DatabaseData *data, dbSignatureObj **iArrayPtr,
        u_int32_t *array_length)
{
    u_int32_t curr_row = 0, num_row;
    u_int32_t queryColCount = 0;
//    int result = 0;

    if ((data == NULL) || ((iArrayPtr == NULL) && (*iArrayPtr != NULL))
            || (array_length == NULL)) {
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSignatureObj **[0x%x] u_int32_t *[0x%x] \n",
                __FUNCTION__, data, iArrayPtr, array_length);
        return 1;
    }

    /* GET : SELECT sig_id, sig_sid, sig_gid,sig_rev, sig_class_id, sig_priority, sig_name FROM signature;*/
    num_row = 1;//GET Doc Count
//    unsigned int i = 0;
    if ( num_row > 0) {
        if ((*iArrayPtr = SnortAlloc(
                (sizeof(dbSignatureObj) * num_row))) == NULL) {
            FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                    __FUNCTION__);
        }
    }
    else {
        LogMessage("[%s()]: No signature found in database ... \n",
                __FUNCTION__);
        return 0;
    }

    *array_length = num_row;
    queryColCount = NUM_ROW_SIGNATURE;//mysql_num_fields(data->m_dbins[SPO_DB_DEF_INS].m_result);
    if (queryColCount != NUM_ROW_SIGNATURE) {
        LogMessage("[%s()] To many column returned by query [%u]...\n",
                __FUNCTION__, queryColCount);
        return 1;
    }

    while ( (curr_row < num_row) ) {
        dbSignatureObj *cPtr = &(*iArrayPtr)[curr_row];
        cPtr->db_id = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->sid = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->gid = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->rev = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->class_id = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->priority_id = strtoul(/*row[i]*/"1", NULL, 10);
        strncpy(cPtr->message, /*row[i]*/"asd", SIG_MSG_LEN);
        cPtr->message[SIG_MSG_LEN - 1] = '\0'; //safety
#if 0
        //Safety escape value.
        if ((snort_escape_string_STATIC(cPtr->message, data->sanitize_buffer[0],
                SIG_MSG_LEN, data))) {
            FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                    "[%s], Exiting. \n",
                    __FUNCTION__, cPtr->message);
        }
#endif
        curr_row++;
    }

    //Case Get Doc Fail
    LogMessage("[%s()]: Failed get doc , will retry \n",
            __FUNCTION__);

    return 0;
}

u_int32_t spo_mr_sig_popdatabase(DatabaseData *data,
        cacheSignatureObj *cacheHead, int inTransac)
{
    u_int32_t db_sig_id = 0;

    if ((data == NULL) || (cacheHead == NULL)) {
        return 1;
    }

    while (cacheHead != NULL) {
        /* This condition block is a shortcut in the signature insertion code.
         ** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
         ** It will also prevent the code to take wrong execution path downstream.
         */
        if ( !(cacheHead->flag&CACHE_DATABASE) ) {
            /* This condition block is a shortcut in the signature insertion code.
             ** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
             ** It will also prevent the code to take wrong execution path downstream.
             */
            // && (((cacheHead->obj.gid != 1 && cacheHead->obj.gid != 3)) || )
            if ( (1 == cacheHead->obj.gid || 3 == cacheHead->obj.gid)
                    && (0 == cacheHead->obj.rev) ) {
                cacheHead = cacheHead->next;
                continue;
            }

            /* DONE at object Insertion
             if( (snort_escape_string_STATIC(cacheHead->obj.message,SIG_MSG_LEN,data)))
             {
             FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
             "[%s], Exiting. \n",
             __FUNCTION__,
             cacheHead->obj.message);
             }
             */

            /* PUT : INSERT INTO signature (sig_sid, sig_gid, sig_rev, sig_class_id, sig_priority, sig_name)
             * VALUES ('%u','%u','%u','%u','%u','%s');
             * cacheHead->obj.sid, cacheHead->obj.gid,
                    cacheHead->obj.rev, cacheHead->obj.class_id,
                    cacheHead->obj.priority_id, cacheHead->obj.message)) */

            //LogMessage("%s: Last query auto_increament id %d\n", __func__, db_sig_id);

            cacheHead->obj.db_id = db_sig_id;

            //cacheHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
            cacheHead->flag |= CACHE_DATABASE;
        }

        cacheHead = cacheHead->next;
    }

    return 0;
}

u_int32_t spo_mr_sig_cache_sync(DatabaseData *data,
        cacheSignatureObj **cacheHead)
{
    dbSignatureObj *dbSigArray = NULL;
    u_int32_t array_length = 0;

    LogMessage("%s: \n", __func__);

    if ((data == NULL) || (*cacheHead == NULL)) {
        return 1;
    }

    if ((spo_mr_sig_pulldata(data, &dbSigArray, &array_length))) {
        return 1;
    }

    LogMessage("%s: SignaturePullDataStore\n", __func__);

    if (array_length > 0) {
        if ((SignatureCacheUpdateDBid(data, dbSigArray, array_length, cacheHead))) {
            if (dbSigArray != NULL) {
                free(dbSigArray);
                dbSigArray = NULL;
                array_length = 0;
            }

            LogMessage("[%s()], Call to SignatureCacheUpdateDBid() failed \n",
                    __FUNCTION__);
            return 1;
        }

        if (dbSigArray != NULL) {
            free(dbSigArray);
            dbSigArray = NULL;
        }
        array_length = 0;
    }

    LogMessage("%s: SignatureCacheUpdateDBid\n", __func__);

    if (spo_mr_sig_popdatabase(data, *cacheHead, 0)) {
        LogMessage("[%s()], Call to SignaturePopulateDatabase() failed \n",
                __FUNCTION__);
        return 1;
    }

    LogMessage("%s: SignaturePopulateDatabase\n", __func__);

    /* Equilibrate references thru sibblings.*/
    if (SignatureReferencePreGenerate(*cacheHead)) {
        LogMessage("[%s()], Call to SignatureReferencePreGenerate failed \n",
                __FUNCTION__);
        return 1;
    }

    LogMessage("%s: SignatureReferencePreGenerate\n", __func__);

    /* Well done */
    return 0;
}

u_int32_t spo_mr_system_pulldata(DatabaseData *data, dbSystemObj **iArrayPtr,
        u_int32_t *array_length)
{
    u_int32_t curr_row = 0, num_row;
//    u_int32_t queryColCount = 0;
//    int result = 0;

    if ((data == NULL) || ((iArrayPtr == NULL) && (*iArrayPtr != NULL))
            || (array_length == NULL)) {
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                __FUNCTION__, data, iArrayPtr, array_length);
        return 1;
    }

    /* GET : SELECT ref_system_id, ref_system_name FROM reference_system;*/
    num_row = 1; //DOC Count
//    unsigned int i = 0;
    if ( num_row  > 0) {
        if ((*iArrayPtr = SnortAlloc((sizeof(dbSystemObj) * num_row))) == NULL) {
            FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                    __FUNCTION__);
        }
    }
    else {
        LogMessage("[%s()]: No System found in database ... \n",
                __FUNCTION__);
        return 0;
    }

    *array_length = num_row;
//    queryColCount = NUM_ROW_REFERENCE_SYSTEM;//mysql_num_fields(data->m_dbins[SPO_DB_DEF_INS].m_result);
    while ( curr_row < num_row ) {
        dbSystemObj *cPtr = &(*iArrayPtr)[curr_row];
        cPtr->db_ref_system_id = strtoul(/*row[i]*/"1", NULL, 10);
        strncpy(cPtr->ref_system_name, /*row[i]*/"asd", SYSTEM_NAME_LEN);
        cPtr->ref_system_name[SYSTEM_NAME_LEN - 1] = '\0'; //toasty.
#if 0
        //Safety escape value.
        if ((snort_escape_string_STATIC(cPtr->ref_system_name, data->sanitize_buffer[0],
                SYSTEM_NAME_LEN, data))) {
            FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                    "[%s], Exiting. \n",
                    __FUNCTION__,
                    cPtr->ref_system_name);
        }
#endif
        curr_row++;
    }

    //Case Get Doc Fail
    LogMessage("[%s()]: Failed exeuting get doc , will retry \n",
            __FUNCTION__);

    return 0;
}

u_int32_t spo_mr_system_popdatabase(DatabaseData *data, cacheSystemObj *cacheHead)
{
    u_int32_t db_system_id = 0;

    if (data == NULL) {
        return 1;
    }

    if (cacheHead == NULL) {
        return 0;
    }

    while (cacheHead != NULL) {
        if ( !(cacheHead->flag & CACHE_DATABASE) ) {

/*            if ((snort_escape_string_STATIC(cacheHead->obj.ref_system_name, data->sanitize_buffer[0],
                    SYSTEM_NAME_LEN, data))) {
                FatalError(
                        "database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                                "[%s], Exiting. \n", __FUNCTION__,
                        cacheHead->obj.ref_system_name);
            }*/

            /* PUT : INSERT INTO reference_system (ref_system_name) VALUES ('%s');
                    cacheHead->obj.ref_system_name)*/

            cacheHead->obj.db_ref_system_id = db_system_id;
            //cacheHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
            cacheHead->flag |= CACHE_DATABASE;

            /* Give child system id */

            cacheReferenceObj *tNode = cacheHead->obj.refList;
            while (tNode != NULL) {
                tNode->obj.parent = (cacheSystemObj *) &cacheHead->obj;
                tNode->obj.system_id = cacheHead->obj.db_ref_system_id;
                tNode = tNode->next;
            }

        }

        cacheHead = cacheHead->next;
    }

    return 0;
}

u_int32_t spo_mr_reference_pulldata(DatabaseData *data, dbReferenceObj **iArrayPtr,
        u_int32_t *array_length)
{
    u_int32_t curr_row = 0, num_row;
//    u_int32_t queryColCount = 0;
//    int result = 0;

    if ((data == NULL) || ((iArrayPtr == NULL) && (*iArrayPtr != NULL))
            || (array_length == NULL)) {
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                __FUNCTION__, data, iArrayPtr, array_length);
        return 1;
    }

    /* GET : SELECT ref_id, ref_system_id, ref_tag FROM reference; */
    num_row = 1; //Doc Count
//    unsigned int i = 0;
    if ( num_row  > 0) {
        if ((*iArrayPtr = SnortAlloc((sizeof(dbReferenceObj) * num_row))) == NULL) {
            FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                    __FUNCTION__);
        }
    }
    else {
        LogMessage("[%s()]: No Reference found in database ... \n",
                __FUNCTION__);
        return 0;
    }

    *array_length = num_row;
//    queryColCount = NUM_ROW_REF;//mysql_num_fields(data->m_dbins[SPO_DB_DEF_INS].m_result);

    while ( curr_row < num_row ) {
        dbReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
        cPtr->ref_id = strtoul(/*row[i]*/"1", NULL, 10);
        /* Do nothing for now but could be used to do a consistency check */
        cPtr->system_id = strtoul(/*row[i]*/"1", NULL, 10);
        strncpy(cPtr->ref_tag, /*row[i]*/"asd", REF_TAG_LEN);
        cPtr->ref_tag[REF_TAG_LEN - 1] = '\0';
#if 0
        //Safety escape value.
        if ((snort_escape_string_STATIC(cPtr->ref_tag, data->sanitize_buffer[0],
                REF_TAG_LEN, data))) {
            FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                    "[%s], Exiting. \n",
                    __FUNCTION__, cPtr->ref_tag);
        }
#endif

        curr_row++;
    }

    //Case Fail
    LogMessage("[%s()]: Failed get doc , will retry \n",
            __FUNCTION__);

    return 0;
}

u_int32_t spo_mr_reference_popdatabase(DatabaseData *data,
        cacheReferenceObj *cacheHead)
{
    u_int32_t db_ref_id;

    if ((data == NULL) || (cacheHead == NULL)) {
        return 1;
    }

    while (cacheHead != NULL) {
        if ( !(cacheHead->flag & CACHE_DATABASE) ) {
            /* PUT : INSERT INTO reference (ref_system_id,ref_tag) VALUES ('%u','%s');
                    cacheHead->obj.parent->obj.db_ref_system_id,
                    cacheHead->obj.ref_tag*/
            db_ref_id = 1; //ID return from ES

            cacheHead->obj.ref_id = db_ref_id;
            cacheHead->obj.system_id =
                    cacheHead->obj.parent->obj.db_ref_system_id;
            //cacheHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH); /* Remove it */
            cacheHead->flag |= CACHE_DATABASE;
        }

        cacheHead = cacheHead->next;
    }

    return 0;
}

u_int32_t spo_mr_system_cache_sync(DatabaseData *data, cacheSystemObj **cacheHead)
{
    cacheSystemObj *SystemCacheElemPtr = NULL;
    dbSystemObj *dbSysArray = NULL;
    dbReferenceObj *dbRefArray = NULL;

    u_int32_t array_length = 0;

    if ((data == NULL) || (*cacheHead == NULL)) {
        return 1;
    }

    //System
    if ((spo_mr_system_pulldata(data, &dbSysArray, &array_length))) {
        return 1;
    }

    //If system is not populated correctly, we probably do not have ref's
    //and if so using the schema logic they probably are wrong, thus
    // we will insert them by our self afterward.
    if (array_length > 0) {
        if ((SystemCacheUpdateDBid(dbSysArray, array_length, cacheHead))) {
            LogMessage("[%s()], Call to SystemCacheUpdateDBid() failed. \n",
                    __FUNCTION__);
            goto func_fail;
        }
    }

    /* Reset for re-use */
    array_length = 0;

    //Reference
    if ((spo_mr_reference_pulldata(data, &dbRefArray, &array_length))) {
        LogMessage("[%s()], Call to ReferencePullDataStore() failed. \n",
                __FUNCTION__);
        goto func_fail;
    }

    if (array_length > 0) {
        if ((ReferenceCacheUpdateDBid(dbRefArray, array_length, cacheHead))) {
            LogMessage("[%s()], Call to ReferenceCacheUpdateDBid() failed \n",
                    __FUNCTION__);
            goto func_fail;
        }
    }

    /* Populate. */
    if (spo_mr_system_popdatabase(data, *cacheHead)) {
        LogMessage("[%s()], Call to SystemPopulateDatabase() failed \n",
                __FUNCTION__);
        goto func_fail;
    }

    /* Update Reference cache */
    SystemCacheElemPtr = *cacheHead;

    while (SystemCacheElemPtr != NULL) {
        if (SystemCacheElemPtr->obj.refList != NULL) {
            if (spo_mr_reference_popdatabase(data,
                    SystemCacheElemPtr->obj.refList)) {
                LogMessage("[%s()], Call to ReferencePopulateDatabase() failed \n",
                        __FUNCTION__);
                goto func_fail;
            }
        }
        SystemCacheElemPtr = SystemCacheElemPtr->next;
    }

    if (dbRefArray != NULL) {
        free(dbRefArray);
        dbRefArray = NULL;
        array_length = 0;
    }

    if (dbSysArray != NULL) {
        free(dbSysArray);
        dbSysArray = NULL;
        array_length = 0;
    }

    return 0;

func_fail:
    if (dbRefArray != NULL) {
        free(dbRefArray);
        dbRefArray = NULL;
        array_length = 0;
    }

    if (dbSysArray != NULL) {
        free(dbSysArray);
        dbSysArray = NULL;
        array_length = 0;
    }

    return 1;
}

u_int32_t spo_mr_sig_ref_pulldata(DatabaseData *data,
        dbSignatureReferenceObj **iArrayPtr, u_int32_t *array_length)
{
    u_int32_t curr_row = 0, num_row;
//    u_int32_t queryColCount = 0;
//    int result = 0;

    if ((data == NULL) || ((iArrayPtr == NULL) && (*iArrayPtr != NULL))
            || (array_length == NULL)) {
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                __FUNCTION__, data, iArrayPtr, array_length);
        return 1;
    }

    /* GET : SELECT ref_id, sig_id, ref_seq FROM sig_reference ORDER BY sig_id,ref_seq;*/
    num_row = 1;
//    unsigned int i = 0;
    if ( num_row > 0) {
        if ((*iArrayPtr = SnortAlloc((sizeof(dbSignatureReferenceObj) * num_row)))
                            == NULL) {
            FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                    __FUNCTION__);
        }
    }
    else {
        LogMessage("[%s()]: No Reference found in database ... \n",
                __FUNCTION__);
        return 0;
    }

    *array_length = num_row;
//    queryColCount = NUM_ROW_SIGREF;//mysql_num_fields(data->m_dbins[SPO_DB_DEF_INS].m_result);
    while ( curr_row < num_row ) {
        dbSignatureReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
        cPtr->db_ref_id = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->db_sig_id = strtoul(/*row[i]*/"1", NULL, 10);
        cPtr->ref_seq = strtoul(/*row[i]*/"1", NULL, 10);
        curr_row++;
    }

    //Case Fail
    LogMessage("[%s()]: Failed get doc, will retry \n",
            __FUNCTION__);

    return 0;
}

u_int32_t spo_mr_sig_ref_popdatabase(DatabaseData *data,
        cacheSignatureReferenceObj *cacheHead)
{
//    u_int32_t row_validate = 0;

    if ((data == NULL)) {
        return 1;
    }

    if (cacheHead == NULL) {
        /* Do nothing */
        return 0;
    }

    while (cacheHead != NULL) {
        if ( !(cacheHead->flag & CACHE_DATABASE) ) {
//            row_validate = 0;

            /* PUT : INSERT INTO sig_reference (ref_id,sig_id,ref_seq) VALUES ('%u','%u','%u');
                    cacheHead->obj.db_ref_id,
                    cacheHead->obj.db_sig_id, cacheHead->obj.ref_seq)*/

            /* Prevent race.. */
            usleep(100);

            /*if (cacheHead->flag & CACHE_INTERNAL_ONLY) {
                cacheHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
            }*/
            cacheHead->flag |= CACHE_DATABASE;
        }
        cacheHead = cacheHead->next;
    }

    return 0;
}

u_int32_t spo_mr_sig_ref_sync(DatabaseData *data,
        cacheSignatureReferenceObj **cacheHead, cacheSignatureObj *cacheSigHead)
{
    //cacheSignatureReferenceObj *SystemCacheElemPtr = NULL;
    dbSignatureReferenceObj *dbSigRefArray = NULL;

    u_int32_t array_length = 0;

    if ((data == NULL) || (cacheHead == NULL) || (cacheSigHead == NULL)) {
        return 1;
    }

    if ((GenerateSigRef(cacheHead, cacheSigHead))) {
        return 1;
    }

    LogMessage("%s: GenerateSigRef\n", __func__);

    //Pull from the db
    if ((spo_mr_sig_ref_pulldata(data, &dbSigRefArray, &array_length))) {
        LogMessage("SignatureReferencePullDataStore failed \n");
        return 1;
    }

    LogMessage("%s: SignatureReferencePullDataStore\n", __func__);

    if (array_length > 0) {
        if ((SignatureReferenceCacheUpdateDBid(dbSigRefArray, array_length,
                cacheHead, data->mc.cacheSignatureHead,
                data->mc.cacheSystemHead))) {
            if (dbSigRefArray != NULL) {
                free(dbSigRefArray);
                dbSigRefArray = NULL;
                array_length = 0;
            }

            LogMessage("[%s()], Call to SignatureReferenceCacheUpdateDBid() failed \n",
                    __FUNCTION__);
            return 1;
        }

        LogMessage("%s: SignatureReferenceCacheUpdateDBid\n", __func__);

        if (dbSigRefArray != NULL) {
            free(dbSigRefArray);
            dbSigRefArray = NULL;
        }
        array_length = 0;
    }

    if ((spo_mr_sig_ref_popdatabase(data, *cacheHead))) {
        return 1;
    }

    LogMessage("%s: SignatureReferencePopulateDatabase\n", __func__);

    //Ze done.
    return 0;
}

u_int32_t spo_mr_cache_synchronize(DatabaseData *data)
{
    if (data == NULL) {
        return 1;
    }

    //Classification Synchronize
    if ((spo_mr_class_cache_sync(data, &data->mc.cacheClassificationHead))) {
        LogMessage("[%s()], ClassificationCacheSynchronize() call failed. \n",
                __FUNCTION__);
        return 1;
    }

    //Signature Synchronize
    if ((spo_mr_sig_cache_sync(data, &data->mc.cacheSignatureHead))) {
        LogMessage("[%s()]:, SignatureCacheSynchronize() call failed. \n",
                __FUNCTION__);
        return 1;
    }

    //System Synchronize
    if (data->mc.cacheSystemHead != NULL) {
        if ((spo_mr_system_cache_sync(data, &data->mc.cacheSystemHead))) {
            LogMessage("[%s()]:, SystemCacheSyncronize() call failed. \n",
                    __FUNCTION__);
            return 1;
        }

        LogMessage("%s: SystemCacheSynchronize\n", __func__);

        if (!data->dbRH[data->dbtype_id].disablesigref) {
            //SigRef Synchronize
            if ((spo_mr_sig_ref_sync(data, &data->mc.cacheSigReferenceHead,
                    data->mc.cacheSignatureHead))) {
                LogMessage("[%s()]: SigRefSynchronize() call failed \n",
                        __FUNCTION__);
                return 1;
            }

            LogMessage("%s: SigRefSynchronize\n", __func__);
        }
    }
    else {
        LogMessage("\n[%s()],INFO: No system was found in cache (from signature map file), will not process or synchronize informations found in the database \n\n",
                __FUNCTION__);
    }

    /* Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count */
    MasterCacheFlush(data, CACHE_FLUSH_SYSTEM_REF | CACHE_FLUSH_SIGREF);
    /* Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count */

    LogMessage("%s: MasterCacheFlush\n", __func__);

    return 0;
}

void spo_mr_init_finalize(int unused, void *arg)
{
//    uint8_t i;
    DatabaseData *data = (DatabaseData *) arg;

    if(init_curl())
        FatalError("database(ES) initialize failed\n");

    if ((data == NULL)) {
        FatalError("database data uninitialized\n");
    }

/*    for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
        Connect(data, i);
    }*/

    if ((ConvertDefaultCache(barnyard2_conf, data))) {
        FatalError("sp_output [%s()], ConvertDefaultCache() Failed \n",
                __FUNCTION__);
    }

    /* Get the versioning information for the DB schema */
/*    if ((CheckDBVersion(data))) {
        FatalError("sp_output problems with schema version, bailing...\n");
    }*/

    if ( spo_mr_initdb_sensor(data) ) {
        FatalError("database Unable to initialize sensor \n");
    }

    if (spo_mr_sync_eventid_fromdb(data)) {
        FatalError(
                "database Encountered an error while trying to synchronize event_id, this is serious and we can't go any further, please investigate \n");
    }

/*    if (spo_mr_cache_synchronize(data)) {
        FatalError("database [%s()]: CacheSynchronize() call failed ...\n",
                __FUNCTION__);
        return;
    }*/

    //TODO: Get Classification information from database.

    //DatabasePluginPrintData(data);

    //SQL_Initialize(data);

    return;
}

u_int32_t spo_mr_exit_finalize(DatabaseData *data)
{

    LogMessage("%s: es exit.\n", __func__);

    destroy_curl();
    return 0;
}

void spo_mr_clean_exit(int signal, void *arg)
{
//    uint8_t i;
    DatabaseData *data = (DatabaseData *) arg;

    if (data != NULL) {
        MasterCacheFlush(data, CACHE_FLUSH_ALL);

        spo_mr_sync_eventid_intodb(data);//, 1, 1, SPO_DB_DEF_INS);

        /*for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
            Disconnect(data, i);
        }*/

        spo_mr_exit_finalize(data);

        free(data->args);
        free(data);
        data = NULL;
    }

    return;
}

