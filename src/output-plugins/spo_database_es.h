#ifndef __SPO_DATABASE_ES_H__
#define __SPO_DATABASE_ES_H__

#include "es_action.h"
#include "json-c/json.h"

#include "sp_mpool.h"
#include "spo_database.h"


#define     ES_CLASS_NAME_LEN 60


void spo_mr_init_finalize(int unused, void *arg);
void spo_mr_clean_exit(int signal, void *arg);
u_int32_t spo_mr_sync_eventid_intodb(DatabaseData *data);
int spo_mr_sync_siginfo(DatabaseData *data, void *event, EventMbufIds *embuf_ids, uint8_t q_sock);

#endif   /*__SPO_DATABASE_ES_H__*/
