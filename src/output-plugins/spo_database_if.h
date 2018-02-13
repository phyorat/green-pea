#ifndef __SPO_DATABASE_IF_H__
#define __SPO_DATABASE_IF_H__

#include "spooler.h"
#include "spo_database.h"

#ifdef ENABLE_MYSQL
# include <mysql.h>
# include <errmsg.h>
#endif


void Connect(DatabaseData *, uint8_t);
void Disconnect(DatabaseData *, uint8_t);
void DatabasePrintUsage();
int Insert(char *, DatabaseData *, u_int32_t, uint8_t);
int Insert_real(char * , uint32_t , DatabaseData *, u_int32_t, uint8_t);
int Select(char *, DatabaseData *, u_int32_t *, uint8_t);
int Select_bigint(char *, DatabaseData *, uint64_t *, uint8_t);

void resetTransactionState(DatabaseIns *);
void setTransactionState(DatabaseIns *);
void setTransactionCallFail(DatabaseIns *);
u_int32_t getReconnectState(DatabaseIns *);
void setReconnectState(DatabaseIns *, u_int32_t);

u_int32_t BeginTransaction(DatabaseData *, uint8_t);
u_int32_t CommitTransaction(DatabaseData *, uint8_t);
u_int32_t RollbackTransaction(DatabaseData *, uint8_t);
u_int32_t checkTransactionState(DatabaseIns *);
u_int32_t checkTransactionCall(DatabaseIns *);

int UpdateLastCid(DatabaseData *, uint8_t, uint8_t, uint8_t);
int GetLastCid(DatabaseData *);
int GetLastCidFromTable(DatabaseData *);

void DatabaseCleanSelect(DatabaseData *data, uint8_t q_sock);
void DatabaseCleanInsert(DatabaseData *data, uint8_t q_sock);

u_int32_t dbReconnectSetCounters(dbReliabilityHandle *, DatabaseIns *);
u_int32_t MYSQL_ManualConnect(DatabaseData *, uint8_t);
u_int32_t dbConnectionStatusMYSQL(dbReliabilityHandle *, uint8_t);


#endif /*__SPO_DATABASE_IF_H__*/
