/*
 ** spo_database.c
 **
 ** Portions Copyright (C) 2000,2001,2002 Carnegie Mellon University
 ** Copyright (C) 2001 Jed Pickel <jed@pickel.net>
 ** Portions Copyright (C) 2001 Andrew R. Baker <andrewb@farm9.com>
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
 */

/*
 *  Maintainers : The Barnyard2 Team <firnsy@gmail.com> <beenph@gmail.com> 
 *  Past Maintainer: Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
 *  Originally written by Jed Pickel <jed@pickel.net> (2000-2001)
 *
 *  See the doc/README.database file with this distribution
 *  documentation or the snortdb web site for configuration
 *  information
 *
 *    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
 *                       this in production for us.
 *
 */

#include "jhash.h"
#include "spo_common.h"
#include "spo_database.h"
#include "spo_database_fm.h"

#define __USE_GNU
#include <pthread.h>

#ifdef ENABLE_MYSQL
#include "spo_database_if.h"
#endif

/******** fatals *******************************************************/

/* these strings deliberately break fatal error messages into
 chunks with lengths < 509 to keep ISO C89 compilers happy
 */

static const char* FATAL_NO_SENSOR_1 =
		" When this plugin starts, a SELECT query is run to find the sensor id for the\n"
				" currently running sensor. If the sensor id is not found, the plugin will run\n"
				" an INSERT query to insert the proper data and generate a new sensor id. Then a\n"
				" SELECT query is run to get the newly allocated sensor id. If that fails then\n"
				" this error message is generated.\n";

static const char* FATAL_NO_SENSOR_2 =
		" Some possible causes for this error are:\n"
				"  * the user does not have proper INSERT or SELECT privileges\n"
				"  * the sensor table does not exist\n"
				"\n"
				" If you are _absolutely_ certain that you have the proper privileges set and\n"
				" that your database structure is built properly please let me know if you\n"
				" continue to get this error. You can contact me at (roman@danyliw.com).\n";

static const char* FATAL_BAD_SCHEMA_1 =
		"database: The underlying database has not been initialized correctly.  This\n"
				"          version of barnyard2 requires version %d of the DB schema.  Your DB\n"
				"          doesn't appear to have any records in the 'schema' table.\n%s";

static const char* FATAL_BAD_SCHEMA_2 =
		"          Please re-run the appropriate DB creation script (e.g. create_mysql,\n"
				"          create_postgresql, create_oracle, create_mssql) located in the\n"
				"          contrib\\ directory.\n\n"
				"          See the database documentation for cursory details (doc/README.database).\n"
				"          and the URL to the most recent database plugin documentation.\n";

static const char* FATAL_OLD_SCHEMA_1 =
		"database: The underlying database seems to be running an older version of\n"
				"          the DB schema (current version=%d, required minimum version= %d).\n\n"
				"          If you have an existing database with events logged by a previous\n"
				"          version of barnyard2, this database must first be upgraded to the latest\n"
				"          schema (see the barnyard2-users mailing list archive or DB plugin\n"
				"          documention for details).\n%s\n";

static const char* FATAL_OLD_SCHEMA_2 =
		"          If migrating old data is not desired, merely create a new instance\n"
				"          of the snort database using the appropriate DB creation script\n"
				"          (e.g. create_mysql, create_postgresql, create_oracle, create_mssql)\n"
				"          located in the contrib\\ directory.\n\n"
				"          See the database documentation for cursory details (doc/README.database).\n"
				"          and the URL to the most recent database plugin documentation.\n";

static const char* FATAL_NO_SUPPORT_1 =
		"If this build of barnyard2 was obtained as a binary distribution (e.g., rpm,\n"
				"or Windows), then check for alternate builds that contains the necessary\n"
				"'%s' support.\n\n"
				"If this build of barnyard2 was compiled by you, then re-run the\n"
				"the ./configure script using the '--with-%s' switch.\n"
				"For non-standard installations of a database, the '--with-%s=DIR'\n%s";

static const char* FATAL_NO_SUPPORT_2 =
		"syntax may need to be used to specify the base directory of the DB install.\n\n"
				"See the database documentation for cursory details (doc/README.database).\n"
				"and the URL to the most recent database plugin documentation.\n";

static SQLEventQueue *spo_db_event_queue[SQL_ELEQUE_INS_MAX] = {NULL};

int Spo_ProcQuery_GetQins(DatabaseData *spo_data, const uint8_t ins_base);

void DatabaseCleanSelect(DatabaseData *data, uint8_t q_sock) {

	if ((data != NULL) && (data->SQL_SELECT[q_sock]) != NULL
			&& (data->SQL_SELECT_SIZE > 0)) {
		memset(data->SQL_SELECT[q_sock], '\0', data->SQL_SELECT_SIZE);
	}

	return;
}

void DatabaseCleanInsert(DatabaseData *data, uint8_t q_sock) {

	if ((data != NULL) && (data->SQL_INSERT[q_sock]) != NULL
			&& (data->SQL_INSERT_SIZE > 0)) {
		memset(data->SQL_INSERT[q_sock], '\0', data->SQL_INSERT_SIZE);
	}

	return;
}

/* SQLQueryList Funcs */
u_int32_t SQL_Initialize(DatabaseData *data)
{
    uint8_t i;
	u_int32_t x = 0;
    int err;
    SQLQueryList *pl_query;
    cpu_set_t cpuset;

    if (data == NULL) {
        return 1;
    }

    CPU_ZERO(&cpuset);
    cpuset.__bits[0] = data->cpuset_bm;

	for (i=0; i<SQL_ELEQUE_INS_MAX; i++) {
	    pl_query = &(data->lEleQue_ins[i].lsql_query);

	    if ((pl_query->query_array = (SQLQueryEle *) SnortAlloc(
	            (sizeof(SQLQueryEle) * MAX_SQL_QUERY_OPS))) == NULL) {
	        return 1;
	    }

	    for (x = 0; x < MAX_SQL_QUERY_OPS; x++) {
	        if ((pl_query->query_array[x].string = SnortAlloc(
	                (sizeof(char) * MAX_SQL_QUERY_LENGTH))) == NULL) {
	            return 1;
	        }
	    }

	    if ((pl_query->query_array_data = (SQLQueryEle *) SnortAlloc(
	            (sizeof(SQLQueryEle) * MAX_SQL_QUERY_DATA_OPS))) == NULL) {
	        return 1;
	    }

	    for (x = 0; x < MAX_SQL_QUERY_DATA_OPS; x++) {
	        if ((pl_query->query_array_data[x].string = SnortAlloc(
	                (sizeof(char) * MAX_SQL_QUERY_LENGTH_DATA))) == NULL) {
	            return 1;
	        }
	    }

	    if ((pl_query->query_array_ad_data = (SQLQueryEle *) SnortAlloc(
	            (sizeof(SQLQueryEle) * MAX_SQL_QUERY_ADDATA_OPS))) == NULL) {
	        return 1;
	    }

	    for (x = 0; x < MAX_SQL_QUERY_ADDATA_OPS; x++) {
	        if ((pl_query->query_array_ad_data[x].string = SnortAlloc(
	                (sizeof(char) * MAX_SQL_QUERY_LENGTH_ADDATA))) == NULL) {
	            return 1;
	        }
	    }

	    if (pipe(data->lEleQue_ins[i].pipe_data2queue) < 0
	            || pipe(data->lEleQue_ins[i].pipe_queue2data) < 0
	            || pipe(data->lEleQue_ins[i].pipe_queue2query) < 0
	            || pipe(data->lEleQue_ins[i].pipe_query2queue) < 0 ) {
	        perror("Cannot create pipe\n");
	        return 1;
	    }

	    LogMessage("%s: initial event_queue[%d], cpuset 0x%lx\n", __func__,
	            i, data->cpuset_bm);
	    spo_db_event_queue[i] = (SQLEventQueue*)SnortAlloc(sizeof(SQLEventQueue));
	    memset(spo_db_event_queue[i], 0, sizeof(SQLEventQueue));

	    data->lEleQue_ins[i].ql_index = i; //Just for initialization of enc_sql thread.
        data->lEleQue_ins[i].ql_switch = 1;
        data->lEleQue_ins[i].lq_stat = LQ_PRE_QUEUE;
        data->lEleQue_ins[i].spo_data = data;

        pthread_mutex_init(&data->lquery_lock, NULL);
        pthread_mutex_init(&data->lsiginfo_lock, NULL);

        err = pthread_create(&data->lEleQue_ins[i].tid_enc_sql,
                NULL, &Spo_EncodeSql, (void*)(&data->lEleQue_ins[i]));
        if (0 != err) {
            LogMessage("Can't create Spo_E thread %d: [%s]\n", i, strerror(err));
            return 1;
        }

        if ( data->cpuset_bm ) {
            err = pthread_setaffinity_np(data->lEleQue_ins[i].tid_enc_sql, sizeof(cpu_set_t), &cpuset);
            if ( 0 != err )
                handle_error_en(err, "pthread_setaffinity_np");
        }
	}
#ifdef IF_SPO_QUERY_IN_THREAD
	for (i=0; i<SQL_QUERY_SOCK_MAX; i++) {
	    err = pthread_create(&data->tid_query[i], NULL, &Spo_ProcQuery, (void*)(&data->m_dbins[i]));
	    if (0 != err) {
	        LogMessage("Can't create Spo_Q: [%s]\n", strerror(err));
	        return 1;
	    }
	}
#endif

	//First queue
	data->enc_q_ins = Spo_ProcQuery_GetQins(data, 0);

	return 0;
}

u_int32_t SQL_Finalize(DatabaseData *data)
{
    uint8_t i;
	u_int32_t x = 0;
	SQLQueryList *pl_query;

	if (data == NULL) {
		return 1;
	}

    for (i=0; i<SQL_ELEQUE_INS_MAX; i++) {
        pl_query = &(data->lEleQue_ins[i].lsql_query);

        pthread_mutex_destroy(&data->lsiginfo_lock);
        pthread_mutex_destroy(&data->lquery_lock);

        data->lEleQue_ins[i].ql_switch = 0;

        if (pl_query->query_array != NULL) {
            for (x = 0; x < MAX_SQL_QUERY_OPS; x++) {
                if (pl_query->query_array[x].string != NULL) {
                    free(pl_query->query_array[x].string);
                    pl_query->query_array[x].string = NULL;
                }
            }

            free(pl_query->query_array);
            pl_query->query_array = NULL;
        }

        if (pl_query->query_array_data != NULL) {
            for (x = 0; x < MAX_SQL_QUERY_DATA_OPS; x++) {
                if (pl_query->query_array_data[x].string != NULL) {
                    free(pl_query->query_array_data[x].string);
                }
            }

            free(pl_query->query_array_data);
            pl_query->query_array_data = NULL;
        }

        if (pl_query->query_array_ad_data != NULL) {
            for (x = 0; x < MAX_SQL_QUERY_DATA_OPS; x++) {
                if (pl_query->query_array_ad_data[x].string != NULL) {
                    free(pl_query->query_array_ad_data[x].string);
                }
            }

            free(pl_query->query_array_ad_data);
            pl_query->query_array_ad_data = NULL;
        }

        if (NULL != spo_db_event_queue[i]) {
            free (spo_db_event_queue[i]);
            spo_db_event_queue[i] = NULL;
        }
    }

	return 0;
}

SQLQueryEle *SQL_GetNextQuery(DatabaseData *data, uint8_t ele_que_ins)
{
    SQLQueryList *pl_query;
	SQLQueryEle *ret_query = NULL;

	if (data == NULL) {
		return NULL;
	}

	pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

	if (pl_query->query_count < MAX_SQL_QUERY_OPS) {
		ret_query = &(pl_query->query_array[pl_query->query_count]);
		ret_query->valid = 1;	//Default is valid
		pl_query->query_count++;
		return ret_query;
	}

	LogMessage("%s: Query Array if full!\n", __func__);

	return NULL;
}

SQLQueryEle *SQL_GetNextQueryData(DatabaseData *data, uint8_t ele_que_ins)
{
    SQLQueryList *pl_query;
	SQLQueryEle *ret_query = NULL;

	if (data == NULL) {
		return NULL;
	}

	pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

	if (pl_query->query_count_data < MAX_SQL_QUERY_DATA_OPS) {
		ret_query = &(pl_query->query_array_data[pl_query->query_count_data]);
		ret_query->valid = 1;	//Default is valid
		pl_query->query_count_data++;
		return ret_query;
	}

	return NULL;
}

SQLQueryEle *SQL_GetNextQueryAdData(DatabaseData *data, uint8_t ele_que_ins)
{
    SQLQueryList *pl_query;
    SQLQueryEle *ret_query = NULL;

    if (data == NULL) {
        return NULL;
    }

    pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

    if (pl_query->query_count_ad_data < MAX_SQL_QUERY_DATA_OPS) {
        ret_query = &(pl_query->query_array_ad_data[pl_query->query_count_ad_data]);
        ret_query->valid = 1;   //Default is valid
        pl_query->query_count_ad_data++;
        return ret_query;
    }

    return NULL;
}

SQLQueryEle *SQL_GetQueryByPos(DatabaseData *data, uint8_t ele_que_ins, u_int32_t pos)
{
    SQLQueryList *pl_query;

	if ((data == NULL) || pos > MAX_SQL_QUERY_OPS) {
		return NULL;
	}

	pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

	if (pl_query->query_array[pos].string != NULL) {
		return &(pl_query->query_array[pos]);
	}

	return NULL;
}

SQLQueryEle *SQL_GetQueryDataByPos(DatabaseData *data, uint8_t ele_que_ins, u_int32_t pos)
{
    SQLQueryList *pl_query;

	if ((data == NULL) || pos > MAX_SQL_QUERY_DATA_OPS) {
		return NULL;
	}

	pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

	if (pl_query->query_array_data[pos].string != NULL) {
		return &(pl_query->query_array_data[pos]);
	}

	return NULL;
}

SQLQueryEle *SQL_GetQueryAdDataByPos(DatabaseData *data, uint8_t ele_que_ins, u_int32_t pos)
{
    SQLQueryList *pl_query;

    if ((data == NULL) || pos > MAX_SQL_QUERY_DATA_OPS) {
        return NULL;
    }

    pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

    if (pl_query->query_array_ad_data[pos].string != NULL) {
        return &(pl_query->query_array_ad_data[pos]);
    }

    return NULL;
}

u_int32_t SQL_GetMaxQuery(DatabaseData *data, uint8_t ele_que_ins)
{
	if (data == NULL) {
		return 0;
	}

	return data->lEleQue_ins[ele_que_ins].lsql_query.query_count;
}

u_int32_t SQL_GetMaxQueryData(DatabaseData *data, uint8_t ele_que_ins)
{
	if (data == NULL) {
		return 0;
	}

	return data->lEleQue_ins[ele_que_ins].lsql_query.query_count_data;
}

u_int32_t SQL_GetMaxQueryAdData(DatabaseData *data, uint8_t ele_que_ins)
{
    if (data == NULL) {
        return 0;
    }

    return data->lEleQue_ins[ele_que_ins].lsql_query.query_count_ad_data;
}

u_int32_t SQL_Cleanup(DatabaseData *data, uint8_t ele_que_ins)
{
	u_int32_t x = 0;
	SQLQueryList *pl_query;

	if (data == NULL) {
		return 1;
	}


    pl_query = &(data->lEleQue_ins[ele_que_ins].lsql_query);

    if (pl_query->query_count) {
        for (x = 0; x < pl_query->query_count; x++) {
            memset(pl_query->query_array[x].string, '\0',
                    (sizeof(char) * MAX_SQL_QUERY_LENGTH));
            pl_query->query_array[x].valid = 0;
        }

        pl_query->query_count = 0;
    }

    if (pl_query->query_count_data) {
        for (x = 0; x < pl_query->query_count_data; x++) {
            memset(pl_query->query_array_data[x].string, '\0',
                    (sizeof(char) * MAX_SQL_QUERY_LENGTH_DATA));
            pl_query->query_array_data[x].valid = 0;
        }

        pl_query->query_count_data = 0;
    }

    if (pl_query->query_count_ad_data) {
        for (x = 0; x < pl_query->query_count_ad_data; x++) {
            memset(pl_query->query_array_ad_data[x].string, '\0',
                    (sizeof(char) * MAX_SQL_QUERY_LENGTH_DATA));
            pl_query->query_array_ad_data[x].valid = 0;
        }

        pl_query->query_count_ad_data = 0;
    }

	return 0;
}

/* SQLQueryList Funcs */

/*******************************************************************************
 * Function: SetupDatabase()
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
void DatabaseSetup(void) {
	/* link the preprocessor keyword to the init function in
	 the preproc list */

	/* CHECKME: -elz I think it should also support OUTPUT_TYPE_FLAG__LOG.. */
	RegisterOutputPlugin("database", OUTPUT_TYPE_FLAG__ALERT, DatabaseInit);

	DEBUG_WRAP(DebugMessage(DEBUG_INIT, "database(debug): database plugin is registered...\n"););
}

void dbEventQueueClean(uint8_t q_ins)
{
    spo_db_event_queue[q_ins]->ele_cnt = 0;
    spo_db_event_queue[q_ins]->ele_exp_cnt = 0;

    //Set free flag from input_rings
    if ( NULL != spo_db_event_queue[q_ins]->ele_rtOct ) {
        spo_db_event_queue[q_ins]->ele_rtOct->r_flag = 0;
        spo_db_event_queue[q_ins]->ele_rtOct = NULL;
    }

//    spo_db_event_queue[q_ins]->qe_switch = 0;
    /*  memset(spo_db_event_queue->event_id_1_cnt,
                0, sizeof(spo_db_event_queue->event_id_1_cnt));*/
}

/*
#ifndef DB_CHECK_TABLES
#define DB_CHECK_TABLES 7
#endif // DB_CHECK_TABLES

#ifndef DB_TABLE_NAME_LEN
#define DB_TABLE_NAME_LEN 20
#endif*/ /* DB_TABLE_NAME_LEN */

/* 
 * Since it is possible that an error occured and that we could have an event_id out of sync
 * or that a human/automated action could have cleaned the database but missed some old data
 * we query every table where cid for this sid(sensor_id) is present and get the latest (cid) 
 * incident_id possible to start the process.
 */
u_int32_t SynchronizeEventId(DatabaseData *data)
{
	if (data == NULL) {
		/* XXX */
		return 1;
	}

	if (GetLastCid(data)) {
		//return 1;
	}

	GetLastCidFromTable(data);

	if (UpdateLastCid(data, 1, 1, SPO_DB_DEF_INS) < 0) {
		FatalError("database Unable to construct query - output error or truncation\n");
	}

/*	if (GetLastCid(data, data->sid, (u_int32_t *) &c_cid)) {
		return 1;
	}

	if (c_cid != data->cid) {
		FatalError(
				"database [%s()]: Something is wrong with the sensor table, you "
						"might have two process updating it...bailing\n",
				__FUNCTION__);
	}*/

	return 0;
}

void DatabasePluginPrintData(DatabaseData *data) {
	/* print out and test the capability of this plugin */
	{
		char database_support_buf[100];
		char database_in_use_buf[100];

		database_support_buf[0] = '\0';
		database_in_use_buf[0] = '\0';

		/* These strings will not overflow the buffers */
#ifdef ENABLE_MYSQL
		snprintf(database_support_buf, sizeof(database_support_buf),
				"database: compiled support for (%s)", KEYWORD_MYSQL);
		if (data->dbtype_id == DB_MYSQL)
			snprintf(database_in_use_buf, sizeof(database_in_use_buf),
					"database: configured to use %s", KEYWORD_MYSQL);
#endif
#ifdef ENABLE_POSTGRESQL
		snprintf(database_support_buf, sizeof(database_support_buf),
				"database: compiled support for (%s)", KEYWORD_POSTGRESQL);
		if (data->dbtype_id == DB_POSTGRESQL)
		snprintf(database_in_use_buf, sizeof(database_in_use_buf),
				"database: configured to use %s", KEYWORD_POSTGRESQL);
#endif
#ifdef ENABLE_ODBC
		snprintf(database_support_buf, sizeof(database_support_buf),
				"database: compiled support for (%s)", KEYWORD_ODBC);
		if (data->dbtype_id == DB_ODBC)
		snprintf(database_in_use_buf, sizeof(database_in_use_buf),
				"database: configured to use %s", KEYWORD_ODBC);
#endif
#ifdef ENABLE_ORACLE
		snprintf(database_support_buf, sizeof(database_support_buf),
				"database: compiled support for (%s)", KEYWORD_ORACLE);
		if (data->dbtype_id == DB_ORACLE)
		snprintf(database_in_use_buf, sizeof(database_in_use_buf),
				"database: configured to use %s", KEYWORD_ORACLE);
#endif
#ifdef ENABLE_MSSQL
		snprintf(database_support_buf, sizeof(database_support_buf),
				"database: compiled support for (%s)", KEYWORD_MSSQL);
		if (data->dbtype_id == DB_MSSQL)
		snprintf(database_in_use_buf, sizeof(database_in_use_buf),
				"database: configured to use %s", KEYWORD_MSSQL);
#endif
		LogMessage("%s\n", database_support_buf);
		LogMessage("%s\n", database_in_use_buf);
	}

	LogMessage("database: schema version = %d\n", data->DBschema_version);

	if (data->host != NULL)
		LogMessage("database:           host = %s\n", data->host);

	if (data->port != NULL)
		LogMessage("database:           port = %s\n", data->port);

	if (data->user != NULL)
		LogMessage("database:           user = %s\n", data->user);

	if (data->dbname != NULL)
		LogMessage("database:  database name = %s\n", data->dbname);

	if (data->sensor_name != NULL)
		LogMessage("database:    sensor name = %s\n", data->sensor_name);

	LogMessage("database:      sensor id = %u\n", data->sid);

	LogMessage("database:     sensor cid[0] = %u\n", data->cid[0]);

	if (data->encoding == ENCODING_HEX) {
		LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_HEX);
	} else if (data->encoding == ENCODING_BASE64) {
		LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_BASE64);
	} else {
		LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_ASCII);
	}

	if (data->detail == DETAIL_FULL) {
		LogMessage("database:   detail level = %s\n", KEYWORD_DETAIL_FULL);
	} else {
		LogMessage("database:   detail level = %s\n", KEYWORD_DETAIL_FAST);
	}

	if (data->ignore_bpf) {
		LogMessage("database:     ignore_bpf = %s\n", KEYWORD_IGNOREBPF_YES);
	} else {
		LogMessage("database:     ignore_bpf = %s\n", KEYWORD_IGNOREBPF_NO);
	}

#ifdef ENABLE_MYSQL
	if (data->dbRH[data->dbtype_id].ssl_key != NULL)
		LogMessage("database:        ssl_key = %s\n",
				data->dbRH[data->dbtype_id].ssl_key);

	if (data->dbRH[data->dbtype_id].ssl_cert != NULL)
		LogMessage("database:       ssl_cert = %s\n",
				data->dbRH[data->dbtype_id].ssl_cert);

	if (data->dbRH[data->dbtype_id].ssl_ca != NULL)
		LogMessage("database:         ssl_ca = %s\n",
				data->dbRH[data->dbtype_id].ssl_ca);

	if (data->dbRH[data->dbtype_id].ssl_ca_path != NULL)
		LogMessage("database:    ssl_ca_path = %s\n",
				data->dbRH[data->dbtype_id].ssl_ca_path);

	if (data->dbRH[data->dbtype_id].ssl_cipher != NULL)
		LogMessage("database:     ssl_cipher = %s\n",
				data->dbRH[data->dbtype_id].ssl_cipher);
#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
	if (data->dbRH[data->dbtype_id].ssl_mode != NULL)
	LogMessage("database:       ssl_mode = %s\n", data->dbRH[data->dbtype_id].ssl_mode);
#endif /* ENABLE_POSTGRESQL */

	if (data->facility != NULL) {
		LogMessage("database: using the \"%s\" facility\n", data->facility);
	}

	return;
}

/*******************************************************************************
 * Function: DatabaseInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 ******************************************************************************/
void DatabaseInit(char *args)
{
    uint8_t i;
	DatabaseData *data = NULL;

	/* parse the argument list from the rules file */
	data = InitDatabaseData(args);

	data->tz = GetLocalTimezone();

	ParseDatabaseArgs(data);

	/* Meanwhile */
	data->dbRH[data->dbtype_id].dbdata = data;
	/* Meanwhile */

	switch (data->dbtype_id) {
#ifdef ENABLE_MYSQL
	case DB_MYSQL:
		data->dbRH[data->dbtype_id].dbConnectionStatus =
				dbConnectionStatusMYSQL;
		//data->dbRH[data->dbtype_id].dbConnectionCount = 0;
		break;
#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
		case DB_POSTGRESQL:
		data->dbRH[data->dbtype_id].dbConnectionStatus = dbConnectionStatusPOSTGRESQL;
		data->dbRH[data->dbtype_id].dbConnectionCount = 0;
		break;
#endif /* ENABLE_POSTGRESQL */

#ifdef ENABLE_ODBC
		case DB_ODBC:
		data->dbRH[data->dbtype_id].dbConnectionStatus = dbConnectionStatusODBC;
		data->dbRH[data->dbtype_id].dbConnectionCount = 0;
		break;
#endif 	/* ENABLE ODBC */

#ifdef ENABLE_ORACLE
#ifdef ENABLE_MSSQL
		case DB_MSSQL:
		case DB_ORACLE:

		FatalError("database The database family you want to use is currently not supported by this build \n");
		break;
#endif 	/* ENABLE MSSQL */
#endif 	/* ENABLE ORACLE */

	default:
		FatalError("database Unknown database type defined: [%lu] \n",
				data->dbtype_id);
		break;
	}

	/* Add the processor function into the function list */
	if (strncasecmp(data->facility, "log", 3) == 0) {
		AddFuncToOutputList(Spo_Database, OUTPUT_TYPE__LOG, data);
	} else {
		AddFuncToOutputList(Spo_Database, OUTPUT_TYPE__ALERT, data);
	}

	AddFuncToOutputList(Spo_Database, OUTPUT_TYPE__FLUSH, data);

	AddFuncToRestartList(SpoDatabaseCleanExitFunction, data);
	AddFuncToCleanExitList(SpoDatabaseCleanExitFunction, data);
	AddFuncToPostConfigList(DatabaseInitFinalize, data);

	/* Set the size of the buffers here */
	data->SQL_INSERT_SIZE = (MAX_QUERY_LENGTH * sizeof(char));
	data->SQL_SELECT_SIZE = (MAX_QUERY_LENGTH * sizeof(char));

	for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
	    if ((data->SQL_INSERT[i] = malloc(data->SQL_INSERT_SIZE)) == NULL) {
	        /* XXX */
	        FatalError(
	                "database [%s()], unable to allocate SQL_INSERT memory, bailing \n",
	                __FUNCTION__);
	    }

	    if ((data->SQL_SELECT[i] = malloc(data->SQL_SELECT_SIZE)) == NULL) {
	        /* XXX */
	        FatalError(
	                "database [%s()], unable to allocate SQL_SELECT memory, bailing \n",
	                __FUNCTION__);

	    }

	    DatabaseCleanSelect(data, i);
	    DatabaseCleanInsert(data, i);
	}

	return;
}

u_int32_t DatabasePluginInitializeSensor(DatabaseData *data)
{
    int i;
	u_int32_t retval = 0;
	char * escapedSensorName = NULL;
	char * escapedInterfaceName = NULL;
	char * escapedBPFFilter = NULL;

	if (data == NULL) {
		/* XXX */
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

	escapedSensorName = snort_escape_string(data->sensor_name, data);
	escapedInterfaceName = snort_escape_string(
			PRINT_INTERFACE(barnyard2_conf->interface), data);

    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
        if (data->ignore_bpf == 0) {
            if (barnyard2_conf->bpf_filter == NULL) {
                DatabaseCleanInsert(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_INSERT[SPO_DB_DEF_INS], data->SQL_INSERT_SIZE,
                        "INSERT INTO sensor (sid, hostname, interface, bid, detail, encoding, last_cid, last_mcid) "
                                "VALUES (%u,'%s','%s',%u,%u,%u, 0, 0);", 1, escapedSensorName,
                        escapedInterfaceName, i, data->detail, data->encoding))
                        != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }

                DatabaseCleanSelect(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], data->SQL_SELECT_SIZE,
                        "SELECT sid "
                                "  FROM sensor "
                                " WHERE hostname = '%s' "
                                "   AND interface = '%s' "
                                "   AND bid = %u "
                                "   AND detail = %u "
                                "   AND encoding = %u "
                                "   AND filter IS NULL", escapedSensorName,
                        escapedInterfaceName, i, data->detail, data->encoding))
                        != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }
            } else {
                escapedBPFFilter = snort_escape_string(barnyard2_conf->bpf_filter,
                        data);

                DatabaseCleanInsert(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_INSERT[SPO_DB_DEF_INS], data->SQL_INSERT_SIZE,
                        "INSERT INTO sensor (sid,hostname, interface, bid, filter, detail, encoding, last_cid, last_mcid) "
                                "VALUES (%u,'%s','%s',%u,'%s',%u,%u, 0, 0);",
                        1, escapedSensorName, escapedInterfaceName, i, escapedBPFFilter,
                        data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS) {
                    retval = 1;
                    goto exit_funct;
                }

                DatabaseCleanSelect(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], data->SQL_SELECT_SIZE,
                        "SELECT sid "
                                "  FROM sensor "
                                " WHERE hostname = '%s' "
                                "   AND interface = '%s' "
                                "   AND bid = %u "
                                "   AND filter ='%s' "
                                "   AND detail = %u "
                                "   AND encoding = %u ", escapedSensorName,
                        escapedInterfaceName, i, escapedBPFFilter, data->detail,
                        data->encoding)) != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }
            }
        }
        else /* ( data->ignore_bpf == 1 ) */
        {
            if (barnyard2_conf->bpf_filter == NULL) {
                DatabaseCleanInsert(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_INSERT[SPO_DB_DEF_INS], data->SQL_INSERT_SIZE,
                        "INSERT INTO sensor (sid,hostname, interface, bid, detail, encoding, last_cid, last_mcid) "
                                "VALUES (%u,'%s','%s',%u,%u,%u, 0, 0);", escapedSensorName,
                        1, escapedInterfaceName, i, data->detail, data->encoding))
                        != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }

                DatabaseCleanSelect(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], data->SQL_SELECT_SIZE,
                        "SELECT sid "
                                "  FROM sensor "
                                " WHERE hostname = '%s' "
                                "   AND interface = '%s' "
                                "   AND bid = %u "
                                "   AND detail = %u "
                                "   AND encoding = %u", escapedSensorName,
                        escapedInterfaceName, i, data->detail, data->encoding))
                        != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }
            } else {
                escapedBPFFilter = snort_escape_string(barnyard2_conf->bpf_filter,
                        data);

                DatabaseCleanInsert(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_INSERT[SPO_DB_DEF_INS], data->SQL_INSERT_SIZE,
                        "INSERT INTO sensor (sid,hostname, interface, bid, filter, detail, encoding, last_cid, last_mcid) "
                                "VALUES (%u,'%s','%s',%u,'%s',%u,%u, 0, 0);",
                        1, escapedSensorName, escapedInterfaceName, i, escapedBPFFilter,
                        data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }

                DatabaseCleanSelect(data, SPO_DB_DEF_INS);
                if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], data->SQL_SELECT_SIZE,
                        "SELECT sid "
                                "  FROM sensor "
                                " WHERE hostname = '%s' "
                                "   AND interface = '%s' "
                                "   AND bid = %u "
                                "   AND detail = %u "
                                "   AND encoding = %u", escapedSensorName,
                        escapedInterfaceName, i, data->detail, data->encoding))
                        != SNORT_SNPRINTF_SUCCESS) {
                    /* XXX */
                    retval = 1;
                    goto exit_funct;
                }
            }
        }

        /* No check here */
        Select(data->SQL_SELECT[SPO_DB_DEF_INS], data, (u_int32_t *) &data->sid, SPO_DB_DEF_INS);

        if (data->sid == 0) {
            if (BeginTransaction(data, SPO_DB_DEF_INS)) {
                /* XXX */
                FatalError(
                        "database [%s()]: Failed to Initialize transaction, bailing ... \n",
                        __FUNCTION__);
            }

            if (Insert(data->SQL_INSERT[SPO_DB_DEF_INS], data, 1, SPO_DB_DEF_INS)) {
                /* XXX */
                FatalError("database Error inserting [%s] \n", data->SQL_INSERT[SPO_DB_DEF_INS]);
            }

            if (CommitTransaction(data, SPO_DB_DEF_INS)) {
                /* XXX */
                ErrorMessage(
                        "ERROR database: [%s()]: Error commiting transaction \n",
                        __FUNCTION__);

                setTransactionCallFail(&data->m_dbins[SPO_DB_DEF_INS]);
                retval = 1;
                goto exit_funct;
            } else {
                resetTransactionState(&data->m_dbins[SPO_DB_DEF_INS]);
            }

            if (Select(data->SQL_SELECT[SPO_DB_DEF_INS], data, (u_int32_t *) &data->sid, SPO_DB_DEF_INS)) {
                /* XXX */
                FatalError("database Error Executing [%s] \n", data->SQL_SELECT[SPO_DB_DEF_INS]);
            }

            if (data->sid == 0) {
                ErrorMessage(
                        "ERROR database: Problem obtaining SENSOR ID (sid) from %s->sensor\n",
                        data->dbname);
                FatalError("%s\n%s\n", FATAL_NO_SENSOR_1, FATAL_NO_SENSOR_2);
            }
        }
    }


exit_funct:
    if (escapedSensorName != NULL) {
		free(escapedSensorName);
		escapedSensorName = NULL;
	}
	if (escapedInterfaceName != NULL) {
		free(escapedInterfaceName);
		escapedInterfaceName = NULL;
	}

	if (escapedBPFFilter != NULL) {
		free(escapedBPFFilter);
		escapedBPFFilter = NULL;
	}

	return retval;
}

void DatabaseInitFinalize(int unused, void *arg)
{
    uint8_t i;
	DatabaseData *data = (DatabaseData *) arg;

	if ((data == NULL)) {
		FatalError("database data uninitialized\n");
	}

    for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
        Connect(data, i);
    }

	if ((ConvertDefaultCache(barnyard2_conf, data))) {
		/* XXX */
		FatalError("database [%s()], ConvertDefaultCache() Failed \n",
				__FUNCTION__);
	}

	/* Get the versioning information for the DB schema */
	if ((CheckDBVersion(data))) {
		/* XXX */
		FatalError("database problems with schema version, bailing...\n");
	}

	if ((DatabasePluginInitializeSensor(data))) {
		FatalError("database Unable to initialize sensor \n");
	}

	if (SynchronizeEventId(data)) {
		FatalError(
				"database Encountered an error while trying to synchronize event_id, this is serious and we can't go any further, please investigate \n");
	}

	if (CacheSynchronize(data)) {
		/* XXX */
		FatalError("database [%s()]: CacheSynchronize() call failed ...\n",
				__FUNCTION__);
		return;
	}

	DatabasePluginPrintData(data);

	SQL_Initialize(data);

	return;
}

/*******************************************************************************
 * Function: InitDatabaseData(char *)
 *
 * Purpose: Initialize the data structure for connecting to
 *          this database.
 *
 * Arguments: args => argument list
 *
 * Returns: Pointer to database structure
 *
 ******************************************************************************/
DatabaseData *InitDatabaseData(char *args) {
	DatabaseData *data;

	data = (DatabaseData *) SnortAlloc(sizeof(DatabaseData));

	if (args == NULL) {
		ErrorMessage(
				"ERROR database: you must supply arguments for database plugin\n");
		SPO_PrintUsage();
		FatalError("");
	}

	data->args = SnortStrdup(args);

	return data;
}

/*******************************************************************************
 * Function: ParseDatabaseArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and
 *          initialize the preprocessor's data struct.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 ******************************************************************************/
void ParseDatabaseArgs(DatabaseData *data) {
	char *dbarg;
	char *a1;
	char *type;
	char *facility;

	if (data->args == NULL) {
		ErrorMessage(
				"ERROR database: you must supply arguments for database plugin\n");
		SPO_PrintUsage();
		FatalError("");
	}

	data->dbtype_id = DB_UNDEFINED;
	data->sensor_name = NULL;
	data->facility = NULL;
	data->encoding = ENCODING_HEX;
	data->detail = DETAIL_FULL;
	data->ignore_bpf = 0;
	data->use_ssl = 0;

	facility = strtok(data->args, ", ");
	if (facility != NULL) {
		if ((!strncasecmp(facility, "log", 3))
				|| (!strncasecmp(facility, "alert", 5)))
			data->facility = facility;
		else {
			ErrorMessage(
					"ERROR database: The first argument needs to be the logging facility\n");
			SPO_PrintUsage();
			FatalError("");
		}
	} else {
		ErrorMessage("ERROR database: Invalid format for first argment\n");
		SPO_PrintUsage();
		FatalError("");
	}

	type = strtok(NULL, ", ");

	if (type == NULL) {
		ErrorMessage(
				"ERROR database: you must enter the database type in configuration "
						"file as the second argument\n");
		SPO_PrintUsage();
		FatalError("");
	}

#ifdef ENABLE_MYSQL
	if (!strncasecmp(type, KEYWORD_MYSQL, strlen(KEYWORD_MYSQL)))
		data->dbtype_id = DB_MYSQL;
#endif
#ifdef ENABLE_POSTGRESQL
	if(!strncasecmp(type,KEYWORD_POSTGRESQL,strlen(KEYWORD_POSTGRESQL)))
	data->dbtype_id = DB_POSTGRESQL;
#endif
#ifdef ENABLE_ODBC
	if(!strncasecmp(type,KEYWORD_ODBC,strlen(KEYWORD_ODBC)))
	data->dbtype_id = DB_ODBC;
#endif
#ifdef ENABLE_ORACLE
	if(!strncasecmp(type,KEYWORD_ORACLE,strlen(KEYWORD_ORACLE)))
	data->dbtype_id = DB_ORACLE;
#endif
#ifdef ENABLE_MSSQL
	if(!strncasecmp(type,KEYWORD_MSSQL,strlen(KEYWORD_MSSQL)))
	data->dbtype_id = DB_MSSQL;
#endif

	if (data->dbtype_id == 0) {
		if (!strncasecmp(type, KEYWORD_MYSQL, strlen(KEYWORD_MYSQL))
				|| !strncasecmp(type, KEYWORD_POSTGRESQL,
						strlen(KEYWORD_POSTGRESQL))
				|| !strncasecmp(type, KEYWORD_ODBC, strlen(KEYWORD_ODBC))
				|| !strncasecmp(type, KEYWORD_MSSQL, strlen(KEYWORD_MSSQL))
				|| !strncasecmp(type, KEYWORD_ORACLE, strlen(KEYWORD_ORACLE))) {
			ErrorMessage(
					"ERROR database: '%s' support is not compiled into this build of barnyard2\n\n",
					type);
			FatalError(FATAL_NO_SUPPORT_1, type, type, type,
					FATAL_NO_SUPPORT_2);
		} else {
			FatalError(
					"database '%s' is an unknown database type.  The supported\n"
							"          databases include: MySQL (mysql), PostgreSQL (postgresql),\n"
							"          ODBC (odbc), Oracle (oracle), and Microsoft SQL Server (mssql)\n",
					type);
		}
	}

	dbarg = strtok(NULL, " =");
	while (dbarg != NULL) {
		a1 = NULL;
		a1 = strtok(NULL, ", ");

		if (!strncasecmp(dbarg, KEYWORD_HOST, strlen(KEYWORD_HOST))) {
			data->host = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_PORT, strlen(KEYWORD_PORT))) {
			data->port = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_USER, strlen(KEYWORD_USER))) {
			data->user = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_PASSWORD, strlen(KEYWORD_PASSWORD))) {
			data->password = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_DBNAME, strlen(KEYWORD_DBNAME))) {
			data->dbname = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_SENSORNAME,
				strlen(KEYWORD_SENSORNAME))) {
			data->sensor_name = a1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_ENCODING, strlen(KEYWORD_ENCODING))) {
			if (!strncasecmp(a1, KEYWORD_ENCODING_HEX,
					strlen(KEYWORD_ENCODING_HEX))) {
				data->encoding = ENCODING_HEX;
			} else if (!strncasecmp(a1, KEYWORD_ENCODING_BASE64,
					strlen(KEYWORD_ENCODING_BASE64))) {
				data->encoding = ENCODING_BASE64;
			} else if (!strncasecmp(a1, KEYWORD_ENCODING_ASCII,
					strlen(KEYWORD_ENCODING_ASCII))) {
				data->encoding = ENCODING_ASCII;
			} else {
				FatalError("database unknown  (%s)", a1);
			}
		}
		else if (!strncasecmp(dbarg, KEYWORD_DETAIL, strlen(KEYWORD_DETAIL))) {
			if (!strncasecmp(a1, KEYWORD_DETAIL_FULL,
					strlen(KEYWORD_DETAIL_FULL))) {
				data->detail = DETAIL_FULL;
			} else if (!strncasecmp(a1, KEYWORD_DETAIL_FAST,
					strlen(KEYWORD_DETAIL_FAST))) {
				data->detail = DETAIL_FAST;
			} else {
				FatalError("database unknown detail level (%s)", a1);
			}
		}
		else if (!strncasecmp(dbarg, KEYWORD_IGNOREBPF, strlen(KEYWORD_IGNOREBPF))) {
			if (!strncasecmp(a1, KEYWORD_IGNOREBPF_NO,
					strlen(KEYWORD_IGNOREBPF_NO))
					|| !strncasecmp(a1, KEYWORD_IGNOREBPF_ZERO,
							strlen(KEYWORD_IGNOREBPF_ZERO))) {
				data->ignore_bpf = 0;
			} else if (!strncasecmp(a1, KEYWORD_IGNOREBPF_YES,
					strlen(KEYWORD_IGNOREBPF_YES))
					|| !strncasecmp(a1, KEYWORD_IGNOREBPF_ONE,
							strlen(KEYWORD_IGNOREBPF_ONE))) {
				data->ignore_bpf = 1;
			} else {
				FatalError("database unknown ignore_bpf argument (%s)", a1);
			}

		}
		else if (!strncasecmp(dbarg, KEYWORD_CONNECTION_LIMIT,
				strlen(KEYWORD_CONNECTION_LIMIT))) {
			data->dbRH[data->dbtype_id].dbConnectionLimit = strtoul(a1, NULL,
					10);

			/* Might make a different option for it but for now lets consider
			 the threshold being the same as connectionlimit. */
			data->dbRH[data->dbtype_id].transactionErrorThreshold =
					data->dbRH[data->dbtype_id].dbConnectionLimit;

		}
		else if (!strncasecmp(dbarg, KEYWORD_RECONNECT_SLEEP_TIME,
				strlen(KEYWORD_RECONNECT_SLEEP_TIME))) {
			data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec = strtoul(
					a1, NULL, 10);
		}
		else if (!strncasecmp(dbarg, KEYWORD_DISABLE_SIGREFTABLE,
				strlen(KEYWORD_DISABLE_SIGREFTABLE))) {
			data->dbRH[data->dbtype_id].disablesigref = 1;
		}

#ifdef ENABLE_MYSQL
		/* Option declared here should be forced to dbRH[DB_MYSQL] */

		/* the if/elseif check order is important because the keywords for the */
		/* ca and ca_path are very similar */
		else if (!strncasecmp(dbarg, KEYWORD_SSL_KEY, strlen(KEYWORD_SSL_KEY))) {
			data->dbRH[DB_MYSQL].ssl_key = a1;
			data->use_ssl = 1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_SSL_CERT,
				strlen(KEYWORD_SSL_CERT))) {
			data->dbRH[DB_MYSQL].ssl_cert = a1;
			data->use_ssl = 1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_SSL_CA_PATH,
				strlen(KEYWORD_SSL_CA_PATH))) {
			data->dbRH[DB_MYSQL].ssl_ca_path = a1;
			data->use_ssl = 1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_SSL_CA,
				strlen(KEYWORD_SSL_CA))) {
			data->dbRH[DB_MYSQL].ssl_ca = a1;
			data->use_ssl = 1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_SSL_CIPHER,
				strlen(KEYWORD_SSL_CIPHER))) {
			data->dbRH[DB_MYSQL].ssl_key = a1;
			data->use_ssl = 1;
		}
		else if (!strncasecmp(dbarg, KEYWORD_MYSQL_RECONNECT,
				strlen(KEYWORD_MYSQL_RECONNECT))) {
		    LogMessage("Set MYSQL reconnect OK\n");
			data->dbRH[DB_MYSQL].mysql_reconnect = 1;
		}
#endif
		else if (!strncasecmp(dbarg, "cpuset", 6)) {
		    if ( 1 == sscanf(a1, "%lx", &data->cpuset_bm) ) {
		        LogMessage("Set MYSQL query threads cpuset: 0x%lx\n", data->cpuset_bm);
		    }
		}

#ifdef ENABLE_POSTGRESQL
		if(!strncasecmp(dbarg, KEYWORD_SSL_MODE, strlen(KEYWORD_SSL_MODE)))
		{
			if ( (!strncasecmp(a1, KEYWORD_SSL_MODE_DISABLE, strlen(KEYWORD_SSL_MODE_DISABLE))) ||
					(!strncasecmp(a1, KEYWORD_SSL_MODE_ALLOW, strlen(KEYWORD_SSL_MODE_ALLOW))) ||
					(!strncasecmp(a1, KEYWORD_SSL_MODE_PREFER, strlen(KEYWORD_SSL_MODE_PREFER))) ||
					(!strncasecmp(a1, KEYWORD_SSL_MODE_REQUIRE, strlen(KEYWORD_SSL_MODE_REQUIRE))) )
			{
				data->dbRH[data->dbtype_id].ssl_mode = a1;
				data->use_ssl = 1;
			}
			else
			{
				ErrorMessage("ERROR database: unknown ssl_mode argument (%s)", a1);
			}
		}
#endif

		dbarg = strtok(NULL, "=");
	}

	if (data->dbtype_id == DB_ODBC) {
		/* Print Transaction Warning */
		if (data->dbname == NULL) {
			ErrorMessage(
					"database: no DSN was specified, unable to try to initialize ODBC connection. (use [dbname] parameter, in configuration file to set DSN)\n");
			FatalError("");
		} else {
			LogMessage(
					"database: will use DSN [%s] for ODBC Connection setup \n",
					data->dbname);
		}

		if (data->host != NULL) {
			ErrorMessage(
					"database: [host] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
					data->host, data->dbname);
		}

		if (data->user != NULL) {
			ErrorMessage(
					"database: [user] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
					data->user, data->dbname);
		}

		if (data->port != NULL) {
			ErrorMessage(
					"database: [port] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
					data->port, data->dbname);
		}
	} else {
		if (data->dbname == NULL) {
			ErrorMessage(
					"ERROR database: must enter database name in configuration file\n\n");
			SPO_PrintUsage();
			FatalError("");
		} else if (data->host == NULL) {
			ErrorMessage(
					"ERROR database: must enter host in configuration file\n\n");
			SPO_PrintUsage();
			FatalError("");
		}
	}

	if (data->dbRH[data->dbtype_id].dbConnectionLimit == 0) {
		LogMessage(
				"INFO database: Defaulting Reconnect/Transaction Error limit to 10 \n");
		data->dbRH[data->dbtype_id].dbConnectionLimit = 10;

		/* Might make a different option for it but for now lets consider
		 the threshold being the same as connectionlimit. */
		data->dbRH[data->dbtype_id].transactionErrorThreshold =
				data->dbRH[data->dbtype_id].dbConnectionLimit;
	}

	if (data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec == 0) {
		LogMessage(
				"INFO database: Defaulting Reconnect sleep time to 5 second \n");
		data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec = 5;
	}

	return;
}

/*
 ** This function will either insert a "new" signature, present in file and not in db and update
 ** the cache information (db_sig_id) or update an existing signature using its db_sig_id.
 **
 */
u_int32_t dbSignatureInformationUpdate(DatabaseData *data,
		cacheSignatureObj *iUpdateSig, uint8_t q_sock)
{
	u_int32_t db_sig_id = 0;
	uint8_t isupdate = 0;

	if ((data == NULL) || (iUpdateSig == NULL)) {
		return 1;
	}

//	DatabaseCleanSelect(data, q_sock);
	DatabaseCleanInsert(data, q_sock);

/*	if (SnortSnprintf(data->SQL_SELECT[q_sock], data->SQL_SELECT_SIZE,
	SQL_SELECT_SPECIFIC_SIGNATURE, iUpdateSig->obj.sid, iUpdateSig->obj.gid,
			iUpdateSig->obj.rev, iUpdateSig->obj.class_id,
			iUpdateSig->obj.priority_id, iUpdateSig->obj.message)) {
		LogMessage(
				"ERROR database: calling SnortSnprintf() on data->SQL_SELECT in [%s()] \n",
				__FUNCTION__);
		return 1;
	}*/

	if ( iUpdateSig->flag & CACHE_DATABASE ) {
	    isupdate = 1;
		if (SnortSnprintf(data->SQL_INSERT[q_sock], data->SQL_INSERT_SIZE,
		SQL_UPDATE_SPECIFIC_SIGNATURE, iUpdateSig->obj.class_id,
				iUpdateSig->obj.priority_id, iUpdateSig->obj.rev,
				iUpdateSig->obj.db_id)) {
			LogMessage(
					"ERROR database: calling SnortSnprintf() on data->SQL_INSERT in [%s()] \n",
					__FUNCTION__);
			return 1;
		}
	} else {
		if (SnortSnprintf(data->SQL_INSERT[q_sock], data->SQL_INSERT_SIZE,
		SQL_INSERT_SIGNATURE, iUpdateSig->obj.sid, iUpdateSig->obj.gid,
				iUpdateSig->obj.rev, iUpdateSig->obj.class_id,
				iUpdateSig->obj.priority_id, iUpdateSig->obj.message)) {
			LogMessage(
					"ERROR database: calling SnortSnprintf() on data->SQL_INSERT in [%s()] \n",
					__FUNCTION__);
			return 1;
		}
	}

#if DEBUG
	DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()] Issuing signature update [%s]\n",
					__FUNCTION__,
					data->SQL_INSERT));
#endif

	if (Insert(data->SQL_INSERT[q_sock], data, 1, q_sock)) {
		LogMessage("ERROR database: calling Insert() in [%s()] \n",
				__FUNCTION__);
		return 1;
	}

/*	if (Select(data->SQL_SELECT, data, (u_int32_t *) &db_sig_id)) {
		LogMessage("ERROR database: calling Select() in [%s()] \n",
				__FUNCTION__);
		return 1;
	}*/

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
#ifdef ENABLE_MYSQL
	    db_sig_id = mysql_insert_id(data->m_dbins[q_sock].m_sock);
#endif
	    LogMessage("%s: Last query(insert) auto_increament id %d\n", __func__, db_sig_id);

        iUpdateSig->flag |= CACHE_DATABASE;
        iUpdateSig->obj.db_id = db_sig_id;
	}

	return 0;
}

/* NOTE: -elz this function need to be broken up.. */
int dbProcessSignatureInformation(DatabaseData *data, void *event,
		/*u_int32_t event_type, */u_int32_t *psig_id, uint8_t q_sock) {
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

	if ((data == NULL) || (event == NULL) || (psig_id == NULL)) {
		return 1;
	}

	memset(&unInitSig, '\0', sizeof(cacheSignatureObj));

	*psig_id = 0;
	sid = ntohl(((Unified2EventCommon *) event)->signature_id);
	gid = ntohl(((Unified2EventCommon *) event)->generator_id);
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
				*psig_id = psigObj->db_id;
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

			if ((dbSignatureInformationUpdate(data, &unInitSig, q_sock))) {
				LogMessage(
						"[%s()] Line[%u], call to dbSignatureInformationUpdate failed for : \n"
								"[gid :%u] [sid: %u] [upd_rev: %u] [upd class: %u] [upd pri %u]\n",
						__FUNCTION__,
						__LINE__, gid, sid, revision, db_classification_id,
						priority);
				return 1;
			}

			assert(unInitSig.obj.db_id != 0);
			*psig_id = unInitSig.obj.db_id;
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
/*			LogMessage(
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
/*			LogMessage(
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
//		if (SignaturePopulateDatabase(data, data->mc.cacheSignatureHead, 1, q_sock)) {
		if ((dbSignatureInformationUpdate(data, pcacheSig, q_sock))) {
			LogMessage("[%s()]: ERROR inserting new signature \n",
					__FUNCTION__);
			goto func_err;
		}
	}
/*	else {
		LogMessage("%s: is in database\n", __func__);
		if ( NULL == (pcacheSig=SignatureCacheInsertObj(&sigInsertObj, &data->mc, 1)) ) {
			LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
					__FUNCTION__);
			goto func_err;
		}
	}*/

	/* Added for bugcheck */
/*	assert(data->mc.cacheSignatureHead->obj.db_id != 0);
	*psig_id = data->mc.cacheSignatureHead->obj.db_id;*/

    assert(pcacheSig->obj.db_id != 0);
    *psig_id = pcacheSig->obj.db_id;

	return 0;

func_err:
    return 1;
}

int dbProcessEventInformation(DatabaseData *data, Packet *p, void *event,
		u_int32_t event_type, u_int32_t i_sig_id) {
	char *SQLQueryPtr = NULL;
	int i = 0;

	if ((data == NULL) || (p == NULL) || (event == NULL)) {
		/* XXX */
		/* Mabey move to debug... */
		LogMessage(
				"[%s()]: Bailing, Invoked with DatabaseData *[0x%x] Packet *[0x%x] Event(void) *[0x%x] \n",
				__FUNCTION__, data, p, event);
		return 1;
	}

	/*
	 CHECKME: -elz We need to get this logic sorted out since event shouldn't be null
	 theorically and event time should be priorized
	 */
	/* Generate a default-formatted timestamp now */
	memset(data->timestampHolder, '\0', SMALLBUFFER);

	if (event != NULL) {
		if ((GetTimestampByComponent_STATIC(
				ntohl(((Unified2EventCommon *) event)->event_second),
				ntohl(((Unified2EventCommon *) event)->event_microsecond),
				data->tz, data->timestampHolder))) {
			/* XXX */
			return 1;
		}
	} else if (p != NULL) {
		if ((GetTimestampByStruct_STATIC((struct timeval *) &p->pkth->ts,
				data->tz, data->timestampHolder))) {
			/* XXX */
			return 1;
		}
	} else {
		if (GetCurrentTimestamp_STATIC(data->timestampHolder)) {
			/* XXX */
			return 1;
		}
	}

	/* Some timestring comments comments */
	/* SQL Server uses a date format which is slightly
	 * different from the ISO-8601 standard generated
	 * by GetTimestamp() and GetCurrentTimestamp().  We
	 * need to convert from the ISO-8601 format of:
	 *   "1998-01-25 23:59:59+14316557"
	 * to the SQL Server format of:
	 *   "1998-01-25 23:59:59.143"
	 */

	/* Oracle (everything before 9i) does not support
	 * date information smaller than 1 second.
	 * To go along with the TO_DATE() Oracle function
	 * below, this was written to strip out all the
	 * excess information. (everything beyond a second)
	 * Use the Oracle format of:
	 *   "1998-01-25 23:59:59"
	 */
	/* MySql does not support date information smaller than
	 * 1 second.  This was written to strip out all the
	 * excess information. (everything beyond a second)
	 * Use the MySql format of:
	 *   "2005-12-23 22:37:16"
	 */
	/* ODBC defines escape sequences for date data.
	 * These escape sequences are of the format:
	 *   {literal-type 'value'}
	 * The Timestamp (ts) escape sequence handles
	 * date/time values of the format:
	 *   yyyy-mm-dd hh:mm:ss[.f...]
	 * where the number of digits to the right of the
	 * decimal point in a time or timestamp interval
	 * literal containing a seconds component is
	 * dependent on the seconds precision, as contained
	 * in the SQL_DESC_PRECISION descriptor field. (For
	 * more information, see function SQLSetDescField.)
	 *
	 * The number of decimal places within the fraction
	 * of a second is database dependant.  I wasn't able
	 * to easily determine the granularity of this
	 * value using SQL_DESC_PRECISION, so choosing to
	 * simply discard the fractional part.
	 */
	/* From Posgres Documentation
	 * For timestamp with time zone, the internally stored
	 * value is always in UTC (GMT). An input value that has
	 * an explicit time zone specified is converted to UTC
	 * using the appropriate offset for that time zone. If no
	 * time zone is stated in the input string, then it is assumed
	 * to be in the time zone indicated by the system's TimeZone
	 * parameter, and is converted to UTC using the offset for
	 * the TimeZone zone
	 */
	/* Some timestring comments comments */

	/*
	 COMMENT: -elz
	 The new schema will log timestamp in UTC,
	 no need for resolve time to be logged as a string literal,
	 this should be handled by UI's.
	 */
	if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
		goto bad_query;
	}

	switch (data->dbtype_id) {

	case DB_MSSQL:
	case DB_MYSQL:
	case DB_ORACLE:
	case DB_ODBC:
		if (strlen(data->timestampHolder) > 20) {
			data->timestampHolder[19] = '\0';
		}
		break;

	case DB_POSTGRESQL:
	default:

		if (strlen(data->timestampHolder) > 24) {
			data->timestampHolder[23] = '\0';
		}

		break;
	}

	switch (data->dbtype_id) {
	case DB_ORACLE:
		if ((data->DBschema_version >= 105)) {
			if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
					"INSERT INTO "
							"event (sid,cid,signature,timestamp) "
							"VALUES (%u, %u, %u, TO_DATE('%s', 'YYYY-MM-DD HH24:MI:SS'));",
					data->sid, data->cid[0], i_sig_id, data->timestampHolder))
					!= SNORT_SNPRINTF_SUCCESS) {
				goto bad_query;
			}
		} else {
			/*
			 COMMENT: -elz
			 I just hate useless duplication and this
			 dosent break anything so just go down please
			 */
			goto GenericEVENTQUERYJMP;

		}
		break;

		/* -elz: ODBC with {ts ....} string for timestamp!? nha...
		 if( (SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
		 "INSERT INTO "
		 "event (sid,cid,signature,timestamp) "
		 "VALUES (%u, %u, %u, {ts '%s'})",
		 data->sid,
		 data->cid,
		 i_sig_id,
		 data->timestampHolder)) != SNORT_SNPRINTF_SUCCESS)
		 {
		 goto bad_query;
		 }
		 break;
		 */

	case DB_MSSQL:
	case DB_MYSQL:
	case DB_POSTGRESQL:
	case DB_ODBC:
	default:
		GenericEVENTQUERYJMP: if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
				"INSERT INTO "
						"event (sid,cid,signature,timestamp) "
						"VALUES (%u, %u, %u, '%s');", data->sid, data->cid[0],
				i_sig_id, data->timestampHolder)) != SNORT_SNPRINTF_SUCCESS) {
			goto bad_query;
		}
		break;
	}

	/* We do not log fragments! They are assumed to be handled
	 by the fragment reassembly pre-processor */

	if (p != NULL) {
		if ((!p->frag_flag) && (IPH_IS_VALID(p))) {
			switch (GET_IPH_PROTO(p)) {
			case IPPROTO_ICMP:
				/* IPPROTO_ICMP */
				if (p->icmph) {
					if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
						goto bad_query;
					}

					/*** Build a query for the ICMP Header ***/
					if (data->detail) {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"icmphdr (sid, cid, icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq) "
										"VALUES (%u,%u,%u,%u,%u,%u,%u);",
								data->sid, data->cid[0], p->icmph->type,
								p->icmph->code, ntohs(p->icmph->csum),
								ntohs(p->icmph->s_icmp_id),
								ntohs(p->icmph->s_icmp_seq)))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					} else {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"icmphdr (sid, cid, icmp_type, icmp_code) "
										"VALUES (%u,%u,%u,%u);", data->sid,
								data->cid[0], p->icmph->type, p->icmph->code))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					}

				} else {

					DEBUG_WRAP(DebugMessage(DB_DEBUG,
									"[%s()], unable to build query, IP header tell's us its an ICMP packet but "
									"there is not ICMP header in the decoded packet ... \n",
									__FUNCTION__));
				}
				break;
				/* IPPROTO_ICMP */

				/* IPPROTO_TCP */
			case IPPROTO_TCP:

				if (p->tcph) {
					if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
						goto bad_query;
					}

					/*** Build a query for the TCP Header ***/
					if (data->detail) {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"tcphdr (sid, cid, tcp_sport, tcp_dport, "
										"tcp_seq, tcp_ack, tcp_off, tcp_res, "
										"tcp_flags, tcp_win, tcp_csum, tcp_urp) "
										"VALUES (%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u);",
								data->sid, data->cid[0], ntohs(p->tcph->th_sport),
								ntohs(p->tcph->th_dport),
								(u_long) ntohl(p->tcph->th_seq),
								(u_long) ntohl(p->tcph->th_ack),
								TCP_OFFSET(p->tcph), TCP_X2(p->tcph),
								p->tcph->th_flags, ntohs(p->tcph->th_win),
								ntohs(p->tcph->th_sum), ntohs(p->tcph->th_urp)))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					} else {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"tcphdr (sid,cid,tcp_sport,tcp_dport,tcp_flags) "
										"VALUES (%u,%u,%u,%u,%u);", data->sid,
								data->cid[0], ntohs(p->tcph->th_sport),
								ntohs(p->tcph->th_dport), p->tcph->th_flags))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					}

					if (data->detail) {
						/*** Build the query for TCP Options ***/
						for (i = 0; i < (int) (p->tcp_option_count); i++) {

							if ((&p->tcp_options[i])
									&& (p->tcp_options[i].len > 0)) {
								if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string)
										== NULL) {
									goto bad_query;
								}

								if ((data->encoding == ENCODING_HEX)
										|| (data->encoding == ENCODING_ASCII)) {
									//packet_data = fasthex(p->tcp_options[i].data, p->tcp_options[i].len);
									if (fasthex_STATIC(p->tcp_options[i].data,
											p->tcp_options[i].len,
											data->PacketData[0])) {
										/* XXX */
										goto bad_query;
									}
								} else {
									//packet_data = base64(p->tcp_options[i].data, p->tcp_options[i].len);
									if (base64_STATIC(p->tcp_options[i].data,
											p->tcp_options[i].len,
											data->PacketData[0])) {
										/* XXX */
										goto bad_query;
									}
								}

								if (data->dbtype_id == DB_ORACLE) {
									/* Oracle field BLOB type case. We append unescaped
									 * opt_data data after query, which later in Insert()
									 * will be cut off and uploaded with OCIBindByPos().
									 */
									if ((SnortSnprintf(SQLQueryPtr,
											MAX_SQL_QUERY_LENGTH,
											"INSERT INTO "
													"opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
													"VALUES (%u,%u,%u,%u,%u,%u,:1);|%s",
											data->sid, data->cid[0], i, 6,
											p->tcp_options[i].code,
											p->tcp_options[i].len,
											//packet_data))  != SNORT_SNPRINTF_SUCCESS)
											data->PacketData[0]))
											!= SNORT_SNPRINTF_SUCCESS) {
										goto bad_query;
									}
								} else {
									if ((SnortSnprintf(SQLQueryPtr,
											MAX_SQL_QUERY_LENGTH,
											"INSERT INTO "
													"opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
													"VALUES (%u,%u,%u,%u,%u,%u,'%s');",
											data->sid, data->cid[0], i, 6,
											p->tcp_options[i].code,
											p->tcp_options[i].len,
											//packet_data))  != SNORT_SNPRINTF_SUCCESS)
											data->PacketData[0]))
											!= SNORT_SNPRINTF_SUCCESS) {
										goto bad_query;
									}
								}
							}
						}
					}
				} else {
					DEBUG_WRAP(DebugMessage(DB_DEBUG,
									"[%s()], unable to build query, IP header tell's us its an TCP  packet but "
									"there is not TCP header in the decoded packet ... \n",
									__FUNCTION__));
				}

				break;
				/* IPPROTO_TCP */

				/* IPPROTO_UDP */
			case IPPROTO_UDP:

				if (p->udph) {
					/*** Build the query for the UDP Header ***/
					if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
						goto bad_query;
					}

					if (data->detail) {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"udphdr (sid, cid, udp_sport, udp_dport, udp_len, udp_csum) "
										"VALUES (%u, %u, %u, %u, %u, %u);",
								data->sid, data->cid[0], ntohs(p->udph->uh_sport),
								ntohs(p->udph->uh_dport),
								ntohs(p->udph->uh_len), ntohs(p->udph->uh_chk)))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					} else {
						if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
								"INSERT INTO "
										"udphdr (sid, cid, udp_sport, udp_dport) "
										"VALUES (%u, %u, %u, %u);", data->sid,
								data->cid[0], ntohs(p->udph->uh_sport),
								ntohs(p->udph->uh_dport)))
								!= SNORT_SNPRINTF_SUCCESS) {
							goto bad_query;
						}
					}
				} else {
					DEBUG_WRAP(DebugMessage(DB_DEBUG,
									"[%s()], unable to build query, IP header tell's us its an UDP packet but "
									"there is not UDP header in the decoded packet ... \n",
									__FUNCTION__));
				}
				break;
				/* IPPROTO_UDP */

				/* DEFAULT */
			default:
				/* Do nothing ... */
				break;
				/* DEFAULT */
			}

			/*** Build the query for the IP Header ***/
			if (p->iph) {

				if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
					goto bad_query;
				}

				if (data->detail) {
					if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
							"INSERT INTO "
									"iphdr (sid, cid, ip_src, ip_dst, ip_ver, ip_hlen, "
									"ip_tos, ip_len, ip_id, ip_flags, ip_off,"
									"ip_ttl, ip_proto, ip_csum) "
									"VALUES (%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u);",
							data->sid, data->cid[0],
							(u_long) ntohl(p->iph->ip_src.s_addr),
							(u_long) ntohl(p->iph->ip_dst.s_addr),
							IP_VER(p->iph), IP_HLEN(p->iph), p->iph->ip_tos,
							ntohs(p->iph->ip_len), ntohs(p->iph->ip_id),
							p->frag_flag, ntohs(p->frag_offset), p->iph->ip_ttl,
							p->iph->ip_proto, ntohs(p->iph->ip_csum)))
							!= SNORT_SNPRINTF_SUCCESS) {
						goto bad_query;
					}
				} else {
					if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH,
							"INSERT INTO "
									"iphdr (sid, cid, ip_src, ip_dst, ip_proto) "
									"VALUES (%u,%u,%lu,%lu,%u);", data->sid,
							data->cid[0], (u_long) ntohl(p->iph->ip_src.s_addr),
							(u_long) ntohl(p->iph->ip_dst.s_addr),
							GET_IPH_PROTO(p))) != SNORT_SNPRINTF_SUCCESS) {
						goto bad_query;
					}
				}

				/*** Build querys for the IP Options ***/
				if (data->detail) {
					for (i = 0; i < (int) (p->ip_option_count); i++) {
						if ((&p->ip_options[i]) && (p->ip_options[i].len > 0)) {
							if ((SQLQueryPtr = SQL_GetNextQuery(data, 0)->string) == NULL) {
								goto bad_query;
							}

							if ((data->encoding == ENCODING_HEX)
									|| (data->encoding == ENCODING_ASCII)) {
								//packet_data = fasthex(p->ip_options[i].data, p->ip_options[i].len);
								if (fasthex_STATIC(p->ip_options[i].data,
										p->ip_options[i].len,
										data->PacketData[0])) {
									/* XXX */
									goto bad_query;
								}
							} else {
								//packet_data = base64(p->ip_options[i].data, p->ip_options[i].len);
								if (base64_STATIC(p->ip_options[i].data,
										p->ip_options[i].len,
										data->PacketData[0])) {
									/* XXX */
									goto bad_query;
								}

							}

							if (data->dbtype_id == DB_ORACLE) {
								/* Oracle field BLOB type case. We append unescaped
								 * opt_data data after query, which later in Insert()
								 * will be cut off and uploaded with OCIBindByPos().
								 */
								if ((SnortSnprintf(SQLQueryPtr,
										MAX_SQL_QUERY_LENGTH,
										"INSERT INTO "
												"opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
												"VALUES (%u,%u,%u,%u,%u,%u,:1);|%s",
										data->sid, data->cid[0], i, 0,
										p->ip_options[i].code,
										p->ip_options[i].len,
										//packet_data))  != SNORT_SNPRINTF_SUCCESS)
										data->PacketData[0]))
										!= SNORT_SNPRINTF_SUCCESS) {
									goto bad_query;
								}
							} else {
								if ((SnortSnprintf(SQLQueryPtr,
										MAX_SQL_QUERY_LENGTH,
										"INSERT INTO "
												"opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
												"VALUES (%u,%u,%u,%u,%u,%u,'%s');",
										data->sid, data->cid[0], i, 0,
										p->ip_options[i].code,
										p->ip_options[i].len,
										//packet_data))  != SNORT_SNPRINTF_SUCCESS)
										data->PacketData[0]))
										!= SNORT_SNPRINTF_SUCCESS) {
									goto bad_query;
								}
							}
						}
					}
				}
			}

			/*** Build query for the payload ***/
			if (p->data) {
				if (data->detail) {
					if (p->dsize) {
						if ((SQLQueryPtr = SQL_GetNextQueryData(data, 0)->string) == NULL) {
							goto bad_query;
						}

						if (data->encoding == ENCODING_BASE64) {
							//packet_data_not_escaped = base64(p->data, p->dsize);
							if (base64_STATIC(p->data, p->dsize,
									data->PacketDataNotEscaped[0])) {
								/* XXX */
								goto bad_query;
							}
						} else if (data->encoding == ENCODING_ASCII) {
							//packet_data_not_escaped = ascii(p->data, p->dsize);
							if (ascii_STATIC(p->data, p->dsize,
									data->PacketDataNotEscaped[0])) {
								/* XXX */
								goto bad_query;
							}

						} else {
							//packet_data_not_escaped = fasthex(p->data, p->dsize);
							if ((fasthex_STATIC(p->data, p->dsize,
									data->PacketDataNotEscaped[0]))) {
								/* XXX */
								goto bad_query;
							}

						}

						//packet_data = snort_escape_string(packet_data_not_escaped, data);
						if (snort_escape_string_STATIC(data->PacketDataNotEscaped[0], data->sanitize_buffer[0],
								strlen(data->PacketDataNotEscaped[0]) + 1, data)) {
							/* XXX */
							goto bad_query;
						}

						switch (data->dbtype_id) {

						case DB_ORACLE:

							/* Oracle field BLOB type case. We append unescaped
							 * packet_payload data after query, which later in Insert()
							 * will be cut off and uploaded with OCIBindByPos().
							 */
							if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH_DATA,
									"INSERT INTO "
											"data (sid,cid,data_payload) "
											"VALUES (%u,%u,:1);|%s", data->sid,
									data->cid[0],
									//packet_data_not_escaped))  != SNORT_SNPRINTF_SUCCESS)
									data->PacketDataNotEscaped[0]))
									!= SNORT_SNPRINTF_SUCCESS) {
								goto bad_query;
							}
							break;

						default:
							if ((SnortSnprintf(SQLQueryPtr, MAX_SQL_QUERY_LENGTH_DATA,
									"INSERT INTO "
											"data (sid,cid,data_payload) "
											"VALUES (%u,%u,'%s');", data->sid,
									data->cid[0],
									//packet_data))  != SNORT_SNPRINTF_SUCCESS)
									data->sanitize_buffer[0]))
									!= SNORT_SNPRINTF_SUCCESS) {
								goto bad_query;
							}
							break;
						}
					}
				}
			}
		}
	}

	return 0;

	bad_query:

	setTransactionCallFail(&data->m_dbins[SPO_DB_DEF_INS]);
	return 1;

}

uint8_t dbProcessTspInfo(DatabaseData *data, SQLEventQueue *e_queue, uint8_t ele_que_ins)
{
    char sl_separator;
    uint8_t rid;
    uint16_t i;
    uint16_t ins_cnt = 0;
    Packet *p;
    SQLQueryEle *SQLQuery;
    char *SQLQueryPtr = NULL;
    char sl_buf[256];
    us_cid_t event_id;

    if ((SQLQuery = SQL_GetNextQuery(data, ele_que_ins)) == NULL) {
        return 1;
    }

    SQLQueryPtr = SQLQuery->string;

    if ( !dbEventInfoFm_tsp(SQLQueryPtr, MAX_SQL_QUERY_LENGTH) )
        return 1;

    SQL_EVENT_FOR_EACH(e_queue, i, p, rid)
        if ( !dbEventInfoFm_tspdata(data, sl_buf, sizeof(sl_buf),
                data->sid, rid, event_id, &(e_queue->ele[i]), sl_separator) )
            return 1;
        ins_cnt++;
        //data->cid[rid] = event_id;
    SQL_EVENT_FOR_EACH_END(SQLQueryPtr, sl_buf, MAX_SQL_QUERY_LENGTH)

    if ( 0 == ins_cnt )
        SQLQuery->valid = 0;
    else
        strncat(SQLQueryPtr, ";", MAX_SQL_QUERY_LENGTH);

    return 0;
//bad_query:
    return 1;
}

int dbProcessMultiEventInfo(DatabaseData *data, SQLEventQueue *e_queue, uint8_t ele_que_ins)
{
	Packet *p;
	SQLPkt *ad_pkt;
	char *SQLQueryPtr = NULL;
	SQLQueryEle *ProtoICMPPtr = NULL;
	SQLQueryEle *ProtoTCPtr = NULL;
	SQLQueryEle *ProtoUDPPtr = NULL;
	SQLQueryEle *SQLQuery = NULL;
	us_cid_t event_id;
	uint8_t ret;
	uint8_t rid;
	uint16_t i;
    uint16_t ins_cnt;
	char sl_separator;
	char sl_buf[256];
	char *sl_buf_data;

	if ( NULL == data ) {
		LogMessage(
				"[%s()]: Bailing, Invoked with DatabaseData *[0x%x]\n",
				__FUNCTION__, data);
		return 0;
	}

	SQL_EVENT_QUEUE_VALID(e_queue, ret);
	if ( !ret ) {
		LogMessage(
				"[%s()]: Bailing, Invoked with DatabaseData ele_cnt[%u], ele_exp_cnt[%u], invalid queue\n",
				__FUNCTION__, e_queue->ele_cnt, e_queue->ele_exp_cnt);
		return 0;
	}

	DEBUG_U_WRAP(LogMessage("%s: proceed, detail %d\n", __func__, data->detail));

	memset(sl_buf, 0, sizeof(sl_buf));

    /*** Build query for the additional packet ***/
	if ( 0 < e_queue->ele_exp_cnt ) {
	    sl_buf_data = e_queue->ele_pktbuf;

	    if ((SQLQuery = SQL_GetNextQueryAdData(data, ele_que_ins)) == NULL) {
	        LogMessage("%s: bad_query hmmm\n", __func__);
	        goto bad_query;
	    }

		SQLQuery->slen = 0;

	    if ( !dbEventInfoFm_raw(SQLQuery->string, MAX_SQL_QUERY_LENGTH) )
	        goto bad_query;

	    SQLQuery->slen += strlen(SQLQuery->string);

	    SQL_ADP_FOR_EACH(e_queue, i, ad_pkt, rid)
	        DEBUG_U_WRAP_DEEP(LogMessage("%s: ad_p event_id %d, ad_eid %d, r_data_len %d \n", __func__,
	                data->ms_cid, ad_pkt->event_id, ad_pkt->u2raw_datalen));
	        if ( !dbEventInfoFm_rawdata(data, sl_buf_data, SQL_PKT_BUF_LEN,/*sizeof(sl_buf_data),*/
	                data->sid, rid, ad_pkt->event_id, ad_pkt, sl_separator, ele_que_ins) )
	            goto bad_query;
	    SQL_ADP_FOR_EACH_END(SQLQuery, sl_buf_data, ad_pkt->u2raw_esc_len)
	}
    /*** Build query for the additional packet End ***/

	if ( 0 == e_queue->ele_cnt ) {
		LogMessage("%s: event queue is empty, packet queue: %d \n",
				__func__, e_queue->ele_exp_cnt);
		return 1;
	}

	/* Generate a default-formatted timestamp now */
	dbProcessTspInfo(data, e_queue, ele_que_ins);

/*	if (NULL == p)
		return 0;

	 We do not log fragments! They are assumed to be handled
	 by the fragment reassembly pre-processor
	if ( (p->frag_flag) || (!IPH_IS_VALID(p)) || (NULL==p->data) || (!p->dsize) )
		return 0;*/

	SQLQuery = NULL;
	SQL_EVENT_FOR_EACH_PRO(e_queue, i, p, rid)
	switch (GET_IPH_PROTO(p)) {
	case IPPROTO_ICMP:
		if (NULL == p->icmph) {
			DEBUG_WRAP(DebugMessage(DB_DEBUG,
					"[%s()], unable to build query, IP header tell's us its an ICMP packet but "
					"there is not ICMP header in the decoded packet ... \n",
					__FUNCTION__));
			break;
		}

		/*** Build a query for the ICMP Header ***/
		if ( NULL == ProtoICMPPtr ) {
			if ((ProtoICMPPtr = SQL_GetNextQuery(data, ele_que_ins)) == NULL) {
				goto bad_query;
			}

			if ( !dbEventInfoFm_icmp(ProtoICMPPtr->string, MAX_SQL_QUERY_LENGTH, data->detail) )
				goto bad_query;

		    sl_separator = ' ';
		}
		else {
	        sl_separator = ',';
		}

		SQLQueryPtr = ProtoICMPPtr->string;
		if ( !dbEventInfoFm_icmpdata(sl_buf, sizeof(sl_buf),
				data->sid, rid, event_id, p, sl_separator, data->detail) )
			goto bad_query;
		break;
	case IPPROTO_TCP:
		if ( NULL == p->tcph ) {
			DEBUG_WRAP(DebugMessage(DB_DEBUG,
							"[%s()], unable to build query, IP header tell's us its an TCP  packet but "
							"there is not TCP header in the decoded packet ... \n",
							__FUNCTION__));
			break;
		}

		/*** Build a query for the TCP Header ***/
		if ( NULL == ProtoTCPtr ) {
			if ((ProtoTCPtr = SQL_GetNextQuery(data, ele_que_ins)) == NULL) {
				goto bad_query;
			}

			if ( !dbEventInfoFm_tcp(ProtoTCPtr->string, MAX_SQL_QUERY_LENGTH, data->detail) )
				goto bad_query;

		    sl_separator = ' ';
		}
        else {
            sl_separator = ',';
        }

		SQLQueryPtr = ProtoTCPtr->string;
		if ( !dbEventInfoFm_tcpdata(sl_buf, sizeof(sl_buf),
				data->sid, rid, event_id, p, sl_separator, data->detail) )
			goto bad_query;

		if (!data->detail) {
		    //No query for TCP Option
		    break;
		}

		/*** Build the query for TCP Options ***/
		if ( NULL == SQLQuery ) {
			if ( NULL == (SQLQuery=SQL_GetNextQuery(data, ele_que_ins)) ) {
				goto bad_query;
			}

			if ( !dbEventInfoFm_tcpopt(SQLQuery->string, MAX_SQL_QUERY_LENGTH) )
				goto bad_query;

			SQLQuery->valid = 0;	//There may be not any option data
		}

		if (0 == SQLQuery->valid) {
			sl_separator = ' ';
		}
		else {
		    sl_separator = ',';
		}

		if ( !dbEventInfoFm_tcpoptdata(data, SQLQuery, MAX_SQL_QUERY_LENGTH,
				data->sid, rid, event_id, p, sl_separator, ele_que_ins) )
			goto bad_query;
		break;
	case IPPROTO_UDP:
		if ( NULL == p->udph ) {
			DEBUG_WRAP(DebugMessage(DB_DEBUG,
							"[%s()], unable to build query, IP header tell's us its an UDP packet but "
							"there is not UDP header in the decoded packet ... \n",
							__FUNCTION__));
			break;
		}

		/*** Build the query for the UDP Header ***/
		if ( NULL == ProtoUDPPtr ) {
			if ((ProtoUDPPtr = SQL_GetNextQuery(data, ele_que_ins)) == NULL) {
				goto bad_query;
			}

			if ( !dbEventInfoFm_udp(ProtoUDPPtr->string, MAX_SQL_QUERY_LENGTH, data->detail) )
				goto bad_query;

			sl_separator = ' ';
		}
        else {
            sl_separator = ',';
        }

		SQLQueryPtr = ProtoUDPPtr->string;
		if ( !dbEventInfoFm_udpdata(sl_buf, sizeof(sl_buf),
				data->sid, rid, event_id, p, sl_separator, data->detail) )
			goto bad_query;
		break;
	default:
		break;
	}
	SQL_EVENT_FOR_EACH_PRO_END(SQLQueryPtr, sl_buf, MAX_SQL_QUERY_LENGTH)

	if ( NULL != ProtoICMPPtr )
	    strncat(ProtoICMPPtr->string, ";", MAX_SQL_QUERY_LENGTH);
    if ( NULL != ProtoTCPtr )
        strncat(ProtoTCPtr->string, ";", MAX_SQL_QUERY_LENGTH);
    if ( NULL != ProtoUDPPtr )
        strncat(ProtoUDPPtr->string, ";", MAX_SQL_QUERY_LENGTH);
    if ( NULL != SQLQuery ) {
        if ( SQLQuery->valid )
            strncat(SQLQuery->string, ";", MAX_SQL_QUERY_LENGTH);
    }

	/*** Build the query for the IP Header ***/
	if ((SQLQuery = SQL_GetNextQuery(data, ele_que_ins)) == NULL) {
		goto bad_query;
	}

	SQLQueryPtr = SQLQuery->string;
	if ( !dbEventInfoFm_ip(SQLQueryPtr, MAX_SQL_QUERY_LENGTH, data->detail) )
		goto bad_query;

	ins_cnt = 0;
	SQL_EVENT_FOR_EACH(e_queue, i, p, rid)
		if ( !dbEventInfoFm_ipdata(sl_buf, sizeof(sl_buf),
				data->sid, rid, event_id, p, sl_separator, data->detail) )
			goto bad_query;
	    ins_cnt++;
	SQL_EVENT_FOR_EACH_END(SQLQueryPtr, sl_buf, MAX_SQL_QUERY_LENGTH)

    if ( 0 == ins_cnt )
        SQLQuery->valid = 0;
    else
        strncat(SQLQueryPtr, ";", MAX_SQL_QUERY_LENGTH);

	/*** If is detailed ***/
	if (!data->detail) {
		//data->cid += e_queue->ele_cnt;
		return 1;
	}

	/*** Build querys for the IP Options ***/
	if ( NULL == (SQLQuery=SQL_GetNextQuery(data, ele_que_ins)) ) {
		goto bad_query;
	}

	if ( !dbEventInfoFm_ipopt(SQLQuery->string,MAX_SQL_QUERY_LENGTH) )
		goto bad_query;

	SQLQuery->valid = 0;	//There may be not any option data

	SQL_EVENT_FOR_EACH(e_queue, i, p, rid)
		if ( !dbEventInfoFm_ipoptdata(data, SQLQuery, MAX_SQL_QUERY_LENGTH,
				data->sid, rid, event_id, p, sl_separator, ele_que_ins) )
			goto bad_query;
	SQL_EVENT_FOR_EC_END(SQLQuery->valid)
	strncat(SQLQuery->string, ";", MAX_SQL_QUERY_LENGTH);

	/*** Build query for the packet ***/
/*	if ((SQLQueryPtr = SQL_GetNextQueryData(data)->string) == NULL) {
		goto bad_query;
	}

	if ( !dbEventInfoFm_payload(SQLQueryPtr, MAX_SQL_QUERY_LENGTH) )
		goto bad_query;

	SQL_EVENT_FOR_EACH(e_queue, sl_i, p)
		if ( !dbEventInfoFm_payloaddata(data, sl_buf_data, sizeof(sl_buf_data),
				data->sid, data->cid+sl_i, p, sl_separator) )
			goto bad_query;
	SQL_EVENT_FOR_EACH_END(SQLQueryPtr, sl_buf_data, MAX_SQL_QUERY_LENGTH_DATA)*/

	//data->cid += e_queue->ele_cnt;
    /*for (i=0; i<e_queue->ele_cnt; i++) {
        data->cid[e_queue->ele[i].rid]++;
    }*/
	return 1;

bad_query:
    LogMessage("%s: bad_query, ele_queue %d\n", __func__, ele_que_ins);
//    setTransactionCallFail(&data->m_dbins[SPO_DB_DEF_INS]);
    return 0;
}

int Spo_ProcQuery_QinsCheckAll(DatabaseData *spo_data)
{
    int ret;

    pthread_mutex_lock(&spo_data->lquery_lock);
    if ( spo_data->sql_q_bitmap ) {
        ret = 1;
    }
    else {
        ret = 0;
    }
    pthread_mutex_unlock(&spo_data->lquery_lock);

    return ret;
}

int Spo_ProcQuery_GetQins(DatabaseData *spo_data, const uint8_t ins_base)
{
    uint8_t i, q_ins_bit;
    int q_ins = -1;

    pthread_mutex_lock(&spo_data->lquery_lock);
/*    DEBUG_U_WRAP_SP_QUERY(LogMessage("%s: bitmap 0x%x, base queue [%d]\n",
            __func__, spo_data->sql_q_bitmap, ins_base));*/
    for ( i=0; i<SQL_ELEQUE_INS_MAX; i++ ) {
        q_ins_bit = (ins_base+i) & (SQL_ELEQUE_INS_MAX-1);
        if ( !(spo_data->sql_q_bitmap & (0x01<<q_ins_bit)) ) {
            q_ins = q_ins_bit;
            spo_data->sql_q_bitmap |= (0x01<<q_ins_bit);
            break;
        }
    }
    pthread_mutex_unlock(&spo_data->lquery_lock);

    return q_ins;
}

void Spo_ProcQuery_PutQins(DatabaseData *spo_data, uint8_t q_ins)
{
    pthread_mutex_lock(&spo_data->lquery_lock);
    spo_data->sql_q_bitmap &= ~(0x01<<q_ins);
    pthread_mutex_unlock(&spo_data->lquery_lock);
}

#ifdef IF_SPO_QUERY_IN_THREAD
void *Spo_ProcQuery(void *arg)
#else
void Spo_ProcQuery(void *arg)
#endif
{
    uint8_t q_retry;
    uint8_t ele_que_ins = 0, lQ_ins;
    char c;
    uint16_t i;
    u_int32_t sig_id;
    int n;//, ret;
    int qe2qr_r, qr2qe_w;
    lquery_state lq_stat;
    u_int32_t itr = 0;
    u_int32_t SQLMaxQuery = 0;
    SQLQueryEle *CurrentQuery = NULL;
    DatabaseIns *lDB_ins = (DatabaseIns*)arg;
    DatabaseData *spo_data = (DatabaseData*)lDB_ins->spo_data;
    SQLEventQueue *lQ_queue;
    SQLEvent *lQ_ele;
    us_cid_t tsp_up_cid[BY_MUL_TR_DEFAULT];
/*    struct timespec t_elapse;

    t_elapse.tv_sec = 0;
    t_elapse.tv_nsec = 10;*/
    lQ_ins = lDB_ins->q_sock_idx;
    ele_que_ins = lQ_ins;
    lQ_queue = spo_db_event_queue[ele_que_ins];

    //Proceed
    qe2qr_r = spo_data->lEleQue_ins[ele_que_ins].pipe_queue2query[0];
    qr2qe_w = spo_data->lEleQue_ins[ele_que_ins].pipe_query2queue[1];

#ifdef IF_SPO_QUERY_IN_THREAD
    while ( 1 ) //spo_data->lquery_ins[ele_que_ins].ql_switch
#endif
    {
        //Get ele_que_ins first
/*        DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: GetNextQins, base queue [%d]\n", __func__, lQ_ins, ele_que_ins));
        if ( (ret=Spo_ProcQuery_GetQins(spo_data, ele_que_ins)) < 0 ) {
            DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: sleep in queue [%d]\n", __func__, lQ_ins, ele_que_ins));
            nanosleep(&t_elapse, NULL);
            continue;
        }
        ele_que_ins = (uint8_t)ret;*/

        DEBUG_U_WRAP_DEEP(LogMessage("%s_%d: wait [%d]\n", __func__, lQ_ins, ele_que_ins));

        /* wait action from queue */
        do {
            DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: waiting queue[%d]\n", __func__, lQ_ins, ele_que_ins));
            n = read(qe2qr_r, &c, 1);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            LogMessage("%s: read_queue2query[%d] failed", __func__, ele_que_ins);
            perror("cannot read on queue2query pipe\n");
            /*Spo_ProcQuery_PutQins(spo_data, ele_que_ins);
            ele_que_ins = SQL_ELEQUE_INS_PLUS_ONE(ele_que_ins);*/
#ifdef IF_SPO_QUERY_IN_THREAD
            continue;
#else
            return;
#endif
        }

        if ( 0 == c ) {
            DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: read from queue[%d]: empty\n", __func__, lQ_ins, ele_que_ins));
            /*Spo_ProcQuery_PutQins(spo_data, ele_que_ins);
            ele_que_ins = SQL_ELEQUE_INS_PLUS_ONE(ele_que_ins);*/
#ifdef IF_SPO_QUERY_IN_THREAD
            continue;
#else
            return;
#endif
        }

        lq_stat = spo_data->lEleQue_ins[ele_que_ins].lq_stat;
        DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: queue[%d] stat: %d\n", __func__, lQ_ins, ele_que_ins, lq_stat));

        switch ( lq_stat ) {
        case LQ_PRE_SIG_ID:
            {
                //Check and fix sig_id
                DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: ele_cnt %d, ele_exp_cnt %d\n", __func__, lQ_ins,
                        lQ_queue->ele_cnt, lQ_queue->ele_exp_cnt));
                memset(tsp_up_cid, 0, sizeof(tsp_up_cid));
                pthread_mutex_lock(&spo_data->lsiginfo_lock);
                for (i=0; i<lQ_queue->ele_cnt; i++) {
                    lQ_ele = &(lQ_queue->ele[i]);
                    if (dbProcessSignatureInformation(spo_data,
                            lQ_ele->event, &sig_id, lQ_ins)) {
                        setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
                        FatalError("[dbProcessSignatureInformation()]: Failed, stopping processing \n");
                    }
                    lQ_ele->i_sig_id = sig_id;
                    tsp_up_cid[lQ_ele->rid] = lQ_ele->event_id;
                }
                for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
                    if ( tsp_up_cid[i] > spo_data->cid[i] ) {
                        DEBUG_U_WRAP_SP_QUERY(LogMessage("%s, queue: %d, update cid[%d]: %d\n", __func__,
                                ele_que_ins, i, tsp_up_cid[i]));
                        spo_data->cid[i] = tsp_up_cid[i];
                    }
                }
                pthread_mutex_unlock(&spo_data->lsiginfo_lock);

                /* send ack to queue */
                n = 0;
                while (n == 0 || (n < 0 && errno == EINTR)) {
                    DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: write2queue [%d] sig_id\n", __func__, lQ_ins, ele_que_ins));
                    n = write(qr2qe_w, &c, 1);
                }
                if (n < 0) {
                    LogMessage("%s: write2queue[%d] failed", __func__, ele_que_ins);
                    perror("cannot write on query2queue pipe\n");
                }

                /*Spo_ProcQuery_PutQins(spo_data, ele_que_ins);
                ele_que_ins = SQL_ELEQUE_INS_PLUS_ONE(ele_que_ins);*/
                DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: sig_id done, process next queue [%d]\n",
                        __func__, lQ_ins, ele_que_ins));
            }
            break;
        case LQ_TRANS_QUERY:
            {
                /* This has been refactored to simplify the workflow of the function
                 * We separate the legacy signature entry code and the event entry code
                 */

                DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: BeginTransection [%d]\n", __func__, lQ_ins, ele_que_ins));
                if (BeginTransaction(spo_data, lQ_ins)) {
                    FatalError("database [%s()]: Failed to Initialize transaction, bailing ... \n",
                            __FUNCTION__);
                }

#define Q_RETRY_TIME		64

                //Event
                if ((SQLMaxQuery = SQL_GetMaxQuery(spo_data, ele_que_ins))) {
                    itr = 0;
                    for (itr = 0; itr < SQLMaxQuery; itr++) {
                        if ((CurrentQuery = SQL_GetQueryByPos(spo_data, ele_que_ins, itr)) == NULL) {
                            goto bad_query;
                        }

                        if ( !CurrentQuery->valid )
                            continue;

                        DEBUG_U_WRAP_DEEP(LogMessage("%s: insert query %d, %s\n", __func__, itr, CurrentQuery->string));

                        q_retry = Q_RETRY_TIME;
                        while ( Insert(CurrentQuery->string, spo_data, 1, lQ_ins) ) {
                            ErrorMessage("[%s()]: Insertion of Query [%s] failed\n",
                                    __FUNCTION__, CurrentQuery->string);

                            if ( (Q_RETRY_TIME>>1) == q_retry ) {
                                sleep(1);
                                CommitTransaction(spo_data, lQ_ins);
                                Disconnect(spo_data, lQ_ins);
                                sleep(1);
                                Connect(spo_data, lQ_ins);
                                BeginTransaction(spo_data, lQ_ins);
                            }
                            else if ( 0 == q_retry ) {
                                setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
                                goto bad_query;
                            }

                            q_retry--;
                            sleep(1);
                        }
                    }
                }

                //Event Packet
                if ((SQLMaxQuery = SQL_GetMaxQueryData(spo_data, ele_que_ins))) {
                    itr = 0;
                    for (itr = 0; itr < SQLMaxQuery; itr++) {
                        if ((CurrentQuery = SQL_GetQueryDataByPos(spo_data, ele_que_ins, itr)) == NULL) {
                            goto bad_query;
                        }

                        if ( !CurrentQuery->valid )
                            continue;

                        DEBUG_U_WRAP_DEEP(LogMessage("%s: insert query data %d\n", __func__, itr));

                        q_retry = Q_RETRY_TIME;
                        while ( Insert(CurrentQuery->string, spo_data, 1, lQ_ins) ) {
                            ErrorMessage("[%s()]: Insertion of Query [%s] failed\n",
                                    __FUNCTION__, CurrentQuery->string);

                            if ( (Q_RETRY_TIME>>1) == q_retry ) {
                                sleep(1);
                                CommitTransaction(spo_data, lQ_ins);
                                Disconnect(spo_data, lQ_ins);
                                sleep(1);
                                Connect(spo_data, lQ_ins);
                                BeginTransaction(spo_data, lQ_ins);
                            }
                            else if ( 0 == q_retry ) {
                                setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
                                goto bad_query;
                            }

                            q_retry--;
                            sleep(1);
                        }
                    }
                }

                //Addtional Packet
                if ((SQLMaxQuery = SQL_GetMaxQueryAdData(spo_data, ele_que_ins))) {
                    itr = 0;
                    for (itr = 0; itr < SQLMaxQuery; itr++) {
                        if ((CurrentQuery = SQL_GetQueryAdDataByPos(spo_data, ele_que_ins, itr)) == NULL) {
                            goto bad_query;
                        }

                        if ( !CurrentQuery->valid )
                            continue;

                        DEBUG_U_WRAP_DEEP(LogMessage("%s: insert query Addtional data %d\n", __func__, itr));

                        q_retry = Q_RETRY_TIME;
                        while ( Insert_real(CurrentQuery->string, CurrentQuery->slen, spo_data, 1, lQ_ins) ) {
                            ErrorMessage("[%s()]: Insertion of Query [%s] failed\n",
                                    __FUNCTION__, CurrentQuery->string);

                            if ( (Q_RETRY_TIME>>1) == q_retry ) {
                                sleep(1);
                                CommitTransaction(spo_data, lQ_ins);
                                Disconnect(spo_data, lQ_ins);
                                sleep(1);
                                Connect(spo_data, lQ_ins);
                                BeginTransaction(spo_data, lQ_ins);
                            }
                            else if ( 0 == q_retry ) {
                                setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
                                goto bad_query;
                            }

                            q_retry--;
                            sleep(1);
                        }
                    }
                }

                if ( spo_data->refresh_mcid ) {
                    UpdateLastCid(spo_data, 0, 0, lQ_ins);
                    spo_data->refresh_mcid = 0;
                }

                if (CommitTransaction(spo_data, lQ_ins)) {
                    ErrorMessage("ERROR database: [%s()]: Error commiting transaction \n",
                            __FUNCTION__);
                    setTransactionCallFail(&spo_data->m_dbins[lQ_ins]);
                    goto bad_query;
                } else {
                    resetTransactionState(&spo_data->m_dbins[lQ_ins]);
                }

                DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: CommitTransaction [%d]\n", __func__, lQ_ins, ele_que_ins));
                /* Clean the query */
                SQL_Cleanup(spo_data, ele_que_ins);

                /* send ack to queue */
                n = 0;
                while (n == 0 || (n < 0 && errno == EINTR)) {
                    DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: write2queue [%d], transaction \n", __func__, lQ_ins, ele_que_ins));
                    n = write(qr2qe_w, &c, 1);
                }
                if (n < 0) {
                    LogMessage("%s: write2queue[%d] failed, transaction", __func__, ele_que_ins);
                    perror("cannot write on query2queue pipe\n");
                }

                /*Spo_ProcQuery_PutQins(spo_data, ele_que_ins);
                ele_que_ins = SQL_ELEQUE_INS_PLUS_ONE(ele_que_ins);*/
                DEBUG_U_WRAP_SP_QUERY(LogMessage("%s_%d: query done, process next queue [%d]\n",
                        __func__, lQ_ins, ele_que_ins));
            }
            break;
        case LQ_EXIT:
            {
                /*Spo_ProcQuery_PutQins(spo_data, ele_que_ins);
                ele_que_ins = SQL_ELEQUE_INS_PLUS_ONE(ele_que_ins);*/
                LogMessage("%s: queue exit, process next query [%d]\n",
                        __func__, ele_que_ins);
            }
            break;
        default:
            break;
        }
    }

#ifdef IF_SPO_QUERY_IN_THREAD
    LogMessage("%s: exiting on [%d]\n", __func__, ele_que_ins);
    return NULL;
#else
    return;
#endif

bad_query:
/*    if (checkTransactionCall(&data->dbRH[data->dbtype_id])) {
        goto TransacRollback;
    } */
    if (checkTransactionState(&spo_data->m_dbins[lQ_ins])
            && checkTransactionCall(&spo_data->m_dbins[lQ_ins])) {
        if (RollbackTransaction(spo_data, lQ_ins)) {
            FatalError("database Unable to rollback transaction in [%s()]\n",
                    __FUNCTION__);
        }
        resetTransactionState(&spo_data->m_dbins[lQ_ins]);
    }
    FatalError("database bad_query in [%s()]\n", __FUNCTION__);

#ifdef IF_SPO_QUERY_IN_THREAD
    return NULL;
#else
    return;
#endif
}

void *Spo_EncodeSql(void * arg)
{
    uint8_t q_ins;
    char c;
    int n;
    int da2qe_r, qe2da_w;
    int qr2qe_r, qe2qr_w;
    lquery_instance *lQ_ins = (lquery_instance *) arg;
    DatabaseData *spo_data = (DatabaseData*)lQ_ins->spo_data;

    q_ins = lQ_ins->ql_index;
    da2qe_r = lQ_ins->pipe_data2queue[0];
    qe2da_w = lQ_ins->pipe_queue2data[1];
    qr2qe_r = lQ_ins->pipe_query2queue[0];
    qe2qr_w = lQ_ins->pipe_queue2query[1];

    while ( 1 ) //lQ_ins->ql_switch) {
    {
        switch ( lQ_ins->lq_stat ) {
        case LQ_PRE_QUEUE:
            {
                DEBUG_U_WRAP_DEEP(LogMessage("%s[%d]: wait event data\n", __func__, q_ins));
                do {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: waiting queue \n", __func__, q_ins));
                    n = read(da2qe_r, &c, 1);
                } while (n < 0 && errno == EINTR);
                if (n <= 0) {
                    LogMessage("%s[%d]: read_data2queue failed", __func__, q_ins);
                    perror("cannot read on data2queue pipe\n");
                    break;
                }

                if ( !lQ_ins->ql_switch ) {
                    lQ_ins->lq_stat = LQ_EXIT;
                    c = 1;
                    n = write(qe2qr_w, &c, 1);

                    LogMessage("%s[%d]: exiting \n", __func__, q_ins);
                    dbEventQueueClean(q_ins);
                    n = write(qe2da_w, &c, 1);
                    Spo_ProcQuery_PutQins(spo_data, q_ins);
                    goto enc_endloop;
                }

                if ( 0 == c ) {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: read from data: empty\n", __func__, q_ins, c));
                    //n = write(qe2qr_w, &c, 1);
                    //n = write(qe2qr_w, &c, 1);

                    //write back to data
                    dbEventQueueClean(q_ins);
                    //n = write(qe2da_w, &c, 1);
                    Spo_ProcQuery_PutQins(spo_data, q_ins);
                    break;
                }

                lQ_ins->lq_stat = LQ_PRE_SIG_ID;

                /* send to query for sig_id; */
                n = 0;
                while (n == 0 || (n < 0 && errno == EINTR)) {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: write2query for sig_id\n", __func__, q_ins));
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: ele_cnt %d, ele_exp_cnt %d\n", __func__, q_ins,
                            spo_db_event_queue[q_ins]->ele_cnt, spo_db_event_queue[q_ins]->ele_exp_cnt));
                    n = write(qe2qr_w, &c, 1);

#ifndef IF_SPO_QUERY_IN_THREAD
                    Spo_ProcQuery((void*)(&spo_data->m_dbins[q_ins]));
#endif
                }
                if (n < 0) {
                    LogMessage("%s[%d]: write2query failed", __func__, q_ins);
                    perror("cannot write on queue2query pipe\n");

                    //Drop this queue
                    lQ_ins->lq_stat = LQ_PRE_QUEUE;
                    dbEventQueueClean(q_ins);
                    //n = write(qe2da_w, &c, 1);
                    Spo_ProcQuery_PutQins(spo_data, q_ins);
                    break;
                }
            }
            break;
        case LQ_PRE_SIG_ID:
            {
                do {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: waiting query sig_id\n", __func__, q_ins));
                    n = read(qr2qe_r, &c, 1);
                } while (n < 0 && errno == EINTR);
                if (n <= 0) {
                    LogMessage("%s[%d]: read_query2queue failed", __func__, q_ins);
                    perror("cannot read on query2queue pipe\n");
                    break;
                }

                DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: preparing sql\n", __func__, q_ins));

                if ( !dbProcessMultiEventInfo(spo_data, spo_db_event_queue[q_ins], q_ins) ) {
                    //setTransactionCallFail(&spo_data->m_dbins[SPO_DB_DEF_INS]);
                    FatalError("[dbProcessMultiEventInfo()]: Failed, stoping processing \n");
                }

                lQ_ins->lq_stat = LQ_TRANS_QUERY;

                /* send to query to start transaction with SQL*/
                n = 0;
                while (n == 0 || (n < 0 && errno == EINTR)) {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: write2query \n", __func__, q_ins));
                    n = write(qe2qr_w, &c, 1);

#ifndef IF_SPO_QUERY_IN_THREAD
                    Spo_ProcQuery((void*)(&spo_data->m_dbins[q_ins]));
#endif
                }
                if (n < 0) {
                    LogMessage("%s[%d]: write2query failed", __func__, q_ins);
                    perror("cannot write on queue2query pipe\n");

                    //Skip and start again
                    lQ_ins->lq_stat = LQ_PRE_QUEUE;
                }

                /* send to data to release queue*/
                n = 0;
                {//while (n == 0 || (n < 0 && errno == EINTR)) {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: write2data  \n", __func__, q_ins));
                    dbEventQueueClean(q_ins);
                    //n = write(qe2da_w, &c, 1);
                    Spo_ProcQuery_PutQins(spo_data, q_ins);
                }
                if (n < 0) {
                    LogMessage("%s: write2data[%d] failed", __func__, q_ins);
                    perror("cannot write on queue2data pipe\n");
                    //Can't restart again, end loop
                    goto enc_endloop;
                }
            }
            break;
        case LQ_TRANS_QUERY:
            {
                do {
                    DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: waiting query \n", __func__, q_ins));
                    n = read(qr2qe_r, &c, 1);
                } while (n < 0 && errno == EINTR);
                if (n <= 0) {
                    LogMessage("%s[%d]: read_query2queue failed", __func__, q_ins);
                    perror("cannot read on query2queue pipe\n");
                    break;
                }

                DEBUG_U_WRAP_SP_ELEQUE(LogMessage("%s[%d]: finish query \n", __func__, q_ins));
                lQ_ins->lq_stat = LQ_PRE_QUEUE;
            }
            break;
        default:
            break;
        }
    }

    LogMessage("%s[%d]: exiting (out while)\n", __func__, q_ins);
    return NULL;

enc_endloop:
    return NULL;
}

/*******************************************************************************
 * Function: Database(Packet *p, void *event, uint32_t event_type, void *arg)
 *
 * Purpose: Insert data into the database
 *
 * Arguments: p   => pointer to the current packet data struct
 *            msg => pointer to the signature message
 *
 * Returns: void function
 *
 ******************************************************************************/
void Spo_Database(Packet *p, void *event, uint32_t event_type, void *arg)
{
    uint8_t rid;
    uint8_t q_ins, q_ins_next;
    char c;
    lflush_state q_flushout = LF_CUR;
    int i, n, n_qins = 0;
    int da2qe_w;//, qe2da_r;
	us_cid_t event_id;
    DatabaseData *data = (DatabaseData *) arg;
    Unified2Packet *pdata;
    struct timespec t_elapse;

	if ( NULL == data ) {
		FatalError("database [%s()]: Called with a NULL DatabaseData Argument, can't process \n",
				__FUNCTION__);
		return;
	}

    t_elapse.tv_sec = 0;
    t_elapse.tv_nsec = 10;

	q_ins = data->enc_q_ins;

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
    case UNIFIED2_IDS_GET_ELEQUE_INS:
        {
            if ( NULL != event ) {
                *((uint8_t*)event) = q_ins;
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
    case UNIFIED2_IDS_UPD_MCID:
        {
            if ( NULL != event ) {
                rid = ((EventGMCid*)event)->rid;
                data->ms_cid[rid] = ((EventGMCid*)event)->ms_cid;
                //UpdateLastCid(data, 0);
                data->refresh_mcid = 1;
            }
            return;
        }
        break;
    case UNIFIED2_IDS_SPO_EXIT:
        {
            for (i=0; i<SQL_ELEQUE_INS_MAX; i++) {
                c = 1;
                data->lEleQue_ins[q_ins].ql_switch = 0;
                LogMessage("%s: write to exit [%d] \n", __func__, q_ins);
                n = write(data->lEleQue_ins[q_ins].pipe_data2queue[1], &c, 1);
                n = read(data->lEleQue_ins[q_ins].pipe_queue2data[0], &c, 1);
                LogMessage("%s: queue exit OK [%d] \n", __func__, q_ins);

                q_ins = SQL_ELEQUE_INS_PLUS_ONE(q_ins);
            }
            return;
        }
        break;
    case UNIFIED2_IDS_FLUSH_OUT:
        {
            if ( (0 == spo_db_event_queue[q_ins]->ele_cnt)
                    &&  (0 == spo_db_event_queue[q_ins]->ele_exp_cnt) ) {
                LogMessage( "%s: Event Queue is empty, Flush Out All queues\n", __func__ );
                q_flushout = LF_SET_EMPTY;
            }
            else {
                LogMessage("%s: flush out event_queue[%d], proceed, %d, %d\n", __func__, q_ins,
                        spo_db_event_queue[q_ins]->ele_cnt, spo_db_event_queue[q_ins]->ele_exp_cnt);
                q_flushout = LF_SET;
            }
        }
        break;
    case UNIFIED2_IDS_FLUSH:
	    {
	        if ( (0 == spo_db_event_queue[q_ins]->ele_cnt)
	        		&&  (0 == spo_db_event_queue[q_ins]->ele_exp_cnt) ) {
	            LogMessage( "%s: Event Queue is empty\n", __func__ );
	            if ( NULL != event ) {
	                ((RingTopOct*)event)->r_flag = 0;
	            }
	            return;
	        }

	        LogMessage("%s: flush event_queue[%d], proceed, %d, %d\n", __func__, q_ins,
	                spo_db_event_queue[q_ins]->ele_cnt, spo_db_event_queue[q_ins]->ele_exp_cnt);
	        q_flushout = LF_CUR;

	        if ( NULL != event ) {
	            spo_db_event_queue[q_ins]->ele_rtOct = (RingTopOct*)event;
	        }
	    }
	    break;
	default:
	    {
	        if (event == NULL || p == NULL) {
	            LogMessage("WARNING database [%s()]: Called with Event[0x%x] "
	                    "Event Type [%u] (P)acket [0x%x], information has not been outputed. \n",
	                    __FUNCTION__, event, event_type, p);
	            return;
	        }

	        spo_db_event_queue[q_ins]->ele_expkt[spo_db_event_queue[q_ins]->ele_exp_cnt].rid = ((EventEP*)event)->rid;
	        spo_db_event_queue[q_ins]->ele_expkt[spo_db_event_queue[q_ins]->ele_exp_cnt].event_id =
	                ((EventEP*)event)->ep->event_id;
	        spo_db_event_queue[q_ins]->ele_expkt[spo_db_event_queue[q_ins]->ele_exp_cnt].p = p;

	        pdata = (Unified2Packet *)((EventEP*)event)->ep->data;
	        spo_db_event_queue[q_ins]->ele_expkt[spo_db_event_queue[q_ins]->ele_exp_cnt].u2raw_data =
	                pdata->packet_data;
	        spo_db_event_queue[q_ins]->ele_expkt[spo_db_event_queue[q_ins]->ele_exp_cnt].u2raw_datalen =
	                ntohl(pdata->packet_length);
	        spo_db_event_queue[q_ins]->ele_exp_cnt++;

	        if ( UNIFIED2_PACKET != event_type ) {
	            event_id = ((EventEP*)event)->ee->event_id;

                spo_db_event_queue[q_ins]->ele[spo_db_event_queue[q_ins]->ele_cnt].event_id = event_id;
                spo_db_event_queue[q_ins]->ele[spo_db_event_queue[q_ins]->ele_cnt].event_type = event_type;
                spo_db_event_queue[q_ins]->ele[spo_db_event_queue[q_ins]->ele_cnt].event = ((EventEP*)event)->ee->data;
                spo_db_event_queue[q_ins]->ele[spo_db_event_queue[q_ins]->ele_cnt].rid = ((EventEP*)event)->rid;
                spo_db_event_queue[q_ins]->ele[spo_db_event_queue[q_ins]->ele_cnt].p = p;
                spo_db_event_queue[q_ins]->ele_cnt++;
            }

	        if ( spo_db_event_queue[q_ins]->ele_exp_cnt >= SQL_PKT_QUEUE_LEN
	                || spo_db_event_queue[q_ins]->ele_cnt >= SQL_EVENT_QUEUE_LEN ) {
	            //Shouldn't be, well controlled by Output process/thread.
	            DEBUG_U_WRAP_DEEP(LogMessage("%s: event queue is full, proceed\n", __func__));
	        }
	        else {
	            DEBUG_U_WRAP_DEEP(LogMessage("%s: save pkt into event queue\n", __func__));
	            return;
	        }
	    }
	    break;
	}

//	for (i=q_ins; i<SQL_ELEQUE_INS_MAX; i++) {
	    da2qe_w = data->lEleQue_ins[q_ins].pipe_data2queue[1];
	    if ( (LF_SET==q_flushout || LF_CUR==q_flushout) ) {
	        n_qins = 0;
	        c = 1;
	        while (n_qins == 0 || (n_qins < 0 && errno == EINTR)) {
	            DEBUG_U_WRAP_SP_DB(LogMessage("%s: write2queue [%d], c=1, ele_cnt %d, ele_exp_cnt %d \n", __func__, q_ins,
	                    spo_db_event_queue[q_ins]->ele_cnt, spo_db_event_queue[q_ins]->ele_exp_cnt));
	            n_qins = write(da2qe_w, &c, 1);
	        }
	    }
	    else if ( /*LF_SET==q_flushout ||*/ LF_SET_EMPTY==q_flushout ) {
	        c = 0;
	        DEBUG_U_WRAP_SP_DB(LogMessage("%s: write2queue [%d], c=0 \n", __func__, q_ins));
	        n = write(da2qe_w, &c, 1);
	    }
//	}

/*    for (i=q_ins; i<SQL_ELEQUE_INS_MAX; i++) {
        qe2da_r = data->lEleQue_ins[i].pipe_queue2data[0];
        if ( (i==q_ins) && (LF_SET==q_flushout || LF_CUR==q_flushout) ) {
            if (n_qins <= 0) {
                LogMessage("%s: write2queue[%d] failed", __func__, q_ins);
                perror("cannot write to data2queue pipe\n");
            }
            else {
                // wait queue
                do {
                    DEBUG_U_WRAP_SP_DB(LogMessage("%s: waiting ins [%d]\n", __func__, q_ins));
                    n = read(qe2da_r, &c, 1);
                } while ((n < 0) && (EINTR==errno) && (0==exit_signal));
                if (n <= 0) {
                    LogMessage("%s: read queue2data[%d] failed", __func__, q_ins);
                    perror("cannot read from queue2data pipe\n");
                }
                // wait queue ok

                //Step to next query instance.
                data->enc_q_ins = SQL_ELEQUE_INS_PLUS_ONE(q_ins);
                DEBUG_U_WRAP_SP_DB(LogMessage("%s: process next ins [%d]\n", __func__, data->enc_q_ins));
            }
        }
        else if ( LF_SET==q_flushout || LF_SET_EMPTY==q_flushout ) {
            DEBUG_U_WRAP_SP_DB(LogMessage("%s: waiting ins [%d], 0\n", __func__, i));
            n = read(qe2da_r, &c, 1);
        }
    }*/

    if ( LF_CUR == q_flushout ) {
        if (n_qins <= 0) {
            LogMessage("%s: write2queue[%d] failed\n", __func__, q_ins);
            perror("cannot write to data2queue pipe\n");
        }
        else {
            // wait queue

            //Step to next query instance.
            DEBUG_U_WRAP_SP_DB(LogMessage("%s: Step to next query, from ins [%d]\n", __func__, q_ins));
            //data->enc_q_ins = Spo_ProcQuery_GetQins(data, 0);//SQL_ELEQUE_INS_PLUS_ONE(q_ins);
            q_ins_next = SQL_ELEQUE_INS_PLUS_ONE(q_ins);
            while ( (n=Spo_ProcQuery_GetQins(data, q_ins_next)) < 0 ) {
                nanosleep(&t_elapse, NULL);
            }
            DEBUG_U_WRAP_SP_DB(LogMessage("%s: LF_CUR, process next ins [%d]\n", __func__, n));
            data->enc_q_ins = (uint8_t)n;
        }
    }
    else if ( LF_SET==q_flushout || LF_SET_EMPTY==q_flushout ) {
        //Wait all queue clean
        DEBUG_U_WRAP_SP_DB(LogMessage("%s: LF_SET, waiting ins\n", __func__));
        while ( Spo_ProcQuery_QinsCheckAll(data) ) {
            nanosleep(&t_elapse, NULL);
        }
        DEBUG_U_WRAP_SP_DB(LogMessage("%s: LF_SET, waiting ins done\n", __func__));

        //Start from first queue
        while ( (n=Spo_ProcQuery_GetQins(data, 0)) < 0 ) {
            nanosleep(&t_elapse, NULL);
        }
        DEBUG_U_WRAP_SP_DB(LogMessage("%s: LF_SET, process next ins [%d]\n", __func__, n));
        data->enc_q_ins = (uint8_t)n;
    }

/*    if ( LF_SET==q_flushout || LF_SET_EMPTY==q_flushout ) {
        //Step to first query instance.
        data->enc_q_ins = 0;
    }*/

    //Drop all data in queue;
    //dbEventQueueClean(q_ins);

    return;
}

/* Some of the code in this function is from the
 mysql_real_escape_string() function distributed with mysql.

 Those portions of this function remain
 Copyright (C) 2000 MySQL AB & MySQL Finland AB & TCX DataKonsult AB

 We needed a more general case that was not MySQL specific so there
 were small modifications made to the mysql_real_escape_string()
 function. */

char * snort_escape_string(char * from, DatabaseData * data) {
	char * to;
	char * to_start;
	char * end;
	int from_length;

	from_length = (int) strlen(from);

	to = (char *) SnortAlloc(strlen(from) * 2 + 1);
	to_start = to;
#ifdef ENABLE_ORACLE
	if (data->dbtype_id == DB_ORACLE)
	{
		for (end=from+from_length; from != end; from++)
		{
			switch(*from)
			{
				case '\'': /*  '  -->  '' */
				*to++= '\'';
				*to++= '\'';
				break;
				case '\032': /* Ctrl-Z (Win32 EOF)  -->  \\Z */
				*to++= '\\'; /* This gives problems on Win32 */
				*to++= 'Z';
				break;
				default: /* copy character directly */
				*to++= *from;
			}
		}
	}
	else
#endif
#ifdef ENABLE_MSSQL
	if (data->dbtype_id == DB_MSSQL)
	{
		for (end=from+from_length; from != end; from++)
		{
			switch(*from)
			{
				case '\'': /*  '  -->  '' */
				*to++= '\'';
				*to++= '\'';
				break;
				default: /* copy character directly */
				*to++= *from;
			}
		}
	}
	else
#endif
	/* Historically these were together in a common "else".
	 * Keeping it that way until somebody complains...
	 */
#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
	if (data->dbtype_id == DB_MYSQL || data->dbtype_id == DB_POSTGRESQL) {
		for (end = from + from_length; from != end; from++) {
			switch (*from) {
			/*
			 * Only need to escape '%' and '_' characters
			 * when querying a SELECT...LIKE, which never
			 * occurs in Snort.  Excluding these checks
			 * for that reason.
			 case '%':            ** %  -->  \% **
			 *to++= '\\';
			 *to++= '%';
			 break;
			 case '_':            ** _  -->  \_ **
			 *to++= '\\';
			 *to++= '_';
			 break;
			 */

			case 0: /* NULL  -->  \\0  (probably never encountered due to strlen() above) */
				*to++ = '\\'; /* Must be escaped for 'mysql' */
				*to++ = '0';
				break;
			case '\n': /* \n  -->  \\n */
				*to++ = '\\'; /* Must be escaped for logs */
				*to++ = 'n';
				break;
			case '\r': /* \r  -->  \\r */
				*to++ = '\\';
				*to++ = 'r';
				break;
			case '\t': /* \t  -->  \\t */
				*to++ = '\\';
				*to++ = 't';
				break;
			case '\\': /* \  -->  \\ */
				*to++ = '\\';
				*to++ = '\\';
				break;
			case '\'': /* '  -->  \' */
				*to++ = '\\';
				*to++ = '\'';
				break;
			case '"': /* "  -->  \" */
				*to++ = '\\'; /* Better safe than sorry */
				*to++ = '"';
				break;
			case '\032': /* Ctrl-Z (Win32 EOF)  -->  \\Z */
				if (data->dbtype_id == DB_MYSQL) {
					*to++ = '\\'; /* This gives problems on Win32 */
					*to++ = 'Z';
				} else {
					*to++ = *from;
				}
				break;
			default: /* copy character directly */
				*to++ = *from;
			}
		}
	} else
#endif
	{
		for (end = from + from_length; from != end; from++) {
			switch (*from) {
			case '\'': /*  '  -->  '' */
				*to++ = '\'';
				*to++ = '\'';
				break;
			default: /* copy character directly */
				*to++ = *from;
			}
		}
	}
	*to = 0;
	return (char *) to_start;
}

/*
 Same function as above but will work on a static buffer, slightly different arguments...
 */
u_int32_t snort_escape_string_STATIC(char *from, char *buff_esc, u_int32_t buffer_max_len,
		DatabaseData *data) {

#if defined(ENABLE_POSTGRESQL)
	int error = 0;
	size_t write_len = 0;
#endif /* defined(ENABLE_POSRGRESQL) */

	char * to = NULL;
	char * to_start = NULL;
	char * end = NULL;
	char * from_start = NULL;
	int from_length = 0;

	if ((from == NULL) || (data == NULL)) {
		/* XXX */
		return 1;
	}

	if ((buffer_max_len > (DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN - 1))
			|| ((strlen(from) + 1) > buffer_max_len) || (buffer_max_len == 0)) {
		/* XXX */
		FatalError(
				"database [%s()]: Edit source code and change the value of the #define  DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN in spo_database.h to something greater than [%u] \n",
				__FUNCTION__, buffer_max_len);
	}

	memset(buff_esc, '\0', DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN);

	if ((from_length = strlen(from)) == 1) {
		/* Nothing to escape */
		return 0;
	}

	from_start = from;
	to = buff_esc;
	to_start = to;

	switch (data->dbtype_id) {
#ifdef ENABLE_ORACLE
	case DB_ORACLE:
	for (end=from+from_length; from != end; from++)
	{
		switch(*from)
		{
			case '\'': /*  '  -->  '' */
			*to++= '\'';
			*to++= '\'';
			break;
			case '\032': /* Ctrl-Z (Win32 EOF)  -->  \\Z */
			*to++= '\\'; /* This gives problems on Win32 */
			*to++= 'Z';
			break;
			default: /* copy character directly */
			*to++= *from;
		}
	}
	break;
#endif

#ifdef ENABLE_MSSQL
	case DB_MSSQL:

	for (end=from+from_length; from != end; from++)
	{
		switch(*from)
		{
			case '\'': /*  '  -->  '' */
			*to++= '\'';
			*to++= '\'';
			break;
			default: /* copy character directly */
			*to++= *from;
		}
	}
	break;
#endif
	/* Historically these were together in a common "else".
	 * Keeping it that way until somebody complains...
	 */

#if  defined( ENABLE_MYSQL ) || defined (ENABLE_ODBC)
//#ifdef ENABLE_MYSQL
	case DB_ODBC:
	case DB_MYSQL:
		for (end = from + from_length; from != end; from++) {
			switch (*from) {
			/*
			 * Only need to escape '%' and '_' characters
			 * when querying a SELECT...LIKE, which never
			 * occurs in Snort.  Excluding these checks
			 * for that reason.
			 */
			/*
			 case '%':            * %  -->  \% *
			 *to++= '\\';
			 *to++= '%';
			 break;
			 case '_':            * _  -->  \_  *
			 *to++= '\\';
			 *to++= '_';
			 break;
			 */

			case 0: /* NULL  -->  \\0  (probably never encountered due to strlen() above) */
				*to++ = '\\'; /* Must be escaped for 'mysql' */
				*to++ = '0';
				break;
			case '\n': /* \n  -->  \\n */
				*to++ = '\\'; /* Must be escaped for logs */
				*to++ = 'n';
				break;
			case '\r': /* \r  -->  \\r */
				*to++ = '\\';
				*to++ = 'r';
				break;
			case '\t': /* \t  -->  \\t */
				*to++ = '\\';
				*to++ = 't';
				break;
			case '\\': /* \  -->  \\ */
				*to++ = '\\';
				*to++ = '\\';
				break;
			case '/':
				*to++ = '\\'; /* / --> \/ */
				*to++ = '/';
				break;
			case '\'': /* '  -->  \' */
				*to++ = '\\';
				*to++ = '\'';
				break;
			case '"': /* "  -->  \" */
				*to++ = '\\'; /* Better safe than sorry */
				*to++ = '"';
				break;
			case '\032': /* Ctrl-Z (Win32 EOF)  -->  \\Z */
				if (data->dbtype_id == DB_MYSQL) {
					*to++ = '\\'; /* This gives problems on Win32 */
					*to++ = 'Z';
				} else {
					*to++ = *from;
				}
				break;
			default: /* copy character directly */
				*to++ = *from;
			}
		}
		break;
#endif /* defined( ENABLE_MYSQL ) || defined (ENABLE_ODBC) */

#ifdef ENABLE_POSTGRESQL
		case DB_POSTGRESQL:

		if( (write_len = PQescapeStringConn(data->p_connection,
								data->sanitize_buffer,
								from,
								buffer_max_len,&error)) == 0)
		{
			/* XXX */
			return 1;
		}

		if(error != 1)
		{
			memcpy(from_start,data->sanitize_buffer,write_len+1);
		}
		else
		{
			/* XXX */
			return 1;
		}

		return 0;
		break;
#endif /* ENABLE_POSTGRESQL*/
	default:
		for (end = from + from_length; from != end; from++) {
			switch (*from) {
			case '\'': /*  '  -->  '' */
				*to++ = '\'';
				*to++ = '\'';
				break;
			case '\\': /* \  -->  \\ */
				*to++ = '\\';
				*to++ = '\\';
				break;
			default: /* copy character directly */
				*to++ = *from;
			}
		}
		break;
	}

	*to = '\0';

	if (strlen(to_start) > buffer_max_len) {
		/* XXX */
		return 1;
	}

	memcpy(from_start, to_start, strlen(to_start));
	return 0;
}

/*******************************************************************************
 * Function: CheckDBVersion(DatabaseData * data)
 *
 * Purpose: To determine the version number of the underlying DB schema
 *
 * Arguments: database information
 *
 * Returns: version number of the schema
 *
 ******************************************************************************/
int CheckDBVersion(DatabaseData * data) {
	if (data == NULL) {
		/* XXX */
		return 1;
	}

	DatabaseCleanSelect(data, SPO_DB_DEF_INS);

#if defined(ENABLE_MSSQL) || defined(ENABLE_ODBC)
//   if ( data->dbtype_id == DB_MSSQL ||
	//      (data->dbtype_id==DB_ODBC && data->u_underlying_dbtype_id==DB_MSSQL) )
	if(data->dbtype_id == DB_ODBC)
	{
		/* "schema" is a keyword in SQL Server, so use square brackets
		 *  to indicate that we are referring to the table
		 */
		if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
								"SELECT vseq FROM [schema]")) != SNORT_SNPRINTF_SUCCESS)
		{
			return 1;
		}
	}
	else
#endif
	{
#if defined(ENABLE_MYSQL)
		if (data->dbtype_id == DB_MYSQL) {
			/* "schema" is a keyword in MYSQL, so use `schema`
			 *  to indicate that we are referring to the table
			 */

			if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], MAX_QUERY_LENGTH,
					"SELECT vseq FROM `schema`")) != SNORT_SNPRINTF_SUCCESS) {
				return 1;
			}
		} else
#endif
		{
			if ((SnortSnprintf(data->SQL_SELECT[SPO_DB_DEF_INS], MAX_QUERY_LENGTH,
					"SELECT vseq FROM schema")) != SNORT_SNPRINTF_SUCCESS) {
				return 1;
			}
		}
	}

	if (Select(data->SQL_SELECT[SPO_DB_DEF_INS], data, (u_int32_t *) &data->DBschema_version, SPO_DB_DEF_INS)) {
		/* XXX */
		ErrorMessage("ERROR database: executing Select() with Query [%s] \n",
				data->SQL_SELECT[SPO_DB_DEF_INS]);
		return 1;
	}

	if (data->DBschema_version == -1)
		FatalError(
				"database Unable to construct query - output error or truncation\n");

	if (data->DBschema_version == 0) {
		FatalError(FATAL_BAD_SCHEMA_1, LATEST_DB_SCHEMA_VERSION,
				FATAL_BAD_SCHEMA_2);
	}
	if (data->DBschema_version < LATEST_DB_SCHEMA_VERSION) {
		FatalError(FATAL_OLD_SCHEMA_1, data->DBschema_version,
				LATEST_DB_SCHEMA_VERSION, FATAL_OLD_SCHEMA_2);
	}

	return 0;
}

/* CHECKME: -elz This function is not complete ...alot of leaks could happen here! */
void SpoDatabaseCleanExitFunction(int signal, void *arg)
{
    uint8_t i;
	DatabaseData *data = (DatabaseData *) arg;

	DEBUG_WRAP(DebugMessage(DB_DEBUG,"database(debug): entered SpoDatabaseCleanExitFunction\n"););

	if (data != NULL) {
	    for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
	        if (checkTransactionState(&data->m_dbins[i])) {
	            if (RollbackTransaction(data, i)) {
	                DEBUG_WRAP(DebugMessage(DB_DEBUG,"database: RollbackTransaction failed in [%s()] \n",
	                                __FUNCTION__));
	            }
	        }

	        resetTransactionState(&data->m_dbins[i]);
	    }

		MasterCacheFlush(data, CACHE_FLUSH_ALL);

		SQL_Finalize(data);

		if (!(data->dbRH[data->dbtype_id].dbConnectionStatus(
				&data->dbRH[data->dbtype_id], SPO_DB_DEF_INS))) {
			UpdateLastCid(data, 1, 1, SPO_DB_DEF_INS);
		}

        for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
            Disconnect(data, i);

            if (data->SQL_INSERT[i] != NULL) {
                free(data->SQL_INSERT[i]);
                data->SQL_INSERT[i] = NULL;
            }

            if (data->SQL_SELECT[i] != NULL) {
                free(data->SQL_SELECT[i]);
                data->SQL_SELECT[i] = NULL;
            }
        }

		free(data->args);
		free(data);
		data = NULL;
	}

	return;
}

/* CHECKME: -elz This function is not complete ...alot of leaks could happen here! */
void SpoDatabaseRestartFunction(int signal, void *arg)
{
    uint8_t i;
	DatabaseData *data = (DatabaseData *) arg;

	DEBUG_WRAP(DebugMessage(DB_DEBUG,"database(debug): entered SpoDatabaseRestartFunction\n"););

	if (data != NULL) {
		MasterCacheFlush(data, CACHE_FLUSH_ALL);

		UpdateLastCid(data, 1, 1, SPO_DB_DEF_INS);

        for ( i=0; i<SQL_QUERY_SOCK_MAX; i++ ) {
            resetTransactionState(&data->m_dbins[i]);
            Disconnect(data, i);
        }

		free(data->args);
		free(data);
		data = NULL;
	}

	return;
}

/* CHECKME: -elz , compilation with MSSQL will have to be worked out ... */
#ifdef ENABLE_MSSQL
/*
 * The functions mssql_err_handler() and mssql_msg_handler() are callbacks that are registered
 * when we connect to SQL Server.  They get called whenever SQL Server issues errors or messages.
 * This should only occur whenever an error has occurred, or when the connection switches to
 * a different database within the server.
 */
static int mssql_err_handler(PDBPROCESS dbproc, int severity, int dberr, int oserr,
		LPCSTR dberrstr, LPCSTR oserrstr)
{
	int retval;
	ErrorMessage("ERROR database: DB-Library error:\n\t%s\n", dberrstr);

	if ( severity == EXCOMM && (oserr != DBNOERR || oserrstr) )
	ErrorMessage("ERROR database: Net-Lib error %d:  %s\n", oserr, oserrstr);
	if ( oserr != DBNOERR )
	ErrorMessage("ERROR database: Operating-system error:\n\t%s\n", oserrstr);
#ifdef ENABLE_MSSQL_DEBUG
	if( strlen(g_CurrentStatement) > 0 )
	ErrorMessage("ERROR database:  The above error was caused by the following statement:\n%s\n", g_CurrentStatement);
#endif
	if ( (dbproc == NULL) || DBDEAD(dbproc) )
	retval = INT_EXIT;
	else
	retval = INT_CANCEL;
	return(retval);
}

static int mssql_msg_handler(PDBPROCESS dbproc, DBINT msgno, int msgstate, int severity,
		LPCSTR msgtext, LPCSTR srvname, LPCSTR procname, DBUSMALLINT line)
{
	ErrorMessage("ERROR database: SQL Server message %ld, state %d, severity %d: \n\t%s\n",
			msgno, msgstate, severity, msgtext);
	if ( (srvname!=NULL) && strlen(srvname)!=0 )
	ErrorMessage("Server '%s', ", srvname);
	if ( (procname!=NULL) && strlen(procname)!=0 )
	ErrorMessage("Procedure '%s', ", procname);
	if (line !=0)
	ErrorMessage("Line %d", line);
	ErrorMessage("\n");
#ifdef ENABLE_MSSQL_DEBUG
	if( strlen(g_CurrentStatement) > 0 )
	ErrorMessage("ERROR database:  The above error was caused by the following statement:\n%s\n", g_CurrentStatement);
#endif

	return(0);
}
#endif

