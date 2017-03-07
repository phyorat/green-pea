
#include "spo_database_if.h"


/*******************************************************************************
 * Function: Connect(DatabaseData * data)
 *
 * Purpose: Database independent function to initiate a database
 *          connection
 *
 ******************************************************************************/
void Connect(DatabaseData * data, uint8_t q_sock)
{
#ifdef ENABLE_ODBC
    ODBC_SQLRETURN ret;
#endif /* ENABLE_ODBC */

    if (data == NULL) {
        /* XXX */
        FatalError(
                "database [%s()]: Invoked with NULL DatabaseData argument \n",
                __FUNCTION__);
    }

    switch (data->dbtype_id) {

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

#ifdef HAVE_PQPING
    /* Set PQPing String */
    memset(data->p_pingString,'\0',1024);
    if(SnortSnprintf(data->p_pingString,1024,"host='%s' port='%s' user='%s' dbname='%s'",
                    data->host,
                    data->port == NULL ? "5432" : data->port,
                    data->user,
                    data->dbname))
    {
        /* XXX */
        FatalError("[%s()],unable to create PQPing connection string.. bailing \n",
                __FUNCTION__);
    }
#endif

    if (data->use_ssl == 1)
    {
        data->p_connection =
        PQsetdbLogin(data->host,
                data->port,
                data->dbRH[data->dbtype_id].ssl_mode,
                NULL,
                data->dbname,
                data->user,
                data->password);
    }
    else
    {
        data->p_connection =
        PQsetdbLogin(data->host,
                data->port,
                NULL,
                NULL,
                data->dbname,
                data->user,
                data->password);
    }

    if(PQstatus(data->p_connection) == CONNECTION_BAD)
    {
        PQfinish(data->p_connection);
        data->p_connection = NULL;
        FatalError("database Connection to database '%s' failed\n", data->dbname);
    }
    break;
#endif

#ifdef ENABLE_MYSQL
    case DB_MYSQL:
        data->m_dbins[q_sock].dbConnectionCount = 0;
        data->m_dbins[q_sock].m_sock = mysql_init(NULL);
        if (data->m_dbins[q_sock].m_sock == NULL) {
            FatalError("database Connection to database '%s' failed\n",
                    data->dbname);
        }

        /* check if we want to connect with ssl options */
        if (data->use_ssl == 1) {
            mysql_ssl_set(data->m_dbins[q_sock].m_sock, data->dbRH[data->dbtype_id].ssl_key,
                    data->dbRH[data->dbtype_id].ssl_cert,
                    data->dbRH[data->dbtype_id].ssl_ca,
                    data->dbRH[data->dbtype_id].ssl_ca_path,
                    data->dbRH[data->dbtype_id].ssl_cipher);
        }

        if (mysql_real_connect(data->m_dbins[q_sock].m_sock, data->host, data->user,
                data->password, data->dbname,
                data->port == NULL ? 0 : atoi(data->port), NULL, CLIENT_INTERACTIVE) == NULL) {
            if (mysql_errno(data->m_dbins[q_sock].m_sock)) {
                LogMessage("database mysql_error: %s\n",
                        mysql_error(data->m_dbins[q_sock].m_sock));
                mysql_close(data->m_dbins[q_sock].m_sock);
                data->m_dbins[q_sock].m_sock = NULL;
                CleanExit(1);
            }

            LogMessage("database Failed to logon to database '%s'\n",
                    data->dbname);
            mysql_close(data->m_dbins[q_sock].m_sock);
            data->m_dbins[q_sock].m_sock = NULL;
            CleanExit(1);
        }

        if (mysql_autocommit(data->m_dbins[q_sock].m_sock, 0)) {
            /* XXX */
            mysql_close(data->m_dbins[q_sock].m_sock);
            data->m_dbins[q_sock].m_sock = NULL;
            LogMessage("WARNING database: unable to unset autocommit\n");
            return;
        }

        data->m_dbins[q_sock].pThreadID = mysql_thread_id(data->m_dbins[q_sock].m_sock);
        data->m_dbins[q_sock].spo_data = data;
        data->m_dbins[q_sock].q_sock_idx = q_sock;
/*        if ( 0 == q_sock ) { //first sock
            data->m_sock = data->m_dbins[q_sock].m_sock;
        }*/
        break;
#endif  /* ENABLE_MYSQL */

#ifdef ENABLE_ODBC

        case DB_ODBC:
        data->u_underlying_dbtype_id = DB_UNDEFINED;

        if(!(SQLAllocEnv(&data->u_handle) == SQL_SUCCESS))
        {
            FatalError("database unable to allocate ODBC environment\n");
        }
        if(!(SQLAllocConnect(data->u_handle, &data->u_connection) == SQL_SUCCESS))
        {
            FatalError("database unable to allocate ODBC connection handle\n");
        }

        /* The SQL Server ODBC driver always returns SQL_SUCCESS_WITH_INFO
         * on a successful SQLConnect, SQLDriverConnect, or SQLBrowseConnect.
         * When an ODBC application calls SQLGetDiagRec after getting
         * SQL_SUCCESS_WITH_INFO, it can receive the following messages:
         * 5701 - Indicates that SQL Server put the user's context into the
         *        default database defined in the data source, or into the
         *        default database defined for the login ID used in the
         *        connection if the data source did not have a default database.
         * 5703 - Indicates the language being used on the server.
         * You can ignore messages 5701 and 5703; they are only informational.
         */
        ret = SQLConnect( data->u_connection
                , (ODBC_SQLCHAR *)data->dbname
                , SQL_NTS
                , (ODBC_SQLCHAR *)data->user
                , SQL_NTS
                , (ODBC_SQLCHAR *)data->password
                , SQL_NTS);

        if( (ret != SQL_SUCCESS) &&
                (ret != SQL_SUCCESS_WITH_INFO))
        {
            ODBCPrintError(data,SQL_HANDLE_DBC);
            FatalError("database ODBC unable to connect.\n");
        }

        /* NOTE: -elz
         The code below was commented for review, since we want to streamline the api and remove
         all SQLGetDiagRec call's.

         */
        //int  encounteredFailure = 1;  /* assume there is an error */
        /*
         char odbcError[2000];
         odbcError[0] = '\0';

         if( ret == SQL_SUCCESS_WITH_INFO )
         {

         ODBC_SQLCHAR   sqlState[6];
         ODBC_SQLCHAR   msg[SQL_MAX_MESSAGE_LENGTH];
         SQLINTEGER     nativeError;
         SQLSMALLINT    errorIndex = 1;
         SQLSMALLINT    msgLen;
         */
        /* assume no error unless nativeError tells us otherwise */
        //encounteredFailure = 0;
        /*
         while ((ret = SQLGetDiagRec( SQL_HANDLE_DBC
         , data->u_connection
         , errorIndex
         , sqlState
         , &nativeError
         , msg
         , SQL_MAX_MESSAGE_LENGTH
         , &msgLen)) != SQL_NO_DATA)
         {
         if( strstr((const char *)msg, "SQL Server") != NULL )
         {
         data->u_underlying_dbtype_id = DB_MSSQL;
         }

         if( nativeError!=5701 && nativeError!=5703 )
         {
         encounteredFailure = 1;
         strncat(odbcError, (const char *)msg, sizeof(odbcError));
         }
         errorIndex++;
         }
         }
         if( encounteredFailure )
         {

         }
         */

        break;
#endif

#ifdef ENABLE_ORACLE

        case DB_ORACLE:

#define PRINT_ORACLE_ERR(func_name) \
     { \
         OCIErrorGet(data->o_error, 1, NULL, &data->o_errorcode, \
                     data->o_errormsg, sizeof(data->o_errormsg), OCI_HTYPE_ERROR); \
         ErrorMessage("ERROR database: Oracle_error: %s\n", data->o_errormsg); \
         FatalError("database  %s : Connection to database '%s' failed\n", \
                    func_name, data->dbRH[data->dbtype_id]->dbname); \
     }

        if (!getenv("ORACLE_HOME"))
        {
            ErrorMessage("ERROR database: ORACLE_HOME environment variable not set\n");
        }

        if (!data->user || !data->password || !data->dbRH[data->dbtype_id]->dbname)
        {
            ErrorMessage("ERROR database: user, password and dbname required for Oracle\n");
            ErrorMessage("ERROR database: dbname must also be in tnsnames.ora\n");
        }

        if (data->host)
        {
            ErrorMessage("ERROR database: hostname not required for Oracle, use dbname\n");
            ErrorMessage("ERROR database: dbname  must be in tnsnames.ora\n");
        }

        if (OCIInitialize(OCI_DEFAULT, NULL, NULL, NULL, NULL))
        PRINT_ORACLE_ERR("OCIInitialize");

        if (OCIEnvInit(&data->o_environment, OCI_DEFAULT, 0, NULL))
        PRINT_ORACLE_ERR("OCIEnvInit");

        if (OCIEnvInit(&data->o_environment, OCI_DEFAULT, 0, NULL))
        PRINT_ORACLE_ERR("OCIEnvInit (2)");

        if (OCIHandleAlloc(data->o_environment, (dvoid **)&data->o_error, OCI_HTYPE_ERROR, (size_t) 0, NULL))
        PRINT_ORACLE_ERR("OCIHandleAlloc");

        if (OCILogon(data->o_environment, data->o_error, &data->o_servicecontext,
                        data->user, strlen(data->user), data->password, strlen(data->password),
                        data->dbRH[data->dbtype_id]->dbname, strlen(data->dbRH[data->dbtype_id]->dbname)))
        {
            OCIErrorGet(data->o_error, 1, NULL, &data->o_errorcode, data->o_errormsg, sizeof(data->o_errormsg), OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("ERROR database: Checklist: check database is listed in tnsnames.ora\n");
            ErrorMessage("ERROR database:            check tnsnames.ora readable\n");
            ErrorMessage("ERROR database:            check database accessible with sqlplus\n");
            FatalError("database OCILogon : Connection to database '%s' failed\n", data->dbRH[data->dbtype_id]->dbname);
        }

        if (OCIHandleAlloc(data->o_environment, (dvoid **)&data->o_statement, OCI_HTYPE_STMT, 0, NULL))
        PRINT_ORACLE_ERR("OCIHandleAlloc (2)");
        break;
#endif

#ifdef ENABLE_MSSQL

        case DB_MSSQL:

        CLEARSTATEMENT();
        dberrhandle(mssql_err_handler);
        dbmsghandle(mssql_msg_handler);

        if( dbinit() != NULL )
        {
            data->ms_login = dblogin();
            if( data->ms_login == NULL )
            {
                FatalError("database Failed to allocate login structure\n");
            }
            /* Set up some informational values which are stored with the connection */
            DBSETLUSER (data->ms_login, data->user);
            DBSETLPWD (data->ms_login, data->password);
            DBSETLAPP (data->ms_login, "snort");

            data->ms_dbproc = dbopen(data->ms_login, data->host);
            if( data->ms_dbproc == NULL )
            {
                FatalError("database Failed to logon to host '%s'\n", data->host);
            }
            else
            {
                if( dbuse( data->ms_dbproc, data->dbRH[data->dbtype_id]->dbname ) != SUCCEED )
                {
                    FatalError("database Unable to change context to database '%s'\n", data->dbRH[data->dbtype_id]->dbname);
                }
            }
        }
        else
        {
            FatalError("database Connection to database '%s' failed\n", data->dbRH[data->dbtype_id]->dbname);
        }
        CLEARSTATEMENT();
        break;
#endif

    default:
        FatalError(
                "database [%s()]: Invoked with unknown database type [%u] \n",
                __FUNCTION__, data->dbtype_id);

        break;

    }

    return;

}

/*******************************************************************************
 * Function: Disconnect(DatabaseData * data)
 *
 * Purpose: Database independent function to close a connection
 *
 ******************************************************************************/
void Disconnect(DatabaseData * data, uint8_t q_sock)
{
    if (data == NULL) {
        FatalError("database [%s()]: Invoked with NULL data \n", __FUNCTION__);
    }

    LogMessage("database: Closing connection to database \"%s\"\n",
            data->dbname);

    switch (data->dbtype_id) {
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

    if(data->p_result)
    {
        PQclear(data->p_result);
        data->p_result = NULL;
    }

    if(data->p_connection)
    {
        PQfinish(data->p_connection);
        data->p_connection = NULL;
    }
    break;

#endif

#ifdef ENABLE_MYSQL
    case DB_MYSQL:
        if (data->m_dbins[q_sock].m_result) {
            mysql_free_result(data->m_dbins[q_sock].m_result);
            data->m_dbins[q_sock].m_result = NULL;
        }

        if (data->m_dbins[q_sock].m_sock) {
            mysql_close(data->m_dbins[q_sock].m_sock);
            data->m_dbins[q_sock].m_sock = NULL;
        }
        break;
#endif

#ifdef ENABLE_ODBC

        case DB_ODBC:

        if(data->u_handle)
        {
            SQLDisconnect(data->u_connection);
            SQLFreeHandle(SQL_HANDLE_ENV, data->u_handle);
        }
        break;
#endif

#ifdef ENABLE_ORACLE
        case DB_ORACLE:

        if(data->o_servicecontext)
        {
            OCILogoff(data->o_servicecontext, data->o_error);
            if(data->o_error)
            {
                OCIHandleFree((dvoid *)data->o_error, OCI_HTYPE_ERROR);
            }
            if(data->o_statement)
            {
                OCIHandleFree((dvoid *)data->o_statement, OCI_HTYPE_STMT);
            }
        }
        break;
#endif

#ifdef ENABLE_MSSQL

        case DB_MSSQL:

        CLEARSTATEMENT();
        if( data->ms_dbproc != NULL )
        {
            dbfreelogin(data->ms_login);
            data->ms_login = NULL;
            dbclose(data->ms_dbproc);
            data->ms_dbproc = NULL;
        }
        break;
#endif

    default:
        FatalError(
                "database [%s()]: Invoked with unknown database type [%u] \n",
                __FUNCTION__, data->dbtype_id);
        break;

    }

    return;
}

void DatabasePrintUsage(void) {
    puts("\nUSAGE: database plugin\n");

    puts(
            " output database: [log | alert], [type of database], [parameter list]\n");
    puts(" [log | alert] selects whether the plugin will use the alert or");
    puts(" log facility.\n");

    puts(" For the first argument, you must supply the type of database.");
    puts(" The possible values are mysql, postgresql, odbc, oracle and");
    puts(" mssql ");

    puts(" The parameter list consists of key value pairs. The proper");
    puts(" format is a list of key=value pairs each separated a space.\n");

    puts(" The only parameter that is absolutely necessary is \"dbname\".");
    puts(" All other parameters are optional but may be necessary");
    puts(" depending on how you have configured your RDBMS.\n");

    puts(" dbname - the name of the database you are connecting to\n");

    puts(" host - the host the RDBMS is on\n");

    puts(" port - the port number the RDBMS is listening on\n");

    puts(" user - connect to the database as this user\n");

    puts(" password - the password for given user\n");

    puts(
            " sensor_name - specify your own name for this barnyard2 sensor. If you");
    puts("        do not specify a name one will be generated automatically\n");

    puts(" encoding - specify a data encoding type (hex, base64, or ascii)\n");

    puts(" detail - specify a detail level (full or fast)\n");

    puts(
            " ignore_bpf - specify if you want to ignore the BPF part for a sensor\n");
    puts("              definition (yes or no, no is default)\n");

    puts(" FOR EXAMPLE:");
    puts(" The configuration I am currently using is MySQL with the database");
    puts(
            " name of \"snort\". The user \"snortusr@localhost\" has INSERT and SELECT");
    puts(
            " privileges on the \"snort\" database and does not require a password.");
    puts(" The following line enables barnyard2 to log to this database.\n");

    puts(
            " output database: log, mysql, dbname=snort user=snortusr host=localhost\n");
}

/*******************************************************************************
 * Function: Insert(char * query, DatabaseData * data)
 *
 * Purpose: Database independent function for SQL inserts
 *
 * Arguments: query (An SQL insert)
 *            q_sock (query m_sock instance)
 *
 * Returns:
 * 0 OK
 * 1 Error
 ******************************************************************************/
int Insert(char * query, DatabaseData * data, u_int32_t inTransac, uint8_t q_sock)
{
#ifdef ENABLE_ODBC
    long fRes = 0;
#endif

#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */

    if ((query == NULL) || (data == NULL) || checkDatabaseType(data)) {
        LogMessage("Invalid queryString or data configure\n");
        return 1;
    }

    /* This mainly has been set for Rollback */
    if ( (1==inTransac) || (2 == inTransac)) {
        if (checkTransactionCall(&data->m_dbins[q_sock])) {
            /* A This shouldn't happen since we are in failed transaction state */
            LogMessage("in failed transaction state, stop proceed Insertion\n");
            return 1;
        }
    }

    if ((data->dbRH[data->dbtype_id].dbConnectionStatus(
            &data->dbRH[data->dbtype_id], q_sock))) {
        LogMessage("Insert Query[%s] failed check to dbConnectionStatus()\n",
                query);
        return 1;
    }

#ifdef ENABLE_POSTGRESQL
    if( data->dbtype_id == DB_POSTGRESQL )
    {
        data->p_result = PQexec(data->p_connection,query);
        if(!(PQresultStatus(data->p_result) != PGRES_COMMAND_OK))
        {
            result = 0;
        }
        else
        {
            if(PQerrorMessage(data->p_connection)[0] != '\0')
            {
                ErrorMessage("ERROR database: database: postgresql_error: %s\n",
                        PQerrorMessage(data->p_connection));
                return 1;
            }
        }
        PQclear(data->p_result);
        data->p_result = NULL;
        return 0;
    }
#endif

#ifdef ENABLE_MYSQL
    if (data->dbtype_id == DB_MYSQL) {
        result = mysql_query(data->m_dbins[q_sock].m_sock, query);

        switch (result) {

        case 0:
            return 0;
            break;

        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
            /* XXX */
            /* Could lead to some corruption lets exit nicely .. */
            /* Since this model of the database incluse a lot of atomic queries .....*/
            if ((mysql_errno(data->m_dbins[q_sock].m_sock))) {

                FatalError("database mysql_error: %s, errno: %d\n\tSQL=[%s]\n",
                        mysql_error(data->m_dbins[q_sock].m_sock), mysql_errno(data->m_dbins[q_sock].m_sock), query);

            } else {
                LogMessage("Unknown SQL error(return:%d), Insertion failed\n", result);
                return 1;
            }
            break;
        }
    }
#endif

#ifdef ENABLE_ODBC
    if(data->dbtype_id == DB_ODBC)
    {
        if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
        {
            fRes = SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)query, SQL_NTS);

            if( (fRes != SQL_SUCCESS) ||
                    (fRes != SQL_SUCCESS_WITH_INFO))
            {
                result = 0;
                SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                return 0;
            }
            else
            {
                LogMessage("execdirect failed \n");
            }
        }
        else
        {
            LogMessage("stmtalloc failed \n");
        }

        LogMessage("[%s()], failed insert [%s], \n",
                __FUNCTION__,
                query);
        ODBCPrintError(data,SQL_HANDLE_STMT);
        SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
    }
#endif

#ifdef ENABLE_ORACLE
    if(data->dbtype_id == DB_ORACLE)
    {
        char *blob = NULL;

        /* If BLOB type - split query to actual SQL and blob to BLOB data */
        if(strncasecmp(query,"INSERT INTO data",16)==0 || strncasecmp(query,"INSERT INTO opt",15)==0)
        {
            if((blob=strchr(query,'|')) != NULL)
            {
                *blob='\0'; blob++;
            }
        }

        if(OCI_SUCCESS == OCIStmtPrepare(data->o_statement
                        , data->o_error
                        , query
                        , strlen(query)
                        , OCI_NTV_SYNTAX
                        , OCI_DEFAULT))
        {
            if( blob != NULL )
            {
                OCIBindByPos(data->o_statement
                        , &data->o_bind
                        , data->o_error
                        , 1
                        , (dvoid *)blob
                        , strlen(blob)
                        , SQLT_BIN
                        , 0
                        , 0
                        , 0
                        , 0
                        , 0
                        , OCI_DEFAULT);
            }

            if(OCI_SUCCESS == OCIStmtExecute(data->o_servicecontext
                            , data->o_statement
                            , data->o_error
                            , 1
                            , 0
                            , NULL
                            , NULL
                            , OCI_COMMIT_ON_SUCCESS))
            {
                result = 0;
            }
        }

        if( result != 1 )
        {
            OCIErrorGet(data->o_error
                    , 1
                    , NULL
                    , &data->o_errorcode
                    , data->o_errormsg
                    , sizeof(data->o_errormsg)
                    , OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("        : query: %s\n", query);
        }
    }
#endif

#ifdef ENABLE_MSSQL
    if(data->dbtype_id == DB_MSSQL)
    {
        SAVESTATEMENT(query);
        dbfreebuf(data->ms_dbproc);
        if( dbcmd(data->ms_dbproc, query) == SUCCEED )
        if( dbsqlexec(data->ms_dbproc) == SUCCEED )
        if( dbresults(data->ms_dbproc) == SUCCEED )
        {
            while (dbnextrow(data->ms_dbproc) != NO_MORE_ROWS)
            {
                result = (int)data->ms_col;
            }
            result = 0;
        }
        CLEARSTATEMENT();
    }
#endif

    return 1;
}

/*******************************************************************************
 * Function: Insert(char * query, DatabaseData * data)
 *
 * Purpose: Database independent function for SQL inserts
 *
 * Arguments: query (An SQL insert)
 *
 * Returns:
 * 0 OK
 * 1 Error
 ******************************************************************************/
int Insert_real(char * query, uint32_t query_len, DatabaseData * data, u_int32_t inTransac, uint8_t q_sock)
{
#ifdef ENABLE_ODBC
    long fRes = 0;
#endif

#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */

    if ((query == NULL) || (data == NULL) || checkDatabaseType(data)) {
        /* XXX */
        return 1;
    }

    /* This mainly has been set for Rollback */
    if (inTransac == 1) {
        if (checkTransactionCall(&data->m_dbins[q_sock])) {
            /* A This shouldn't happen since we are in failed transaction state */
            /* XXX */
            return 1;
        }
    }

    if ((data->dbRH[data->dbtype_id].dbConnectionStatus(
            &data->dbRH[data->dbtype_id], q_sock))) {
        /* XXX */
        LogMessage("Insert Query[%s] failed check to dbConnectionStatus()\n",
                query);
        return 1;
    }

#ifdef ENABLE_POSTGRESQL
    if( data->dbtype_id == DB_POSTGRESQL )
    {
        data->p_result = PQexec(data->p_connection,query);
        if(!(PQresultStatus(data->p_result) != PGRES_COMMAND_OK))
        {
            result = 0;
        }
        else
        {
            if(PQerrorMessage(data->p_connection)[0] != '\0')
            {
                ErrorMessage("ERROR database: database: postgresql_error: %s\n",
                        PQerrorMessage(data->p_connection));
                return 1;
            }
        }
        PQclear(data->p_result);
        data->p_result = NULL;
        return 0;
    }
#endif

#ifdef ENABLE_MYSQL
    if (data->dbtype_id == DB_MYSQL) {
        result = mysql_real_query(data->m_dbins[q_sock].m_sock, query, query_len);

        switch (result) {

        case 0:
            return 0;
            break;

        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
            /* XXX */
            /* Could lead to some corruption lets exit nicely .. */
            /* Since this model of the database incluse a lot of atomic queries .....*/
            if ((mysql_errno(data->m_dbins[q_sock].m_sock))) {

                FatalError("database mysql_error: %s\n\tSQL=[%s]\n",
                        mysql_error(data->m_dbins[q_sock].m_sock), query);

            } else {
                /* XXX */
                return 1;
            }
            break;
        }

    }
#endif

#ifdef ENABLE_ODBC
    if(data->dbtype_id == DB_ODBC)
    {
        if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
        {
            fRes = SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)query, SQL_NTS);

            if( (fRes != SQL_SUCCESS) ||
                    (fRes != SQL_SUCCESS_WITH_INFO))
            {
                result = 0;
                SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                return 0;
            }
            else
            {
                LogMessage("execdirect failed \n");
            }
        }
        else
        {
            LogMessage("stmtalloc failed \n");
        }

        LogMessage("[%s()], failed insert [%s], \n",
                __FUNCTION__,
                query);
        ODBCPrintError(data,SQL_HANDLE_STMT);
        SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
    }
#endif

#ifdef ENABLE_ORACLE
    if(data->dbtype_id == DB_ORACLE)
    {
        char *blob = NULL;

        /* If BLOB type - split query to actual SQL and blob to BLOB data */
        if(strncasecmp(query,"INSERT INTO data",16)==0 || strncasecmp(query,"INSERT INTO opt",15)==0)
        {
            if((blob=strchr(query,'|')) != NULL)
            {
                *blob='\0'; blob++;
            }
        }

        if(OCI_SUCCESS == OCIStmtPrepare(data->o_statement
                        , data->o_error
                        , query
                        , strlen(query)
                        , OCI_NTV_SYNTAX
                        , OCI_DEFAULT))
        {
            if( blob != NULL )
            {
                OCIBindByPos(data->o_statement
                        , &data->o_bind
                        , data->o_error
                        , 1
                        , (dvoid *)blob
                        , strlen(blob)
                        , SQLT_BIN
                        , 0
                        , 0
                        , 0
                        , 0
                        , 0
                        , OCI_DEFAULT);
            }

            if(OCI_SUCCESS == OCIStmtExecute(data->o_servicecontext
                            , data->o_statement
                            , data->o_error
                            , 1
                            , 0
                            , NULL
                            , NULL
                            , OCI_COMMIT_ON_SUCCESS))
            {
                result = 0;
            }
        }

        if( result != 1 )
        {
            OCIErrorGet(data->o_error
                    , 1
                    , NULL
                    , &data->o_errorcode
                    , data->o_errormsg
                    , sizeof(data->o_errormsg)
                    , OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("        : query: %s\n", query);
        }
    }
#endif

#ifdef ENABLE_MSSQL
    if(data->dbtype_id == DB_MSSQL)
    {
        SAVESTATEMENT(query);
        dbfreebuf(data->ms_dbproc);
        if( dbcmd(data->ms_dbproc, query) == SUCCEED )
        if( dbsqlexec(data->ms_dbproc) == SUCCEED )
        if( dbresults(data->ms_dbproc) == SUCCEED )
        {
            while (dbnextrow(data->ms_dbproc) != NO_MORE_ROWS)
            {
                result = (int)data->ms_col;
            }
            result = 0;
        }
        CLEARSTATEMENT();
    }
#endif

    return 1;
}

/*******************************************************************************
 * Function: Select(char * query, DatabaeData * data, u_int32_t *rval)
 *
 *
 *
 * Returns:
 * 0 OK
 * 1 ERROR
 ******************************************************************************/
int Select(char * query, DatabaseData * data, u_int32_t *rval, uint8_t q_sock)
{
#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */
    uint8_t retry_num = 10;

    if ((query == NULL) || (data == NULL) || (rval == NULL)) {
        /* XXX */
        FatalError(
                "database [%s()] Invoked with a NULL argument Query [0x%x] Data [0x%x] rval [0x%x] \n",
                __FUNCTION__, query, data, rval);
    }

    if (checkTransactionCall(&data->m_dbins[q_sock])) {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
#if defined(ENABLE_MYSQL)
    Select_reconnect:
#endif /* defined(ENABLE_MYSQL) */

    if ((data->dbRH[data->dbtype_id].dbConnectionStatus(
            &data->dbRH[data->dbtype_id], q_sock))) {
        /* XXX */
        FatalError(
                "database Select Query[%s] failed check to dbConnectionStatus()\n",
                query);
    }

    switch (data->dbtype_id) {

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

    data->p_result = PQexec(data->p_connection,query);
    if((PQresultStatus(data->p_result) == PGRES_TUPLES_OK))
    {
        if(PQntuples(data->p_result))
        {
            if((PQntuples(data->p_result)) > 1)
            {
                ErrorMessage("ERROR database: Query [%s] returned more than one result\n",
                        query);
                result = 0;
                PQclear(data->p_result);
                data->p_result = NULL;
                return 1;
            }
            else
            {
                *rval = atoi(PQgetvalue(data->p_result,0,0));
            }
        }
        else
        {
            PQclear(data->p_result);
            data->p_result = NULL;
            return 1;
        }
    }

    if(!result)
    {
        if(PQerrorMessage(data->p_connection)[0] != '\0')
        {
            ErrorMessage("ERROR database: postgresql_error: %s\n",
                    PQerrorMessage(data->p_connection));
            return 1;
        }
    }

    PQclear(data->p_result);
    data->p_result = NULL;
    break;
#endif

#ifdef ENABLE_MYSQL
    case DB_MYSQL:

        result = mysql_query(data->m_dbins[q_sock].m_sock, query);

        switch (result) {
        case 0:
            if ((data->m_dbins[q_sock].m_result
                    = mysql_use_result(data->m_dbins[q_sock].m_sock)) == NULL) {
                *rval = 0;
                return 1;
            } else {
                if ((data->m_dbins[q_sock].m_row
                        = mysql_fetch_row(data->m_dbins[q_sock].m_result)) == NULL) {
                    /* XXX */
                    *rval = 0;
                    mysql_free_result(data->m_dbins[q_sock].m_result);
                    data->m_dbins[q_sock].m_result = NULL;
                    return 1;
                } else {
                    if (data->m_dbins[q_sock].m_row[0] != NULL) {
                        *rval = atoi(data->m_dbins[q_sock].m_row[0]);
                    } else {
                        /* XXX */
                        *rval = 0;
                        mysql_free_result(data->m_dbins[q_sock].m_result);
                        data->m_dbins[q_sock].m_result = NULL;
                        return 1;
                    }

                }
                mysql_free_result(data->m_dbins[q_sock].m_result);
                data->m_dbins[q_sock].m_result = NULL;
                return 0;
            }
            break;

        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:

            if (checkTransactionState(&data->m_dbins[q_sock])) {
                LogMessage(
                        "[%s()]: Failed executing with error [%s], in transaction will Abort. \n"
                                "\t Failed QUERY: [%s] \n", __FUNCTION__,
                        mysql_error(data->m_dbins[q_sock].m_sock), query);
                return 1;
            }

            LogMessage("[%s()]: Failed to execute with error [%s], query [%s]",
                    __FUNCTION__, mysql_error(data->m_dbins[q_sock].m_sock), query);
            if ( retry_num-- ) {
                LogMessage(", will retry \n");
            }
            else {
                LogMessage(", abort \n");
                return 1;
            }

            goto Select_reconnect;
            break;
        }

        *rval = 0;
        return 1;

        break;

#endif

#ifdef ENABLE_ODBC
        case DB_ODBC:

        if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
        {
            //if(SQLPrepare(data->u_statement, (ODBC_SQLCHAR *)query, SQL_NTS) == SQL_SUCCESS)
            //{
            //if(SQLExecute(data->u_statement) == SQL_SUCCESS)
            if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)query, SQL_NTS) == SQL_SUCCESS)
            {
                if(SQLRowCount(data->u_statement, &data->u_rows) == SQL_SUCCESS)
                {
                    if(data->u_rows)
                    {
                        if(data->u_rows > 1)
                        {
                            SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                            ErrorMessage("ERROR database: Query [%s] returned more than one result\n", query);
                            result = 0;
                            return 1;
                        }
                        else
                        {
                            if(SQLFetch(data->u_statement) == SQL_SUCCESS)
                            {
                                if(SQLGetData(data->u_statement,1,SQL_INTEGER,
                                                &data->u_col,
                                                sizeof(data->u_col), NULL) == SQL_SUCCESS)
                                {
                                    *rval = (int)data->u_col;
                                    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);

                                }
                            }
                            else
                            {
                                SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                                return 1;
                            }
                        }
                    }
                    else
                    {
                        SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                        return 1;
                    }
                }
            }
        }
        break;
#endif

#ifdef ENABLE_ORACLE
        case DB_ORACLE:

        int success = 0; /* assume it will fail */
        if(OCI_SUCCESS == OCIStmtPrepare(data->o_statement
                        , data->o_error
                        , query
                        , strlen(query)
                        , OCI_NTV_SYNTAX
                        , OCI_DEFAULT))
        {
            if(OCI_SUCCESS == OCIDefineByPos(data->o_statement
                            , &data->o_define
                            , data->o_error
                            , 1
                            , &result
                            , sizeof(result)
                            , SQLT_INT
                            , 0
                            , 0
                            , 0
                            , OCI_DEFAULT))
            {
                sword status;
                status = OCIStmtExecute(data->o_servicecontext
                        , data->o_statement
                        , data->o_error
                        , 1 /*0*/
                        , 0
                        , NULL
                        , NULL
                        , OCI_DEFAULT);
                if( status==OCI_SUCCESS || status==OCI_NO_DATA )
                {
                    success = 1;
                }
            }
        }

        if( ! success )
        {
            OCIErrorGet(data->o_error
                    , 1
                    , NULL
                    , &data->o_errorcode
                    , data->o_errormsg
                    , sizeof(data->o_errormsg)
                    , OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("        : query: %s\n", query);
        }

        break;
#endif

#ifdef ENABLE_MSSQL
        case DB_MSSQL:

        SAVESTATEMENT(query);
        dbfreebuf(data->ms_dbproc);
        if( dbcmd(data->ms_dbproc, query) == SUCCEED )
        if( dbsqlexec(data->ms_dbproc) == SUCCEED )
        if( dbresults(data->ms_dbproc) == SUCCEED )
        if( dbbind(data->ms_dbproc, 1, INTBIND, (DBINT) 0, (BYTE *) &data->ms_col) == SUCCEED )
        while (dbnextrow(data->ms_dbproc) != NO_MORE_ROWS)
        {
            result = (int)data->ms_col;
        }
        CLEARSTATEMENT();

        break;

#endif

    default:
        FatalError(
                "database [%s()]: Invoked with unknown database type [%u] \n",
                __FUNCTION__, data->dbtype_id);
    }

    return 0;
}

/*******************************************************************************
 * Function: Select(char * query, DatabaeData * data, uint64_t *rval)
 *
 *
 *
 * Returns:
 * 0 OK
 * 1 ERROR
 ******************************************************************************/
int Select_bigint(char * query, DatabaseData * data, uint64_t *rval, uint8_t q_sock)
{
#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */
    uint8_t retry_num = 10;
    char *p;

    if ((query == NULL) || (data == NULL) || (rval == NULL)) {
        /* XXX */
        FatalError(
                "database [%s()] Invoked with a NULL argument Query [0x%x] Data [0x%x] rval [0x%x] \n",
                __FUNCTION__, query, data, rval);
    }

    if (checkTransactionCall(&data->m_dbins[q_sock])) {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
#if defined(ENABLE_MYSQL)
    Select_reconnect:
#endif /* defined(ENABLE_MYSQL) */

    if ((data->dbRH[data->dbtype_id].dbConnectionStatus(
            &data->dbRH[data->dbtype_id], q_sock))) {
        /* XXX */
        FatalError(
                "database Select Query[%s] failed check to dbConnectionStatus()\n",
                query);
    }

    switch (data->dbtype_id) {
#ifdef ENABLE_MYSQL
    case DB_MYSQL:
        result = mysql_query(data->m_dbins[q_sock].m_sock, query);
        switch (result) {
        case 0:
            if ((data->m_dbins[q_sock].m_result
                    = mysql_use_result(data->m_dbins[q_sock].m_sock)) == NULL) {
                *rval = 0;
                return 1;
            } else {
                if ((data->m_dbins[q_sock].m_row
                        = mysql_fetch_row(data->m_dbins[q_sock].m_result)) == NULL) {
                    /* XXX */
                    *rval = 0;
                    mysql_free_result(data->m_dbins[q_sock].m_result);
                    data->m_dbins[q_sock].m_result = NULL;
                    return 1;
                } else {
                    if (data->m_dbins[q_sock].m_row[0] != NULL) {
                        *rval = strtoul(data->m_dbins[q_sock].m_row[0], &p, 10);
                    } else {
                        /* XXX */
                        *rval = 0;
                        mysql_free_result(data->m_dbins[q_sock].m_result);
                        data->m_dbins[q_sock].m_result = NULL;
                        return 1;
                    }

                }
                mysql_free_result(data->m_dbins[q_sock].m_result);
                data->m_dbins[q_sock].m_result = NULL;
                return 0;
            }
            break;

        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:

            if (checkTransactionState(&data->m_dbins[q_sock])) {
                LogMessage(
                        "[%s()]: Failed executing with error [%s], in transaction will Abort. \n"
                                "\t Failed QUERY: [%s] \n", __FUNCTION__,
                        mysql_error(data->m_dbins[q_sock].m_sock), query);
                return 1;
            }

            LogMessage("[%s()]: Failed to execute with error [%s], query [%s]",
                    __FUNCTION__, mysql_error(data->m_dbins[q_sock].m_sock), query);
            if ( retry_num-- ) {
                LogMessage(", will retry \n");
            }
            else {
                LogMessage(", abort \n");
                return 1;
            }

            goto Select_reconnect;
            break;
        }

        /* XXX */
        *rval = 0;
        return 1;
        break;
#endif
    default:
        FatalError(
                "database [%s()]: Invoked with unknown database type [%u] \n",
                __FUNCTION__, data->dbtype_id);
    }

    return 0;
}

void resetTransactionState(DatabaseIns *d_ins) {
    if ( NULL == d_ins ) {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    d_ins->checkTransaction = 0;
    d_ins->transactionCallFail = 0;

    /* seem'ed to cause loop */
    //pdbRH->transactionErrorCount = 0;
    return;
}

void setTransactionState(DatabaseIns *d_ins)
{
    if ( NULL == d_ins ) {
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    d_ins->checkTransaction = 1;
    return;
}

void setTransactionCallFail(DatabaseIns *d_ins)
{
    LogMessage( "%s: Rollback\n", __func__);

    if ( NULL == d_ins ) {
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    if ( d_ins->checkTransaction ) {
        d_ins->transactionCallFail = 1;
        d_ins->transactionErrorCount++;
    }

    return;
}

u_int32_t getReconnectState(DatabaseIns *d_ins)
{
    if ( NULL == d_ins ) {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    return d_ins->dbReconnectedInTransaction;
}

void setReconnectState(DatabaseIns *d_ins, u_int32_t reconnection_state)
{
    if ( NULL == d_ins ) {
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    d_ins->dbReconnectedInTransaction = reconnection_state;
    return;
}

u_int32_t checkTransactionState(DatabaseIns *d_ins)
{
    if ( NULL == d_ins ) {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    return d_ins->checkTransaction;
}

u_int32_t checkTransactionCall(DatabaseIns *d_ins)
{
    if ( NULL == d_ins ) {
        FatalError("database [%s()] called with a null dbReliabilityHandle",
                __FUNCTION__);
    }

    if (checkTransactionState(d_ins)) {
        return d_ins->transactionCallFail;
    }

    return 0;
}

u_int32_t dbReconnectSetCounters(dbReliabilityHandle *pdbRH, DatabaseIns *d_ins)
{
    struct timespec sleepRet = { 0 };

    if ( NULL == pdbRH || NULL == d_ins ) {
        return 1;
    }

    if (d_ins->dbConnectionCount < pdbRH->dbConnectionLimit) {
        d_ins->dbConnectionCount++; /* Database Reconnected it seem... */

        if (nanosleep(&pdbRH->dbReconnectSleepTime, &sleepRet) < 0) {
            perror("dbReconnectSetCounter():");
            LogMessage("[%s() ]Call to nanosleep(): Failed with [%u] seconds left and [%u] microsecond left \n",
                    __FUNCTION__, sleepRet.tv_sec, sleepRet.tv_nsec);
            return 1;
        }
        return 0;
    }

    return 1;
}

u_int32_t dbReconnectReSetCounters(DatabaseIns *d_ins)
{
    if ( NULL == d_ins ) {
        return 1;
    }

    d_ins->dbConnectionCount = 0;
    return 0;
}

#ifdef ENABLE_MYSQL
u_int32_t MYSQL_ManualConnect(DatabaseData *dbdata, uint8_t q_sock)
{
    if (dbdata == NULL) {
        /* XXX */
        return 1;
    }

    if (dbdata->m_dbins[q_sock].m_sock != NULL) {
        mysql_close(dbdata->m_dbins[q_sock].m_sock);
        dbdata->m_dbins[q_sock].m_sock = NULL;
    }

    dbdata->m_dbins[q_sock].m_sock = mysql_init(NULL);
    if (NULL == dbdata->m_dbins[q_sock].m_sock) {
        FatalError("database Connection to database '%s' failed\n",
                dbdata->dbname);
    }

    /* check if we want to connect with ssl options */
    if (dbdata->use_ssl == 1) {
        mysql_ssl_set(dbdata->m_dbins[q_sock].m_sock, dbdata->dbRH[dbdata->dbtype_id].ssl_key,
                dbdata->dbRH[dbdata->dbtype_id].ssl_cert,
                dbdata->dbRH[dbdata->dbtype_id].ssl_ca,
                dbdata->dbRH[dbdata->dbtype_id].ssl_ca_path,
                dbdata->dbRH[dbdata->dbtype_id].ssl_cipher);
    }

    if (mysql_real_connect(dbdata->m_dbins[q_sock].m_sock, dbdata->host, dbdata->user,
            dbdata->password, dbdata->dbname,
            dbdata->port == NULL ? 0 : atoi(dbdata->port), NULL, CLIENT_INTERACTIVE) == NULL) {
        if (mysql_errno(dbdata->m_dbins[q_sock].m_sock))
            LogMessage("database: mysql_error: %s\n",
                    mysql_error(dbdata->m_dbins[q_sock].m_sock));

        LogMessage("database: Failed to logon to database '%s'\n",
                dbdata->dbname);

        mysql_close(dbdata->m_dbins[q_sock].m_sock);
        dbdata->m_dbins[q_sock].m_sock = NULL;
        return 1;
    }

    if (mysql_autocommit(dbdata->m_dbins[q_sock].m_sock, 0)) {
        /* XXX */
        LogMessage("database Can't set autocommit off \n");
        mysql_close(dbdata->m_dbins[q_sock].m_sock);
        dbdata->m_dbins[q_sock].m_sock = NULL;
        return 1;
    }

    /* We are in manual connect mode */
    if (mysql_options(dbdata->m_dbins[q_sock].m_sock, MYSQL_OPT_RECONNECT,
            &dbdata->dbRH[dbdata->dbtype_id].mysql_reconnect) != 0) {
        LogMessage("database: Failed to set reconnect option: %s\n",
                mysql_error(dbdata->m_dbins[q_sock].m_sock));
        mysql_close(dbdata->m_dbins[q_sock].m_sock);
        dbdata->m_dbins[q_sock].m_sock = NULL;
        return 1;
    }

    /* Get the new thread id */
    dbdata->m_dbins[q_sock].pThreadID = mysql_thread_id(dbdata->m_dbins[q_sock].m_sock);

    return 0;
}

u_int32_t dbConnectionStatusMYSQL(dbReliabilityHandle *pdbRH, uint8_t q_sock)
{
    unsigned long aThreadID = 0; /* after  mysql_ping call thread_id */
    int ping_ret = 0;
    MYSQL * m_sock;
    DatabaseData *dbdata = NULL;

    if ((pdbRH == NULL) || (pdbRH->dbdata == NULL)) {
        return 1;
    }

    dbdata = pdbRH->dbdata;
    m_sock = dbdata->m_dbins[q_sock].m_sock;
    if (NULL == m_sock)
        return 1;

MYSQL_RetryConnection:
    /* mysql_ping() could reconnect and we wouldn't know */
    aThreadID = mysql_thread_id(m_sock);
    ping_ret = mysql_ping(m_sock);

    /* We might try to recover from this */
    if (pdbRH->mysql_reconnect) {
        switch (ping_ret) {
        case 0:
            if (aThreadID != dbdata->m_dbins[q_sock].pThreadID) {
                /* mysql ping reconnected,
                 we need to check if we are in a transaction
                 and if we are we bail, since the resulting issued commands would obviously fail
                 */
                if (dbReconnectSetCounters(pdbRH, &dbdata->m_dbins[q_sock])) {
                    FatalError("database [%s()]: Too much reconnection, "
                            "the process will need to be restarted \n",
                            __FUNCTION__);
                }

                if (checkTransactionState(&dbdata->m_dbins[q_sock])) {
                    /* ResetState for the caller */
                    setReconnectState(&dbdata->m_dbins[q_sock], 1);
                    setTransactionCallFail(&dbdata->m_dbins[q_sock]);
                    setTransactionState(&dbdata->m_dbins[q_sock]);
                }

                dbdata->m_dbins[q_sock].pThreadID = aThreadID;

                /* make sure are are off auto_commit */
                if (mysql_autocommit(m_sock, 0)) {
                    LogMessage("database Can't set autocommit off \n");
                    return 1;
                }

                /* make shure we keep the option on ..*/
                if ( mysql_options(m_sock, MYSQL_OPT_RECONNECT,
                        &(pdbRH->mysql_reconnect) ) != 0) {
                    LogMessage("database: Failed to set reconnect option: %s\n",
                            mysql_error(m_sock));
                    return 1;
                }

                LogMessage("Warning: {MYSQL} The database connection has reconnected"
                        " it self to the database server, via a call to mysql_ping() new thread id is [%u] \n",
                        aThreadID);
                return 0;
            } else {
                /* Safety */
                dbdata->m_dbins[q_sock].pThreadID = aThreadID;

                /*
                 make sure are are off auto_commit, since we are in auto_commit and mysql doc is not clear if
                 by using automatic reconnect we keep connection attribute, i just force them, since we do not call
                 MYSQL_ManualConnect
                 */

                if (mysql_autocommit(m_sock, 0)) {
                    LogMessage("database Can't set autocommit off \n");
                    return 1;
                }

                /* make shure we keep the option on ..*/
                if ( mysql_options(m_sock, MYSQL_OPT_RECONNECT,
                        &(pdbRH->mysql_reconnect) ) != 0) {
                    LogMessage("%s: Failed to set reconnect option: %s\n",
                            __func__, mysql_error(m_sock));
                    return 1;
                }
                return 0;
            }
            break;
        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
            if (checkTransactionState(&dbdata->m_dbins[q_sock])) {
                /* ResetState for the caller */
                LogMessage("%s: reconnect, setTransactionCallFail"
                        ", ping_ret %d\n", __func__, ping_ret);
                setReconnectState(&dbdata->m_dbins[q_sock], 1);
                setTransactionCallFail(&dbdata->m_dbins[q_sock]);
                setTransactionState(&dbdata->m_dbins[q_sock]);
            }

            if (dbReconnectSetCounters(pdbRH, &dbdata->m_dbins[q_sock])) {
                FatalError("database [%s()]: Too much reconnection, "
                        "the process will need to be restarted \n",
                        __FUNCTION__);
            }

            goto MYSQL_RetryConnection;
            break;
        }
    }
    else{    /* Manual Reconnect mode */
        switch (ping_ret) {
        case 0:
            if (aThreadID != dbdata->m_dbins[q_sock].pThreadID) {
                FatalError("database We are in {MYSQL} \"manual reconnect\" mode "
                        "and a call to mysql_ping() changed the mysql_thread_id, "
                        "this shouldn't happen the process will terminate \n");
            }
            break;
        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
            if (checkTransactionState(&dbdata->m_dbins[q_sock])) {
                /* ResetState for the caller */
                LogMessage("%s: no_reconnect(no setTransactionCallFail)"
                        ", ping_ret %d\n", __func__, ping_ret);
                setReconnectState(&dbdata->m_dbins[q_sock], 1);
                //setTransactionCallFail(pdbRH);
                setTransactionState(&dbdata->m_dbins[q_sock]);
            }

            if (dbReconnectSetCounters(pdbRH, &dbdata->m_dbins[q_sock])) {
                FatalError("database [%s()]: Too much reconnection, "
                        "the process will need to be restarted \n",
                        __FUNCTION__);
            }

            if ((MYSQL_ManualConnect(pdbRH->dbdata, q_sock))) {
                goto MYSQL_RetryConnection;
            }

            dbReconnectReSetCounters(&dbdata->m_dbins[q_sock]);
            break;
        }
        return 0;
    }

    LogMessage("[%s()], Reached a point of no return ...it shouldn't happen \n",
            __FUNCTION__);
    return 1;
}
#endif

#ifdef ENABLE_ODBC
u_int32_t dbConnectionStatusODBC(dbReliabilityHandle *pdbRH)
{
    DatabaseData *data = NULL;
    u_int32_t StateFail = 0;
    ODBC_SQLRETURN ret;
    ODBC_SQLCHAR sqlState[6];
    ODBC_SQLCHAR msg[SQL_MAX_MESSAGE_LENGTH] = {0};
    SQLINTEGER nativeError;
    SQLSMALLINT errorIndex = 1;
    SQLSMALLINT msgLen;

    //DEBUGGGGGGGGGGGGGGGGGGG
    return 0;
    //DEBUGGGGGGGGGGGGGGGGGGG

    if( (pdbRH == NULL) ||
            (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }
    data = pdbRH->dbdata;

    if(data->u_connection != NULL)
    {
        while ( (ret = SQLGetDiagRec( SQL_HANDLE_DBC
                                , data->u_connection
                                , errorIndex
                                , sqlState
                                , &nativeError
                                , msg
                                , SQL_MAX_MESSAGE_LENGTH
                                , &msgLen)) == SQL_SUCCESS)
        {
            if(StateFail == 0)
            {
                /* Destroy the statement handle */
                if(data->u_statement != NULL)
                {
                    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                }

                if(data->u_connection != NULL)
                {
                    SQLFreeHandle(SQL_HANDLE_DBC,data->u_connection);
                }

                if(data->u_handle != NULL)
                {
                    SQLFreeHandle(SQL_HANDLE_ENV,data->u_statement);
                }

                if(checkTransactionState(pdbRH))
                {
                    /* ResetState for the caller */
                    setReconnectState(pdbRH,1);
                    setTransactionCallFail(pdbRH);
                    setTransactionState(pdbRH);
                }
                StateFail = 1;

                if(!(SQLAllocEnv(&data->u_handle) == SQL_SUCCESS))
                {
                    FatalError("database unable to allocate ODBC environment\n");
                }

                if(!(SQLAllocConnect(data->u_handle, &data->u_connection) == SQL_SUCCESS))
                {
                    FatalError("database unable to allocate ODBC connection handle\n");
                }

                /* The SQL Server ODBC driver always returns SQL_SUCCESS_WITH_INFO
                 * on a successful SQLConnect, SQLDriverConnect, or SQLBrowseConnect.
                 * When an ODBC application calls SQLGetDiagRec after getting
                 * SQL_SUCCESS_WITH_INFO, it can receive the following messages:
                 * 5701 - Indicates that SQL Server put the user's context into the
                 *        default database defined in the data source, or into the
                 *        default database defined for the login ID used in the
                 *        connection if the data source did not have a default database.
                 * 5703 - Indicates the language being used on the server.
                 * You can ignore messages 5701 and 5703; they are only informational.
                 */
                ret = SQLConnect( data->u_connection
                        , (ODBC_SQLCHAR *)data->dbname
                        , SQL_NTS
                        , (ODBC_SQLCHAR *)data->user
                        , SQL_NTS
                        , (ODBC_SQLCHAR *)data->password
                        , SQL_NTS);

                if( (ret != SQL_SUCCESS) &&
                        (ret != SQL_SUCCESS_WITH_INFO))
                {
                    ODBCPrintError(data,SQL_HANDLE_DBC);
                    FatalError("database ODBC unable to connect.\n");
                }
            }
        }
    }

    return 0;

}
#endif  /* ENABLE_ODBC */

#ifdef ENABLE_POSTGRESQL
u_int32_t dbConnectionStatusPOSTGRESQL(dbReliabilityHandle *pdbRH)
{
    DatabaseData *data = NULL;

    int PQpingRet = 0;

    if( (pdbRH == NULL) ||
            (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }

    data = pdbRH->dbdata;

    conn_test:
    if(data->p_connection != NULL)
    {

#ifdef HAVE_PQPING
        switch( (PQpingRet = PQping(data->p_pingString)))
        {
            case PQPING_OK:
            break;

            case PQPING_NO_ATTEMPT:
            LogMessage("[%s()], PQPing call assumed [PQPING_NO_ATTEMPT] using connection string [%s], continuing \n",
                    __FUNCTION__,
                    data->p_pingString);
            break;

            case PQPING_REJECT:
            case PQPING_NO_RESPONSE:
            default:

            LogMessage("[%s()], PQPing call retval[%d] seem's to indicate unreacheable server, assuming connection is dead \n",
                    __FUNCTION__,
                    PQpingRet);

            if(checkTransactionState(pdbRH))
            {
                /* ResetState for the caller */
                setReconnectState(pdbRH,1);
                setTransactionCallFail(pdbRH);
                setTransactionState(pdbRH);
            }

            if(data->p_connection)
            {
                PQfinish(data->p_connection);
                data->p_connection = NULL;
            }
            break;
        }
#endif

        switch(PQstatus(data->p_connection))
        {
            case CONNECTION_OK:
            return 0;
            break;

            case CONNECTION_BAD:
            default:

            if(checkTransactionState(pdbRH))
            {
                /* ResetState for the caller */
                setReconnectState(pdbRH,1);
                setTransactionCallFail(pdbRH);
                setTransactionState(pdbRH);
            }

            failed_pqcon:
            if(dbReconnectSetCounters(pdbRH))
            {
                /* XXX */
                FatalError("database [%s()]: Call failed, the process will need to be restarted \n",__FUNCTION__);
            }

            /* Changed PQreset by call to PQfinish and PQdbLogin */
            if(data->p_connection)
            {
                PQfinish(data->p_connection);
                data->p_connection = NULL;
            }

            if (data->use_ssl == 1)
            {
                if( (data->p_connection =
                                PQsetdbLogin(data->host,
                                        data->port,
                                        data->dbRH[data->dbtype_id].ssl_mode,
                                        NULL,
                                        data->dbname,
                                        data->user,
                                        data->password)) == NULL)
                {
                    goto failed_pqcon;
                }
            }
            else
            {
                if( (data->p_connection =
                                PQsetdbLogin(data->host,
                                        data->port,
                                        NULL,
                                        NULL,
                                        data->dbname,
                                        data->user,
                                        data->password)) == NULL)
                {
                    goto failed_pqcon;
                }
            }

            goto conn_test;
            break;
        }

    }
    else
    {
        /* XXX */
        setTransactionCallFail(pdbRH);
        setTransactionState(pdbRH);
        return 1;
    }

    return 0;
}
#endif

#ifdef ENABLE_ORACLE
u_int32_t dbConnectionStatusORACLE(dbReliabilityHandle *pdbRH)
{
    if( (pdbRH == NULL) ||
            (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }

    return 0;
}
#endif

#ifdef ENABLE_MSSQL
u_int32_t dbConnectionStatusMSSQL(struct dbReliabilityHandle *pdbRH);
{
    if( (pdbRH == NULL) ||
            (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }

    return 0;
}
#endif

#ifdef ENABLE_ODBC
void ODBCPrintError(DatabaseData *data,SQLSMALLINT iHandleType)
{
    ODBC_SQLRETURN ret;
    ODBC_SQLCHAR sqlState[6];
    ODBC_SQLCHAR msg[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER nativeError;
    SQLSMALLINT errorIndex = 1;
    SQLSMALLINT msgLen;

    void * selected_handle;

    if(data == NULL)
    {
        /* XXX */
        return;
    }

    switch(iHandleType)
    {

        case SQL_HANDLE_DBC:
        selected_handle = data->u_connection;
        break;

        case SQL_HANDLE_STMT:
        selected_handle = data->u_statement;
        break;

        default:
        LogMessage("Database [%s()]: Unknown statement type [%u] \n",
                __FUNCTION__,
                iHandleType);
        return;
        break;
    }

    /* assume no errror unless nativeError tells us otherwise */
    while ( (ret = SQLGetDiagRec( iHandleType
                            , selected_handle
                            , errorIndex
                            , sqlState
                            , &nativeError
                            , msg
                            , SQL_MAX_MESSAGE_LENGTH
                            , &msgLen)) == SQL_SUCCESS)
    {
        ErrorMessage("[%s()]: Error Index [%u] Error Message [%s] \n",
                __FUNCTION__,
                errorIndex,
                msg);

        DEBUG_WRAP(LogMessage("database: %s\n", msg););
        errorIndex++;
    }

    return;
}
#endif /* ENABLE_ODBC */

/* Database Reliability */

