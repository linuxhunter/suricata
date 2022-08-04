#ifndef __UTIL_ICS_H
#define __UTIL_ICS_H
#include <mysql/mysql.h>

#define SQL_HOST        NULL
#define SQL_USER        NULL
#define SQL_PASSWD      NULL
#define SQL_PORT        0
#define SQL_SOCKET      "/tmp/mysql.sock"
#define SQL_CLNT_FLAG   0

#define DB_NAME			"audit_logs"
#define SQL_QUERY_SIZE	2048

typedef MYSQL* sql_handle;

sql_handle sql_db_connect(const char *db_name);
void sql_db_disconnect(sql_handle handle);
int sql_real_query(sql_handle handle, const char *qbuf, int len);
#endif
