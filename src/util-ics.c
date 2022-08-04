#include "suricata-common.h"
#include "util-ics.h"

sql_handle sql_db_connect(const char *db_name)
{
    sql_handle handle;

    handle = mysql_init(NULL);
    if (handle == NULL) {
        goto out;
    }
    if (mysql_real_connect(handle, SQL_HOST, SQL_USER, SQL_PASSWD, db_name, SQL_PORT, SQL_SOCKET, SQL_CLNT_FLAG) == NULL) {
        mysql_close(handle);
        handle = NULL;
        goto out;
    }
out:
    return handle;
}

void sql_db_disconnect(sql_handle handle)
{
    mysql_close(handle);
    return;
}

int sql_real_query(sql_handle handle, const char *qbuf, int len)
{
    int status = 0;

    status = mysql_real_query(handle, qbuf, len);
    if (status != 0) {
        status = -1;
    }
    return status;
}

