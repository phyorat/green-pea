
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <time.h>

#include "squirrel.h"
#include "debug.h"
#include "util.h"

#include "spo_common.h"

/****************************************************************************
 *
 * Function: ts_print2(uint32_t, uint32_t, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision. Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void syslog_timestamp(uint32_t sec, uint32_t usec, char *timebuf)
{
    register int		s;
    int					localzone;
    time_t				Time;
    struct tm			*lt;    /* place to stick the adjusted clock data */
	char				*arr_month[] = {"Jan", "Feb", "Mar", "Apr", "May",
										"Jun", "Jul", "Aug", "Sep", "Oct",
										"Nov", "Dec"};
    localzone = barnyard2_conf->thiszone;
   
    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if(BcOutputUseUtc())
        localzone = 0;
        
    s = (sec + localzone) % 86400;
    Time = (sec + localzone) - s;

    lt = gmtime(&Time);

    SnortSnprintf(timebuf, TIMEBUF_SIZE, "%s %2d %02d:%02d:%02d",
		arr_month[lt->tm_mon], lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60);
}

void SPO_PrintUsage(void)
{
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

    //spooler output to mpool_ring
    puts(
            " output mpool_ring: [mmap], [mr-dpdk], [parameter list]\n");
}


