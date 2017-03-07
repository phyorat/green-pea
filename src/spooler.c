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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#define __USE_GNU
#include <pthread.h>
#include <signal.h>

#include <sys/mman.h>

#include "squirrel.h"
#include "debug.h"
#include "plugbase.h"
#include "spooler.h"
#include "unified2.h"
#include "util.h"

by_mul_tread_para bmt_para;
pthread_t tid_i[BY_MUL_TR_DEFAULT];
pthread_t tid_w[BY_MUL_TR_DEFAULT];
pthread_t tid_o[1];
EventRingTopOcts event_rto;

/*
 ** PRIVATE FUNCTIONS
 */
Spooler *spoolerOpen(spooler_r_para *, const char *, const char *, uint32_t);
int spoolerClose(Spooler *);
int spoolerReadRecordHeader(Spooler *);
int spoolerReadRecord(Spooler *);
void spoolerProcessRecord(Spooler *, int);
void spoolerFreeRecord(Record *record);

int spoolerWriteWaldo(Waldo *, uint8_t);
int spoolerOpenWaldo(Waldo *, uint8_t);
int spoolerCloseWaldo(Waldo *);

int spoolerPacketCacheAdd(Spooler *, Packet *);
int spoolerPacketCacheClear(Spooler *);

int spoolerEventCachePush(Spooler *, uint32_t, void *, uint32_t, uint32_t);
EventRecordNode * spoolerEventCacheGetByEventID(Spooler *, uint32_t, uint32_t);
EventRecordNode * spoolerEventCacheGetHead(Spooler *);
uint8_t spoolerEventCacheHeadUsed(Spooler *);
int spoolerEventCacheClean(Spooler *);

/* Find the next spool file timestamp extension with a value equal to or 
 * greater than timet.  If extension != NULL, the extension will be 
 * returned.
 *
 * @retval 0    file found
 * @retval -1   error
 * @retval 1    no file found
 *
 * Bugs:  This function presumes a 1 character delimeter between the base 
 * filename and the extension
 */
static int FindNextExtension(const char *dirpath, const char *filebase,
        uint32_t timestamp, uint32_t *extension)
{
    DIR *dir = NULL;
    struct dirent *dir_entry;
    size_t filebase_len;
    uint32_t timestamp_min = 0;
    char *endptr;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Looking in %s %s\n", dirpath, filebase););

    /* peform sanity checks */
    if (dirpath == NULL || filebase == NULL)
        return SPOOLER_EXTENSION_EPARAM;

    /* calculate filebase length */
    filebase_len = strlen(filebase);

    /* open the directory */
    if (!(dir = opendir(dirpath))) {
        LogMessage("ERROR: Unable to open directory '%s' (%s)\n", dirpath,
                strerror(errno));
        return SPOOLER_EXTENSION_EOPEN;
    }

    /* step through each entry in the directory */
    while ((dir_entry = readdir(dir))) {
        unsigned long file_timestamp;

        if (strncmp(filebase, dir_entry->d_name, filebase_len) != 0)
            continue;

        /* this is a file we may want */
        file_timestamp = strtol(dir_entry->d_name + filebase_len + 1, &endptr,
                10);
        if ((errno == ERANGE) || (*endptr != '\0')) {
            LogMessage("WARNING: Can't extract timestamp extension from '%s'"
                    "using base '%s'\n", dir_entry->d_name, filebase);

            continue;
        }

        /* exact match */
        if (timestamp != 0 && file_timestamp == timestamp) {
            timestamp_min = file_timestamp;
            break;
        }
        /* possible overshoot */
        else if (file_timestamp > timestamp) {
            /*  realign the minimum timestamp threshold */
            if (timestamp_min == 0 || (file_timestamp < timestamp_min))
                timestamp_min = file_timestamp;
        }
    }

    closedir(dir);

    /* no newer extensions were found */
    if (timestamp_min == 0)
        return SPOOLER_EXTENSION_NONE;

    /* update the extension variable if it exists */
    if (extension != NULL)
        *extension = timestamp_min;

    return SPOOLER_EXTENSION_FOUND;
}

static int FindNextExtAndtrace(uint32_t timestamp, spooler_r_para *sr_para)
{
    size_t filebase_len;
    uint16_t nprod = sr_para->swatch.ns_prod;
    char *endptr;
    char *dirpath = sr_para->waldo->data.spool_dir;
    char *filebase = sr_para->waldo->data.spool_filebase;
    unsigned long file_timestamp;
    struct dirent **namelist;
    int i,n;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Looking in %s %s\n", dirpath, filebase););

    /* peform sanity checks */
    if (dirpath == NULL || filebase == NULL)
        return SPOOLER_EXTENSION_EPARAM;

    /* calculate filebase length */
    filebase_len = strlen(filebase);

    /* open the directory */
//    if (!(dir = opendir(dirpath))) {
    n = scandir(dirpath, &namelist, 0, alphasort);
    if (n < 0) {
        LogMessage("ERROR: Unable to load directory '%s' (%s)\n", dirpath,
                strerror(errno));
        return SPOOLER_EXTENSION_EOPEN;
    }

    /* step through each entry in the directory */
    //while ((dir_entry = readdir(dir))) {
    for (i = 0; i < n; i++) {
        DEBUG_U_WRAP(LogMessage("%s\n", namelist[i]->d_name));

        if ( SPOOLER_WATCH_NS_FULL(sr_para->swatch) ) {
            U2_LOGSTATE_SET_TOSEEK(sr_para->swatch);
            break;
        }

        if (strncmp(filebase, namelist[i]->d_name, filebase_len) != 0)
            continue;

        /* this is a file we may want */
        file_timestamp = strtol(namelist[i]->d_name + filebase_len + 1, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0')) {
            LogMessage("WARNING: Can't extract timestamp extension from '%s'"
                    "using base '%s'\n", namelist[i]->d_name, filebase);
            continue;
        }

        if ( file_timestamp>=timestamp ) {
            Unified2_Archive(sr_para->waldo, SPOOLER_WATCH_NS_P(sr_para->swatch));
            SPOOLER_WATCH_NS_P(sr_para->swatch) = file_timestamp;
            SPOOLER_WATCH_NS_PROD(sr_para->swatch);
            LogMessage("%s: file timestamp in queue: %lu\n", __func__, file_timestamp);
        }

        free(namelist[i]);
    }

    if ( !(SPOOLER_WATCH_NS_FULL(sr_para->swatch)) ) {
        U2_LOGSTATE_UNSET_TOSEEK(sr_para->swatch);
    }

    //closedir(dir);
    free(namelist);

    if ( nprod == sr_para->swatch.ns_prod )
        return SPOOLER_EXTENSION_NONE;

    return SPOOLER_EXTENSION_FOUND;
}

#ifndef SPOOLER_FILE_STREAM
int spoolerMmap(Spooler *spooler)
{
    char *p;
    struct stat sb;

    if (fstat (spooler->fd, &sb) == -1) {
        perror ("fstat");
        return 1;
    }

    if (!S_ISREG (sb.st_mode)) {
        fprintf (stderr, "%s is not a file\n", spooler->filepath);
        return 1;
    }

    p = mmap (0, sb.st_size, PROT_READ, MAP_SHARED, spooler->fd, 0);
    if (p == MAP_FAILED) {
        perror ("mmap");
        return 1;
    }

    if (close (spooler->fd) == -1) {
        perror ("close");
        return 1;
    }

    /* unmap
     if (munmap (p, sb.st_size) == −1) {
     perror ("munmap");
     return 1;
     }
     */
    return 0;
}
#endif

Spooler *spoolerOpen(spooler_r_para *sr_para,
        const char *dirpath,
        const char *filename,
        uint32_t extension)
{
    Spooler *spooler = NULL;
    int ret;
    uint8_t tr_idx = 0;

    if ( NULL != sr_para)
        tr_idx = sr_para->rid;

    /* perform sanity checks */
    if (filename == NULL)
        return NULL;

    /* create the spooler structure and allocate all memory */
    spooler = (Spooler *) SnortAlloc(sizeof(Spooler));
    if ( NULL == spooler)
        return NULL;

    memset(spooler, 0, sizeof(Spooler));
    if ( !RegisterSpooler(spooler, tr_idx) )
        return NULL;

    /* allocate some extra structures required (ie. Packet) */

//    spooler->fd = -1;
    /* build the full filepath */
    if (extension == 0) {
        ret = SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s",
                filename);
    } else {
        ret = SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s/%s.%u",
                dirpath, filename, extension);
    }

    /* sanity check the filepath */
    if (ret != SNORT_SNPRINTF_SUCCESS) {
        UnRegisterSpooler(spooler, tr_idx);
        spoolerClose(spooler);
        FatalError("spooler: filepath too long!\n");
    }

    spooler->timestamp = extension;

    LogMessage("Opened spool file '%s'\n", spooler->filepath);

    /* open the file non-blocking */
#ifndef SPOOLER_FILE_STREAM
    if ( (spooler->fd=open(spooler->filepath, O_RDONLY | O_NONBLOCK, 0)) == -1 )
#else
    if ( NULL == (spooler->fp = fopen(spooler->filepath, "r")))
#endif
            {
        LogMessage("ERROR: Unable to open log spool file '%s' (%s)\n",
                spooler->filepath, strerror(errno));
        UnRegisterSpooler(spooler, tr_idx);
        spoolerClose(spooler);
        spooler = NULL;
        return NULL;
    }

    //spoolerMmap(spooler);

    /* set state to initially be open */
    spooler->state = SPOOLER_OPENED;

    spooler->ifn = GetInputPlugin("unified2");

    if (spooler->ifn == NULL) {
        UnRegisterSpooler(spooler, tr_idx);
        spoolerClose(spooler);
        spooler = NULL;
        FatalError("ERROR: No suitable input plugin found!\n");
    }

    return spooler;
}

int spoolerClose(Spooler *spooler)
{
    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    LogMessage("Closing spool file '%s'. Read %d records\n", spooler->filepath,
            spooler->record_idx);

#ifndef SPOOLER_FILE_STREAM
    if (spooler->fd != -1)
    close(spooler->fd);*/
#else
    if (NULL != spooler->fp)
        fclose(spooler->fp);
#endif

#ifndef SPOOLER_FIXED_BUF
    /* free record */
    spoolerFreeRecord(&spooler->record);
#endif

    free(spooler);
    spooler = NULL;

    return 0;
}

uint8_t RegisterSpooler(Spooler *spooler, uint8_t tr_idx)
{
    Barnyard2Config *bc = BcGetConfig();

    if (!bc)
        return 0;

    if (tr_idx >= BY_MUL_TR_DEFAULT)
        return 0;

    if (bc->spooler[tr_idx]) {
        /* XXX */
        FatalError("[%s()], can't register spooler. \n", __FUNCTION__);
    } else {
        bc->spooler[tr_idx] = spooler;
    }

    return 1;
}

uint8_t UnRegisterSpooler(Spooler *spooler, uint8_t tr_idx)
{
    Barnyard2Config *bc = BcGetConfig();

    if (!bc)
        return 0;

    if (tr_idx >= BY_MUL_TR_DEFAULT)
        return 0;

    if (bc->spooler[tr_idx] != spooler) {
        /* XXX */
        FatalError("[%s()], can't un-register spooler. \n", __FUNCTION__);
    } else {
        bc->spooler[tr_idx] = NULL;
    }

    return 1;
}

int spoolerReadRecordHeader(Spooler *spooler)
{
    int ret;

    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    if (spooler->state != SPOOLER_OPENED
            && spooler->state != SPOOLER_RECORD_READ) {
        LogMessage("ERROR: Invalid attempt to read record header.\n");
        return -1;
    }

    if (NULL == spooler->ifn->readRecordHeader) {
        LogMessage("WARNING: No function defined to read header.\n");
        return -1;
    }

    ret = spooler->ifn->readRecordHeader(spooler);

    if (0 == ret) {
        spooler->state = SPOOLER_HEADER_READ;
    }

    return ret;
}

int spoolerReadRecord(Spooler *spooler)
{
    int ret;

    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    DEBUG_U_WRAP(LogMessage("%s: in\n", __func__));

    if (spooler->state != SPOOLER_HEADER_READ) {
        LogMessage("ERROR: Invalid attempt to read record.\n");
        return -1;
    }

    if (NULL == spooler->ifn->readRecord) {
        LogMessage("WARNING: No function defined to read header.\n");
        return -1;
    }

    ret = spooler->ifn->readRecord(spooler);

    if (0 == ret) {
        spooler->state = SPOOLER_RECORD_READ;
        spooler->record_idx++;

        spooler->spara->sring->event_cache[spooler->spara->sring->event_prod].record_idx =
                spooler->record_idx;
        spooler->spara->sring->event_cache[spooler->spara->sring->event_prod].timestamp =
                spooler->timestamp;
    }

    return ret;
}

int ProcessBatch(const char *dirpath, const char *filename)
{
    Spooler *spooler = NULL;
    int ret = 0;
    int pb_ret = 0;

    /* Open the spool file */
    if ((spooler = spoolerOpen(NULL, "", filename, 0)) == NULL) {
        FatalError("Unable to create spooler: %s\n", strerror(errno));
    }

    while (exit_signal == 0 && pb_ret == 0) {
        /* for SIGUSR1 / dropstats */
        SignalCheck();

        switch (spooler->state) {
        case SPOOLER_OPENED:
        case SPOOLER_RECORD_READ:
            ret = spoolerReadRecordHeader(spooler);

            if (ret == BARNYARD2_READ_EOF) {
                pb_ret = -1;
            } else if (ret != 0) {
                LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n",
                        spooler->filepath, ret);
                pb_ret = -1;
            }
            break;

        default:
            ret = spoolerReadRecord(spooler);

            if (ret == 0) {
                /* process record, firing output as required */
                spoolerProcessRecord(spooler, 1);
            } else if (ret == BARNYARD2_READ_EOF) {
                pb_ret = -1;
            } else {
                LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n",
                        spooler->filepath, ret);
                pb_ret = -1;
            }

            spoolerFreeRecord(&spooler->record);
            break;
        }
    }

    /* we've finished with the spooler so destroy and cleanup */
    spoolerClose(spooler);
    spooler = NULL;

    return pb_ret;
}

/*
 ** ProcessContinuous(const char *dirpath, const char *filebase, uint32_t record_start, time_t timestamp)
 **
 **
 **
 */
int ProcessContinuous(Waldo *waldo, spooler_r_para *sr_para)
{
    Spooler *spooler = NULL;
    int ret = 0;
    int pc_ret = 0;
    int new_file_available = 0;
    int waiting_logged = 0;
    uint32_t skipped = 0;
    uint32_t extension = 0;
    char *dirpath;
    char *filebase;
    uint32_t record_start;
    uint32_t timestamp;
    u_int32_t waldo_timestamp = 0;

    dirpath = waldo->data.spool_dir;
    filebase = waldo->data.spool_filebase;
    record_start = waldo->data.record_idx;
    timestamp = waldo->data.timestamp;

    waldo_timestamp = timestamp; /* fix possible bug by keeping invocated timestamp at the time of the initial call */

    if (BcProcessNewRecordsOnly()) {
        DEBUG_U_WRAP(LogMessage("Processing new records only.\n"));

        /* Find newest file extension */
        while (FindNextExtension(dirpath, filebase, timestamp, &extension) == 0) {
            if (timestamp > 0 && BcLogVerbose())
                LogMessage("Skipping file: %s/%s.%u\n", dirpath, filebase,
                        timestamp);

            timestamp = extension + 1;
        }

        timestamp = extension;
    }

    /* Start the main process loop */
    while (exit_signal == 0) {
        /* for SIGUSR1 / dropstats */
        SignalCheck();

        /* no spooler exists so let's create one */
        if (spooler == NULL) {
            LogMessage("%s: spooler is null\n", __func__);
            /* find the next file to spool */
            ret = FindNextExtension(dirpath, filebase, timestamp, &extension);

            /* The file found is not the same as specified in the waldo,
             thus we need to reset record_start, since we are obviously not processing the same file*/
            if (waldo_timestamp != extension) {
                record_start = 0; /* There is no danger to resetting record_start to 0
                 if called timestamp is not the same */
            }

            /* no new extensions found */
            if (ret == SPOOLER_EXTENSION_NONE) {
                if (waiting_logged == 0) {
                    if (BcProcessNewRecordsOnly())
                        LogMessage("Skipped %u old records\n", skipped);

                    LogMessage("Waiting for new spool file\n");
                    waiting_logged = 1;
                    barnyard2_conf->process_new_records_only_flag = 0;
                }

                sleep(1);
                continue;
            }
            /* an error occured whilst looking for new extensions */
            else if (ret != SPOOLER_EXTENSION_FOUND) {
                LogMessage("ERROR: Unable to find the next spool file!\n");
                exit_signal = -1;
                pc_ret = -1;
                continue;
            }

            /* found a new extension so create a new spooler */
            if ((spooler = spoolerOpen(NULL, dirpath, filebase, extension)) == NULL) {
                LogMessage("ERROR: Unable to create spooler!\n");
                exit_signal = -1;
                pc_ret = -1;
                continue;
            } else {
                /* Make sure we create a new waldo even if we did not have processed an event */
                if (waldo_timestamp != extension) {
                    spooler->record_idx = 0;
                    barnyard2_conf->waldos[0].data.timestamp = spooler->timestamp;
                    barnyard2_conf->waldos[0].data.record_idx = spooler->record_idx;
                    spoolerWriteWaldo(&(barnyard2_conf->waldos[0]), 0);
                }
                waiting_logged = 0;

                /* set timestamp to ensure we look for a newer file next time */
                timestamp = extension + 1;

                spooler->spara = sr_para;
            }

            continue;
        }

#ifdef SPOOLER_RECORD_RING
        if (SPOOLER_RING_FULL(spooler->spara->sring)) {
            usleep(100000);
            continue;
        }
#endif

        /* act according to current spooler state */
        switch (spooler->state) {
        case SPOOLER_OPENED:
        case SPOOLER_RECORD_READ:
            ret = spoolerReadRecordHeader(spooler);
            break;

        case SPOOLER_HEADER_READ:
            ret = spoolerReadRecord(spooler);
            break;

        default:
            LogMessage("ERROR: Invalid spooler state (%i). Closing '%s'\n",
                    spooler->state, spooler->filepath);

#ifndef WIN32
            /* archive the spool file */
            if (BcArchiveDir() != NULL)
                ArchiveFile(spooler->filepath, BcArchiveDir());
#endif

            /* we've finished with the spooler so destroy and cleanup */
            UnRegisterSpooler(spooler, sr_para->rid);
            spoolerClose(spooler);
            spooler = NULL;

            record_start = 0;
            break;
        }

        /* if no spooler exists, we are waiting for a newer file to arrive */
        if (spooler == NULL)
            continue;

        if (ret == 0) {
            /* check for a successful record read */
            if (spooler->state == SPOOLER_RECORD_READ) {
                if (record_start > 0) {
                    /* skip this record */
                    record_start--;
                    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Skipping due to record start offset (%lu)...\n",
                                    (long unsigned)record_start););

                    /* process record to ensure correlation context, but DO NOT fire output*/
                    spoolerProcessRecord(spooler, 0);
                } else if (BcProcessNewRecordsOnly()) {
                    /* skip this record */
                    skipped++;
                    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Skipping due to new records only flag...\n"););

                    /* process record to ensure correlation context, but DO NOT fire output*/
                    spoolerProcessRecord(spooler, 0);
                } else {
                    DEBUG_U_WRAP(LogMessage("%s: Process record\n", __func__));
                    /* process record, firing output as required */
                    spoolerProcessRecord(spooler, 1);
                }
            }
#ifndef SPOOLER_FIXED_BUF
            spoolerFreeRecord(&spooler->record);
#endif
        } else if (ret == BARNYARD2_FILE_ERROR) {
            LogMessage("ERROR: Reading current file!\n");
            exit_signal = -3;
            pc_ret = -1;
            continue;
        } else {
            if (new_file_available) {
                switch (spooler->state) {
                case SPOOLER_OPENED:
                case SPOOLER_HEADER_READ:
                case SPOOLER_RECORD_READ:
                    if (ret == BARNYARD2_ETRUNC)
                        LogMessage("Truncated record in '%s'\n",
                                spooler->filepath);
                    break;

                default:
                    if (ret == BARNYARD2_READ_PARTIAL)
                        LogMessage("Partial read from '%s'\n",
                                spooler->filepath);
                    break;
                }

                /* archive the file */
                if (BcArchiveDir() != NULL)
                    ArchiveFile(spooler->filepath, BcArchiveDir());

                /* close (ie. destroy and cleanup) the spooler so we can rotate */
                UnRegisterSpooler(spooler, sr_para->rid);
                spoolerClose(spooler);
                spooler = NULL;

                record_start = 0;
                new_file_available = 0;
            } else {
                ret = FindNextExtension(dirpath, filebase, timestamp, NULL);
                if (ret == 0) {
                    new_file_available = 1;
                } else if (ret == -1) {
                    LogMessage("ERROR: Looking for next spool file!\n");
                    exit_signal = -3;
                    pc_ret = -1;
                } else {
                    if (!waiting_logged) {
                        if (BcProcessNewRecordsOnly())
                            LogMessage("Skipped %u old records\n", skipped);

                        LogMessage("Waiting for new data\n");
                        waiting_logged = 1;
                        barnyard2_conf->process_new_records_only_flag = 0;
                    }

                    sleep(1);
                    continue;
                }
            }
        }
    }

    /* close waldo if appropriate */
    if (barnyard2_conf)
        spoolerCloseWaldo(&(barnyard2_conf->waldos[0]));

    return pc_ret;
}

int ProcessContinuousWithWaldo(Barnyard2Config *bc)
{
#ifndef SPOOLER_DUAL_THREAD
    int ret;
#else
    uint8_t i;
    int err;
    static pthread_once_t spool_once = PTHREAD_ONCE_INIT;
    pthread_t  *ptid;
    EventGMCid ret_mcid;
#endif

    /*    if (waldo == NULL)
     return -1;*/

#ifndef SPOOLER_DUAL_THREAD
    ret = ProcessContinuous(waldo, pSring);
    free(pSring);
    return ret;
#else

    cpu_set_t cpuset, cpuset_o;

    if ( !bc->trbit_valid ){
        LogMessage("%s: no valid thread read path configured, exit\n", __func__);
        return 0;
    }

    //Nice Value
    errno = 0;
    err = nice(-6);
    if (-1==err && 0!=errno) {
        LogMessage("Can't set nice value: [%s]\n", strerror(errno));
    }

    CPU_ZERO(&cpuset);
    CPU_ZERO(&cpuset_o);

    memset(&bmt_para, 0, sizeof(bmt_para));

    pthread_once(&spool_once, spool_mult_init);

    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
        if ( !(bc->trbit_valid&(0x01<<i)) )
            continue;

        bmt_para.s_para[i].waldo = &(bc->waldos[i]);
        snprintf(bc->waldos[i].data.spool_filebase,
                sizeof(bc->waldos[i].data.spool_filebase), "%s", bc->spool_filebase);
        snprintf(bc->waldos[i].filepath, sizeof(bc->waldos[i].filepath), "%s_%02d", bc->waldo_filepath, i+1);
        bmt_para.s_para[i].waldo->state |= WALDO_STATE_ENABLED;
        spoolerReadWaldo(bmt_para.s_para[i].waldo);
        bmt_para.s_para[i].rid = i;

        LogMessage("%s: starting read thread %d\n", __func__, i);

        pthread_mutex_init(&bmt_para.s_para[i].lock_ring, NULL);
        pthread_mutex_init(&bmt_para.s_para[i].waldo->lock_waldo, NULL);
        pthread_mutex_init(&bmt_para.s_para[i].swatch.t_lock, NULL);
        pthread_mutex_init(&bmt_para.s_para[i].swatch.c_lock, NULL);

        bmt_para.s_para[i].sring = (spooler_ring*) SnortAlloc(sizeof(spooler_ring));
        if ( NULL == bmt_para.s_para[i].sring) {
            pthread_mutex_destroy(&bmt_para.s_para[i].swatch.t_lock);
            pthread_mutex_destroy(&bmt_para.s_para[i].swatch.c_lock);
            pthread_mutex_destroy(&bmt_para.s_para[i].lock_ring);
            pthread_mutex_destroy(&bmt_para.s_para[i].waldo->lock_waldo);
            goto pexit;
        }
        memset(bmt_para.s_para[i].sring, 0, sizeof(spooler_ring));

        ret_mcid.rid = i;
        CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, &ret_mcid, UNIFIED2_IDS_GET_MCID);
        bmt_para.s_para[i].sring->base_eventid = ret_mcid.ms_cid;
        bmt_para.s_para[i].sring->rollon_cid = ret_mcid.cid;
        if ( 0 == bmt_para.s_para[i].waldo->data.record_idx ) {     //Start from begining of file, try to recognize previous event_id.
            bmt_para.s_para[i].sring->prev_eventid = (ret_mcid.cid>ret_mcid.ms_cid) ? (ret_mcid.cid-ret_mcid.ms_cid):0;
        }
        LogMessage("%s: start with ms_cid=%lu\n", __func__, ret_mcid.ms_cid);

        bmt_para.trbit_valid |= (0x01<<i);
        bmt_para.by_conf = bc;
        err = pthread_create(&tid_i[i], NULL, &spoolerRecordRead_T,
                &(bmt_para.s_para[i]));
        if (0 != err) {
            LogMessage("Can't create thread %d: [%s]\n", i, strerror(err));
            goto pexit;
        }

        bc->waldos[i].data.spool_filebase_len = strlen(bc->waldos[i].data.spool_filebase);
        pthread_cond_init(&bmt_para.s_para[i].watch_cond, NULL);
        Unified2DirAddWatch(bc->waldos[i].data.spool_dir, &(bmt_para.s_para[i].swatch.fd));
        err = pthread_create(&tid_w[i], NULL, &Unified2DirEvent, &(bmt_para.s_para[i]));
        if (0 != err) {
            LogMessage("Can't create watch thread %d: [%s]\n", i, strerror(err));
            goto pexit;
        }

        if ( bc->tr_lcore[i] ) {
            //Set affinity to Logs Read Threads
            LogMessage("%s: set cpuset 0x%lx\n", __func__, bc->tr_lcore[i]);
            cpuset.__bits[0] = bc->tr_lcore[i];
            cpuset_o.__bits[0] |= bc->tr_lcore[i];
            err = pthread_setaffinity_np(tid_i[i], sizeof(cpu_set_t), &cpuset);
            if ( 0 != err )
                handle_error_en(err, "pthread_setaffinity_np");
            err = pthread_setaffinity_np(tid_w[i], sizeof(cpu_set_t), &cpuset);
            if ( 0 != err )
                handle_error_en(err, "pthread_setaffinity_np");
        }
    }

    /* NOTE: This "i" is following previous state */
    //bmt_para.trbit_valid = bc->trbit_valid;
    err = pthread_create(&tid_o[0], NULL, &spoolerRecordOutput_T, &bmt_para);
    if (0 != err) {
        LogMessage("Can't create thread 2: [%s]\n", strerror(err));
        goto pexit;
    }

    if ( cpuset_o.__bits[0] ) {
        //Set affinity to Logs Dispatch Thread
        err = pthread_setaffinity_np(tid_o[0], sizeof(cpu_set_t), &cpuset_o);
        if ( 0 != err )
            handle_error_en(err, "pthread_setaffinity_np");
    }

    //Thread Join
    ptid = tid_o;
    for (i=0; i<BY_MUL_TR_DEFAULT; i++) {
        if ( !(bmt_para.trbit_valid&(0x01<<i)) )
            continue;
        bmt_para.s_para[i].ptid_join = ptid;
        ptid = &(tid_i[i]);
    }

    /* Join i/o threads */
    LogMessage("pthread_join will tid_o: %u!\n", *ptid);
    if ( 0 != pthread_join(*ptid, NULL) )
        LogMessage("%s: pthread_join ptid failed!\n", __func__);

    LogMessage("pthreads finished!\n");

pexit:
    for (i = 0; i < BY_MUL_TR_DEFAULT; i++) {
        if (NULL != bmt_para.s_para[i].sring) {
            ret_mcid.rid = i;
            ret_mcid.ms_cid = bmt_para.s_para[i].sring->base_eventid;
            CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, &ret_mcid, UNIFIED2_IDS_SET_MCID);
            LogMessage("%s: end with ms_cid=%lu\n", __func__, ret_mcid.ms_cid);

            free(bmt_para.s_para[i].sring);
            pthread_mutex_destroy(&bmt_para.s_para[i].lock_ring);
            pthread_mutex_destroy(&bmt_para.s_para[i].waldo->lock_waldo);
            pthread_mutex_destroy(&bmt_para.s_para[i].swatch.t_lock);
            pthread_mutex_destroy(&bmt_para.s_para[i].swatch.c_lock);
            pthread_cond_destroy(&bmt_para.s_para[i].watch_cond);
        }
    }

    return 0;
#endif
}

/*
 ** RECORD PROCESSING EVENTS
 */

void spoolerProcessRecord(Spooler *spooler, int fire_output)
{
    struct pcap_pkthdr pkth;
    uint32_t type;
    EventRecordNode *ernCache;
    Packet *sp_pkt;
    uint8_t *pCurData;
    uint32_t event_id, event_second;

    /* convert type once */
    type = ntohl(((Unified2RecordHeader *) spooler->spara->sring->event_cache[spooler->spara->sring->event_prod].header)->type);

    /* increment the stats */
    pc.total_records++;
    switch (type) {
    case UNIFIED2_PACKET:
        pc.total_packets++;
        break;
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_MPLS:
    case UNIFIED2_IDS_EVENT_IPV6_MPLS:
    case UNIFIED2_IDS_EVENT_VLAN:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        pc.total_events++;
        break;
    default:
        pc.total_unknown++;
    }

    /* convert event id once */
#ifndef SPOOLER_FIXED_BUF
    pCurData = spooler->record.data;
#else
    pCurData = spooler->spara->sring->event_cache[spooler->spara->sring->event_prod].data;
#endif
    event_id = 0x0000ffff & ntohl(((Unified2CacheCommon *) pCurData)->event_id);
    event_second = ntohl(((Unified2CacheCommon *) pCurData)->event_second);

    /*	LogMessage("%s: event_cur %d, event_top %d, event_cnt %d\n", __func__,
     spooler->event_cur, spooler->event_top, spooler->event_cnt);
     */
    /* check if it's packet */
    if (type == UNIFIED2_PACKET) {
#ifndef SPOOLER_RECORD_RING
        /* check if there is a previously cached event that matches this event id */
        ernCache = spoolerEventCacheGetByEventID(spooler, event_id, event_second);
        /* allocate space for the packet and construct the packet header */
        spooler->record.pkt = SnortAlloc(sizeof(Packet));
        spooler->record.pkt->ip6_extensions = SnortAlloc(sizeof(IP6Option) * 1);
#else
        ernCache = spoolerEventCacheGetHead(spooler);
        if (NULL != ernCache) {
            if (ernCache->event_id != event_id
                    || ernCache->event_second != event_second) {
                ernCache = NULL;
            }
        }
        memset(spooler->record.pkt, 0, sizeof(spooler->record.pkt));
#endif

        sp_pkt = spooler->record.pkt;

        pkth.caplen = ntohl(((Unified2Packet *) pCurData)->packet_length);
        pkth.len = pkth.caplen;
        pkth.ts.tv_sec = ntohl(((Unified2Packet *) pCurData)->packet_second);
        pkth.ts.tv_usec = ntohl(
                ((Unified2Packet *) pCurData)->packet_microsecond);

        /* decode the packet from the Unified2Packet information */
        datalink = ntohl(((Unified2Packet *) pCurData)->linktype);
        DecodePacket(datalink, sp_pkt, (DAQ_PktHdr_t *) &pkth,
                ((Unified2Packet *) pCurData)->packet_data);

        /* This is a fixup for portscan... */
        if ((sp_pkt->iph == NULL)
                && ((sp_pkt->inner_iph != NULL)
                        && (sp_pkt->inner_iph->ip_proto == 255))) {
            sp_pkt->iph = sp_pkt->inner_iph;
        }

        /* check if it's been re-assembled */
        if (sp_pkt->packet_flags & PKT_REBUILT_STREAM) {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Packet has been rebuilt from a stream\n"););
        }

        /* if the packet and cached event share the same id */
        if (ernCache != NULL) {
            /* call output plugins with a "SPECIAL" alert format (both Event and Packet information) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing SPECIAL style (Packet+Event)\n"););

#ifndef SPOOLER_RECORD_RING
            if ( fire_output && ((ernCache->used == 0) || BcAlertOnEachPacketInStream()) ) {
#else
            if (fire_output && BcAlertOnEachPacketInStream()) {
#endif
                /*LogMessage("%s: out put to database, event_id %d\n", __func__, event_id);
                 do{
                 CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                 sp_pkt,
                 ernCache->data,
                 ernCache->type);
                 } while(0);
                 spooler->event_end = 1;*/
            }
#ifndef SPOOLER_RECORD_RING
            /* indicate that the cached event has been used */
            ernCache->used = 1;
#else
            SPOOLER_RING_DEC(spooler->spara);
#endif
        } else {
            /* fire the event cache head only if not already used (ie dirty) */
            if (spoolerEventCacheHeadUsed(spooler) == 0) {
                ernCache = spoolerEventCacheGetHead(spooler);

                /* call output plugins with an "ALERT" format (cached Event information only) */
                DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

                if (fire_output)
                    CallOutputPlugins(OUTPUT_TYPE__ALERT,
                    NULL, ernCache->data, ernCache->type);
#ifndef SPOOLER_RECORD_RING
                /* set the event cache used flag */
                ernCache->used = 1;
#else
                SPOOLER_RING_DEC(spooler->spara);
#endif
            }

            /* call output plugins with a "LOG" format (Packet information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing LOG style (Packet)\n"););

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL, sp_pkt,
                NULL, 0);
        }

#ifndef SPOOLER_FIXED_BUF
        /* free the memory allocated in this function */
        free(sp_pkt->ip6_extensions);
        free(sp_pkt);
        spooler->record.pkt = NULL;
#endif

        /* waldo operations occur after the output plugins are called */
        if (fire_output) {
            barnyard2_conf->waldos[0].data.timestamp = spooler->timestamp;
            barnyard2_conf->waldos[0].data.record_idx = spooler->record_idx;
            spoolerWriteWaldo(&(barnyard2_conf->waldos[0]), 0);
        }
    }
    /* check if it's an event of known sorts */
    else if (type == UNIFIED2_IDS_EVENT || type == UNIFIED2_IDS_EVENT_IPV6
            || type == UNIFIED2_IDS_EVENT_MPLS
            || type == UNIFIED2_IDS_EVENT_IPV6_MPLS
            || type == UNIFIED2_IDS_EVENT_VLAN
            || type == UNIFIED2_IDS_EVENT_IPV6_VLAN) {
        /* fire the cached event only if not already used (ie dirty) */
        if (spoolerEventCacheHeadUsed(spooler) == 0) {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT,
                NULL, ernCache->data, ernCache->type);

#ifndef SPOOLER_RECORD_RING
            /* flush the event cache flag */
            ernCache->used = 1;
#else
            SPOOLER_RING_DEC(spooler->spara);
#endif
        }

        /* cache new data */
        spoolerEventCachePush(spooler, type, pCurData, event_id, event_second);
#ifndef SPOOLER_FIXED_BUF
        spooler->record.data = NULL;
#endif
        /* waldo operations occur after the output plugins are called */
        if (fire_output) {
            barnyard2_conf->waldos[0].data.timestamp = spooler->timestamp;
            barnyard2_conf->waldos[0].data.record_idx = spooler->record_idx;
            spoolerWriteWaldo(&(barnyard2_conf->waldos[0]), 0);
        }
    } else if (type == UNIFIED2_EXTRA_DATA) {
        /* waldo operations occur after the output plugins are called */
        if (fire_output) {
            barnyard2_conf->waldos[0].data.timestamp = spooler->timestamp;
            barnyard2_conf->waldos[0].data.record_idx = spooler->record_idx;
            spoolerWriteWaldo(&(barnyard2_conf->waldos[0]), 0);
        }
        LogMessage("%s: Extra_data, skipped\n", __func__);
    } else {
        LogMessage("%s: Unknown type, skipped\n", __func__);
        /* fire the cached event only if not already used (ie dirty) */
        if (spoolerEventCacheHeadUsed(spooler) == 0) {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT,
                NULL, ernCache->data, ernCache->type);

#ifndef SPOOLER_RECORD_RING
            /* flush the event cache flag */
            ernCache->used = 1;
#else
            SPOOLER_RING_DEC(spooler->spara);
#endif
            /* waldo operations occur after the output plugins are called */
            if (fire_output) {
                barnyard2_conf->waldos[0].data.timestamp = spooler->timestamp;
                barnyard2_conf->waldos[0].data.record_idx = spooler->record_idx;
                spoolerWriteWaldo(&(barnyard2_conf->waldos[0]), 0);
            }
        }
    }

    /* clean the cache out */
    spoolerEventCacheClean(spooler);
}

void spool_mult_init(void)
{

}

Spooler* spoolerGet(spooler_r_para *sr_para, uint32_t timestamp, uint32_t *extension)
{
    int ret = 0;
    char *dirpath;
    char *filebase;
    Spooler *spooler = NULL;
    static int waiting_logged = 0;
    Waldo* waldo = sr_para->waldo;

    dirpath = waldo->data.spool_dir;
    filebase = waldo->data.spool_filebase;

    if ( timestamp>0 && NULL!=extension ) {
        /* find the next file to spool */
        ret = FindNextExtension(dirpath, filebase, timestamp, extension);

        if (SPOOLER_EXTENSION_NONE == ret) { /* no new extensions found */
            if (0 == waiting_logged) {
                LogMessage("Waiting for new spool file\n");
                waiting_logged = 1;
            }

            sleep(1);
            return NULL;
        } else if (ret != SPOOLER_EXTENSION_FOUND) { /* an error occured whilst looking for new extensions */
            LogMessage("ERROR: Unable to find the next spool file!\n");
            exit_signal = SIGQUIT;
            return NULL;
        }

        timestamp = *extension;
    }

    if ( timestamp > 0 ) {
        /* found a new extension, or appointed one, so create a new spooler */
        if ((spooler = spoolerOpen(sr_para, dirpath, filebase, timestamp)) == NULL) {
            LogMessage("ERROR: Unable to create spooler!\n");
            //exit_signal = SIGQUIT;
        } else {
            waiting_logged = 0;
            spooler->record_idx = 0;
            spooler->spara = sr_para;
            spooler->state = SPOOLER_RECORD_READY;
            sr_para->watch_cts = spooler->timestamp;
        }
    }

    return spooler;
}

Spooler *spoolerFresh(Spooler *spooler, spooler_r_para *sr_para)
{
    uint8_t s_cnt = 0;
    uint8_t sp_isnew = 0;

spf_new:    //If there is newer file
    while ( !(SPOOLER_WATCH_NS_EMPTY(sr_para->swatch)) )
    {
        sp_isnew = 1;
        LogMessage("New u2 file created, continue reading!\n");

        if ( NULL != spooler ) {
            DEBUG_U_WRAP(LogMessage("Close previous spooler first.\n"));
            if (BcArchiveDir() != NULL)
                ArchiveFile(spooler->filepath, BcArchiveDir());
            UnRegisterSpooler(spooler, sr_para->rid);
            spoolerClose(spooler);
            //record_offset = 0;
        }

        spooler = spoolerGet(sr_para, SPOOLER_WATCH_NS_C(sr_para->swatch), NULL);
        SPOOLER_WATCH_NS_CONS(sr_para->swatch);

        if ( NULL == spooler )
            continue;

        //timestamp = sr_para->swatch.newstamp[sr_para->swatch.ns_cons] + 1;
        //U2_LOGSTATE_UNSET_CREATE(sr_para->swatch);
        break;
    }

    //Found new log file
    if ( sp_isnew ) {
    	spoolerWriteWaldo(sr_para->waldo, 1);
    	return spooler;
    }

    //Watch list is empty
    if ( U2_LOGSTATE_ISSET_TOSEEK(sr_para->swatch) ) {
        FindNextExtAndtrace(SPOOLER_WATCH_NS_T(sr_para->swatch)+1, sr_para);
        if ( !(SPOOLER_WATCH_NS_EMPTY(sr_para->swatch)) )
            goto spf_new;
    }

    //if (SPOOLER_EXTENSION_FOUND == FindNextExtension(dirpath, filebase, spooler->timestamp+1, NULL)) {}
    while ( !sr_para->swatch.mask && !exit_signal) {
    	DEBUG_U_WRAP(LogMessage("Waiting u2 file update, sleep!\n"));
        sleep(1);
        if ( ++s_cnt >= 1 ) {
            /*Update Waldo*/
            spoolerWriteWaldo(sr_para->waldo, 1);
            s_cnt = 0;
        }
    }

    if ( U2_LOGSTATE_ISSET_MODIFY(sr_para->swatch) ) {
        DEBUG_U_WRAP(LogMessage("Log u2 file updated, continue reading!\n"));
        U2_LOGSTATE_UNSET_MODIFY(sr_para->swatch);
        return spooler;
    }

    return NULL;
}

/*
 * spoolerRecordRead_T(void * arg)
 */
void* spoolerRecordRead_T(void * arg)
{
    Spooler *spooler = NULL;
    Spooler *spooler_new = NULL;
    int read_rtn = BARNYARD2_SUCCESS;
//    uint32_t extension = 0;
    Waldo *waldo;
    char *dirpath;
    uint32_t timestamp;
    u_int32_t waldo_timestamp;
    sigset_t set;
    spooler_r_para *sr_para = (spooler_r_para*) arg;
    EventRecordNode *ernCache;
    //uint32_t ws_idx = 0;

    sigemptyset(&set);
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    waldo = sr_para->waldo;
    dirpath = waldo->data.spool_dir;
    timestamp = waldo->data.timestamp;
    waldo_timestamp = waldo->data.timestamp; /* fix possible bug by keeping invocated timestamp at the time of the initial call */
    sr_para->watch_cts = waldo->data.timestamp;
    LogMessage("%s: Processing in dir %s, ts: %d, record_idx %d\n", __func__,
            dirpath, waldo_timestamp, waldo->data.record_idx);

    pthread_mutex_lock(&sr_para->swatch.c_lock);

    /* Find newest file extension, and trace if needed, or drop */
    if (SPOOLER_EXTENSION_FOUND ==
            FindNextExtAndtrace(timestamp, sr_para))
    {
        if (BcProcessNewRecordsOnly()) {
/*            if (timestamp > 0 && BcLogVerbose())
                LogMessage("Skipping file: %s/%s.%u\n", dirpath, filebase,
                        timestamp);*/
            DEBUG_U_WRAP(LogMessage("Processing new records only.\n"));
            timestamp = SPOOLER_WATCH_NS_T(sr_para->swatch);
            SPOOLER_WATCH_NS_CLEAR(sr_para->swatch);
        }
        else{
            timestamp = SPOOLER_WATCH_NS_C(sr_para->swatch);
            SPOOLER_WATCH_NS_CONS(sr_para->swatch);
        }

        spooler = spoolerGet(sr_para, timestamp, NULL);
    }

    if ( NULL != spooler && waldo_timestamp==timestamp ) {
    	spooler->skip_offset = waldo->data.record_idx;
    	spooler->state = SPOOLER_RECORD_SKIP;
    	sr_para->sring->r_switch = RING_OFF;
    	if ( 0 == spooler->skip_offset )
    		sr_para->sring->r_switch = RING_PRE_ON;
    }
    else{
    	//spooler->skip_offset = 0;
    	sr_para->sring->r_switch = RING_PRE_ON;
    }

    sr_para->watch_start = 1;
    pthread_cond_signal(&sr_para->watch_cond);
    pthread_mutex_unlock(&sr_para->swatch.c_lock);

    while (0 == exit_signal)
    {
        //Detect Folder state if needed
        if ( NULL == spooler || BARNYARD2_SUCCESS!=read_rtn ) {
            DEBUG_U_WRAP(LogMessage( "%s: spooler is null\n", __func__ ));

            /*Wait new state of log folder*/
            spooler_new = spoolerFresh(spooler, sr_para);
            if(NULL == spooler_new){
                LogMessage("%s: spooler fresh failed! Continue\n", __func__);
                sleep(1);
                continue;
            }
            else if(timestamp != spooler_new->timestamp){
                //ws_idx = 0;//spooler->record_idx;
                //spooler->skip_offset = 0;
                timestamp = spooler_new->timestamp;
            }
            spooler = spooler_new;
        }

        //If Ring Full
        //if (SPOOLER_RING_FULL(sr_para->sring)) {
        if ( ! SPOOLER_RING_PROCEED(sr_para->sring) ) {
            //LogMessage("%s:%d Spooler Ring is full.\n", __func__, sr_para->wid);
            if ( sr_para->sring->i_sleep_cnt++ > 50000 ) {   //sleep 50000 times
                spoolerWriteWaldo(sr_para->waldo, 1);
                sr_para->sring->i_sleep_cnt = 0;
                //ws_idx = spooler->record_idx;
            }
            usleep(1);
            continue;
        }
        sr_para->sring->i_sleep_cnt = 0;

        //Read
        read_rtn = spooler->ifn->readRecordHeader(spooler);
        if (BARNYARD2_SUCCESS == read_rtn) {
            read_rtn = spooler->ifn->readRecord(spooler);
        }

        //Read Result Check
        switch(read_rtn) {
        case BARNYARD2_SUCCESS: /* check for a successful record read */
            spooler->record_idx++;
            ernCache = &(sr_para->sring->event_cache[sr_para->sring->event_prod]);
/*
            sr_para->sring->event_cache[sr_para->sring->event_cur].record_idx =
                    spooler->record_idx;
            sr_para->sring->event_cache[sr_para->sring->event_cur].timestamp =
                    spooler->timestamp;
                    */

            ernCache->record_idx = spooler->record_idx;
            ernCache->timestamp = spooler->timestamp;

            if (spooler->skip_offset > 0) { /* skip this record */
            	DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER, "Skipping due to record start offset (%lu)...\n",
            			(long unsigned)spooler->skip_offset));
            	spooler->skip_offset--;
            	if ( 0 == spooler->skip_offset ) {
            		sr_para->sring->r_switch = RING_PRE_ON;
            		spooler->state = SPOOLER_RECORD_SKIP_DONE;
            	}
            }
            else if ( UNIFIED2_INVALID_REC != ernCache->type ){
                DEBUG_U_WRAP(LogMessage("%s: Process record, idx: %d\n", __func__, spooler->record_idx));
                SPOOLER_RING_INC(sr_para);
            }
            break;
        case BARNYARD2_RING_FULL:
        	read_rtn = BARNYARD2_SUCCESS;	//Treat it as success, wiat for next time.
        	break;
        case BARNYARD2_FILE_ERROR:
            LogMessage("ERROR: Reading current file!\n");
            exit_signal = SIGQUIT;
            break;
        default:     //Nothing Read
            //continue to fresh
            break;
        }
    }

    if ( NULL != sr_para->ptid_join ) {
        LogMessage("%s:%d pthread_join tid_o: %u!\n", __func__, sr_para->rid, *(sr_para->ptid_join));
        if ( 0 != pthread_join(*(sr_para->ptid_join), NULL) )
            LogMessage("%s:%d pthread_join tid_o: %u failed!\n",
                    __func__, sr_para->rid, *(sr_para->ptid_join));
    }

    /* close (ie. destroy and cleanup) the spooler so we can rotate */
    if ( NULL != spooler ) {
        /* Make sure we create a new waldo even if we did not have processed an event, which update waldo indeed. */
        if ( 0 == spooler->record_idx ) {
            LogMessage("%s: spoolerWriteWaldo with empty u2_log.\n", __func__);
            SPOOLER_WALDO_SET_REC(waldo, spooler->timestamp, spooler->record_idx)
        }

        UnRegisterSpooler(spooler, sr_para->rid);
        spoolerClose(spooler);
        spooler = NULL;
    }

    spoolerWriteWaldo(sr_para->waldo, 0);   //Thread Output already exit
    spoolerCloseWaldo(sr_para->waldo);

    LogMessage("%s:%d -----> exiting\n", __func__, sr_para->rid);

    return NULL; //pc_ret;
}

Packet * spoolerRetrievePktData(Packet *sp_pkt, uint8_t *pPktData)
{
    struct pcap_pkthdr pkth;

    memset(sp_pkt, 0, sizeof(Packet));

    pkth.caplen = ntohl(((Unified2Packet *) pPktData)->packet_length);
    pkth.len = pkth.caplen;
    pkth.ts.tv_sec = ntohl(((Unified2Packet *) pPktData)->packet_second);
    pkth.ts.tv_usec = ntohl(((Unified2Packet *) pPktData)->packet_microsecond);

    /* decode the packet from the Unified2Packet information */
    datalink = ntohl(((Unified2Packet *) pPktData)->linktype);
    DecodePacket(datalink, sp_pkt, (DAQ_PktHdr_t *) &pkth,
            ((Unified2Packet *) pPktData)->packet_data);

    /* This is a fixup for portscan... */
    if ((sp_pkt->iph == NULL)
            && ((sp_pkt->inner_iph != NULL)
                    && (sp_pkt->inner_iph->ip_proto == 255))) {
        sp_pkt->iph = sp_pkt->inner_iph;
    }

    /* check if it's been re-assembled */
    if (sp_pkt->packet_flags & PKT_REBUILT_STREAM) {
        DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Packet has been rebuilt from a stream\n"););
    }

    return sp_pkt;
}

/*
 * */
void spoolerRingTopSave(by_mul_tread_para *pbmt_para, RingTopOct *ele_rt)
{
    uint8_t i;

    for ( i=0; i<BY_MUL_TR_DEFAULT; i++ ) {
        if ( pbmt_para->trbit_valid & (0x01<<i) ) {
            DEBUG_U_WRAP_DEEP(LogMessage("%s: save ring[%d] top %d, ele_rt %d\n", __func__,
                    i, pbmt_para->s_para[i].sring->event_top,
                    ele_rt->r_id));
            ele_rt->r_top[i] = pbmt_para->s_para[i].sring->event_top;
        }
    }
    ele_rt->r_flag = 1;
}

/*
 * */
void spoolerRingTopSync(by_mul_tread_para *pbmt_para, EventRingTopOcts *ele_rto)
{
    uint8_t i;
    uint8_t sync = 0, mque_fi_prev = 0;

    while ( ele_rto->mque_fo != ele_rto->mque_fi ) {
        if ( 1 == ele_rto->rings2mque[ele_rto->mque_fo].r_flag ) {
            //Keep producer and exit
            break;
        }

        //Proceed To Next
        mque_fi_prev = ele_rto->mque_fo;
        ele_rto->mque_fo = SPOOLER_ELEQUE_RTO_PLUS_ONE(ele_rto->mque_fo);
        sync = 1;
    }

    if ( sync ) {
        for ( i=0; i<BY_MUL_TR_DEFAULT; i++ ) {
            if ( pbmt_para->trbit_valid & (0x01<<i) ) {
                pbmt_para->s_para[i].sring->event_coms = ele_rto->rings2mque[mque_fi_prev].r_top[i];
                DEBUG_U_WRAP_DEEP(LogMessage("%s: proceed ring[%d] coms %d, ele_rt %d\n", __func__,
                        i, pbmt_para->s_para[i].sring->event_coms,
                        ele_rto->rings2mque[mque_fi_prev].r_id));
            }
        }
    }
}

/*
 * */
void spoolerRingTopReset(EventRingTopOcts *ele_rto)
{
    memset(ele_rto, 0, sizeof(EventRingTopOcts));
}

/*
 ** RECORD PROCESSING EVENTS, as thread
 */
void* spoolerRecordOutput_T(void * arg) //, int fire_output)
{
    uint8_t pbmt_idx = 0, mque_fi_next, i;
    uint16_t pktpos;
    uint32_t type;
    uint32_t cur_event_cnt = 0;
    uint32_t record_idx; // current record number
    EventEP enCaChe;
    OutputType opt;
#ifdef BY_FAKE_DATA_RE_CNT
    uint32_t repeat_cnt[BY_MUL_TR_DEFAULT];
#endif
    time_t timestamp;
    us_cid_t cur_eventid[BY_MUL_TR_DEFAULT];

    sigset_t s_set;
    spooler_r_para *sr_para;
    by_mul_tread_para *pbmt_para = (by_mul_tread_para *) arg;
    struct timespec t_elapse;
    EventGMCid ret_mcid;

    sigemptyset(&s_set);
    sigfillset(&s_set);
    pthread_sigmask(SIG_SETMASK, &s_set, NULL);

    t_elapse.tv_sec = 0;
    t_elapse.tv_nsec = 10;
    nanosleep(&t_elapse, NULL);   //switch to read threads

    memset(cur_eventid, 0, sizeof(cur_eventid));
    spoolerRingTopReset(&event_rto);

#ifdef BY_FAKE_DATA_RE_CNT
    memset(repeat_cnt, 0, sizeof(repeat_cnt));
#endif

    while (0 == exit_signal)
    {
        while ( !(pbmt_para->trbit_valid&(0x01<<pbmt_idx)) ) {
            pbmt_idx = BY_MUK_TR_PLUSONE(pbmt_idx);
        }
        sr_para = &(pbmt_para->s_para[pbmt_idx]);
        pbmt_idx++;

        if (SPOOLER_RING_EMPTY(sr_para->sring)) {
            //LogMessage("%s: Spooler Ring is empty.\n", __func__);
            if (sr_para->sring->r_flag) {
                if (sr_para->sring->o_sleep_cnt++ > 1000) {
                    sr_para->sring->r_flag = 0;
                    sr_para->sring->o_sleep_cnt = 0;
                    CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, NULL, UNIFIED2_IDS_FLUSH_OUT);
                    //sr_para->sring->event_coms = sr_para->sring->event_top;
                    for ( i=0; i<BY_MUL_TR_DEFAULT; i++ ) {
                        if ( pbmt_para->trbit_valid & (0x01<<i) ) {
                            pbmt_para->s_para[i].sring->event_coms = pbmt_para->s_para[i].sring->event_top;
                        }
                    }
                    spoolerRingTopReset(&event_rto);

                    cur_event_cnt = 0;

                    ret_mcid.rid = sr_para->rid;
                    ret_mcid.ms_cid = sr_para->sring->base_eventid;
                    CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, &ret_mcid, UNIFIED2_IDS_UPD_MCID);
                }
            }
            nanosleep(&t_elapse, NULL);		//Sleep 1ns
            continue;
        }

        if ( cur_event_cnt >= 800 ) {
            event_rto.rings2mque[event_rto.mque_fi].r_id = event_rto.mque_fi;
            spoolerRingTopSave(pbmt_para, &(event_rto.rings2mque[event_rto.mque_fi]));
            CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, &(event_rto.rings2mque[event_rto.mque_fi]), UNIFIED2_IDS_FLUSH);
            //If mque is all used
            mque_fi_next = SPOOLER_ELEQUE_RTO_PLUS_ONE(event_rto.mque_fi);
            do {
                if ( mque_fi_next == event_rto.mque_fo ) {
                    spoolerRingTopSync(pbmt_para, &event_rto);
                    nanosleep(&t_elapse, NULL);
                }
                else {
                    event_rto.mque_fi = mque_fi_next;
                    spoolerRingTopSync(pbmt_para, &event_rto);
                    break;
                }
            } while ( 1 );

            //SPOOLER_RING_COMS_N_DEC(sr_para, cur_event_cnt);
            //sr_para->sring->event_coms = sr_para->sring->event_top;
            cur_event_cnt = 0;
        }
        else {
            spoolerRingTopSync(pbmt_para, &event_rto);
        }

        sr_para->sring->r_flag = 1;
        sr_para->sring->o_sleep_cnt = 0;

        /* convert type once */
        enCaChe.rid = sr_para->rid;
        //LogMessage("%s: rid %d\n", __func__, enCaChe.rid);
        enCaChe.ee = &(sr_para->sring->event_cache[sr_para->sring->event_top]);
        type = ntohl(((Unified2RecordHeader *) enCaChe.ee->header)->type);

        record_idx = enCaChe.ee->record_idx;
        timestamp = enCaChe.ee->timestamp;

        opt = OUTPUT_TYPE__NONE;

        switch (type) {
        case UNIFIED2_PACKET:
            {
                enCaChe.ep = enCaChe.ee;
                //pPktData = enCaChe.ep->data;
                opt = OUTPUT_TYPE__LOG;
                pc.total_packets++;
            }
            break;
        case UNIFIED2_IDS_EVENT: /* check if it's an event of known sorts */
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            {
                if (sr_para->sring->event_cnt < 2) {
                    nanosleep(&t_elapse, NULL);     //Sleep 1ns
                    continue;                       //Continue with next ring, or not ?
                }

                pc.total_events++;

                //pEventData = enCaChe.ee->data;
                opt = OUTPUT_TYPE__ALERT;

                if (sr_para->sring->event_cnt > 1) {
                    pktpos = SPOOLER_RING_PLUSONE(sr_para->sring->event_top);
                    enCaChe.ep = &(sr_para->sring->event_cache[pktpos]);
                    if (UNIFIED2_PACKET == ntohl(((Unified2RecordHeader*) enCaChe.ep->header)->type)) {
                        //pPktData = enCaChe.ep->data;
                        record_idx = enCaChe.ep->record_idx;
                        timestamp = enCaChe.ep->timestamp;
                        opt = OUTPUT_TYPE__SPECIAL;
                        pc.total_packets++;
                    }
                } else {
                    LogMessage("%s: event_cnt is %d\n", __func__, sr_para->sring->event_cnt);
                }
            }
            break;
        case UNIFIED2_EXTRA_DATA:
            LogMessage("%s: Extra_data, skipped\n", __func__);
            pc.total_unknown++;
            break;
        default:
            pc.total_unknown++;
            break;
        }
        /* increment the stats */
        pc.total_records++;

        switch (opt) {
        case OUTPUT_TYPE__LOG: /* call output plugins with a "LOG" format (Packet information only) */
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing LOG style (Packet)\n"););
            DEBUG_U_WRAP_DEEP(LogMessage("%s: Firing LOG style (Packet only), dsize %d\n",
                    __func__, enCaChe.ep->s_pkt[0].dsize));
            //enCaChe.ee = &(sr_para->sring->event_cache[sr_para->sring->event_top]);
            //spoolerRetrievePktData(enCaChe.ee->s_pkt, pPktData);
            if (enCaChe.ep->event_id <= cur_eventid[enCaChe.rid]) {
                DEBUG_U_WRAP_DEEP(LogMessage("%s: this is additional packet for previous event\n", __func__));
                CallOutputPlugins(OUTPUT_TYPE__LOG, enCaChe.ep->s_pkt,
                        &enCaChe, enCaChe.ep->type);
            }
            else {
                LogMessage("%s: this is wild packet(rid: %d, pkt: %lu, cur: %lu), skip it!\n", __func__,
                        enCaChe.rid, enCaChe.ep->event_id, cur_eventid[enCaChe.rid]);
/*                CallOutputPlugins(OUTPUT_TYPE__LOG, enCaChe.ep->s_pkt,
                        NULL, 0);*/
            }
            SPOOLER_RING_DEC(sr_para);
            cur_event_cnt++;
            break;
        }
        case OUTPUT_TYPE__ALERT: /* call output plugins with an "ALERT" format (cached Event information only) */
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););
            LogMessage("%s: Firing ALERT style (Event only)\n", __func__);
            //enCaChe.ee = &(sr_para->sring->event_cache[sr_para->sring->event_top]);
            CallOutputPlugins(OUTPUT_TYPE__ALERT, NULL,
                    &enCaChe, enCaChe.ee->type);
            SPOOLER_RING_DEC(sr_para);
            cur_event_cnt++;
            cur_eventid[enCaChe.rid] = enCaChe.ee->event_id;
            break;
        }
        case OUTPUT_TYPE__SPECIAL: {
            DEBUG_WRAP(LogMessage("%s: Firing SPECIAL style, top %d\n", __func__, sr_para->sring->event_top));
/*            event_id = 0x0000ffff & ntohl(((Unified2CacheCommon *) pEventData)->event_id);
            event_second = ntohl(((Unified2CacheCommon *) pEventData)->event_second);
            pevent_id = 0x0000ffff & ntohl(((Unified2CacheCommon *) pPktData)->event_id);
            pevent_second = ntohl(((Unified2CacheCommon *) pPktData)->event_second);
            if (event_id != pevent_id || event_second != pevent_second) {
                SPOOLER_RING_EVENT_DEC(sr_para);
                break;
            }*/

            /*			LogMessage("%s: event_cur %d, event_top %d, event_cnt %d\n", __func__,
             spooler->event_cur, spooler->event_top, spooler->event_cnt);
             */
            //enCaChe.ee = &(sr_para->sring->event_cache[sr_para->sring->event_top]);
            //spoolerRetrievePktData(s_pkt, pPktData);

            /* call output plugins with a "SPECIAL" alert format (both Event and Packet information) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing SPECIAL style (Packet+Event)\n"););

#ifdef BY_FAKE_DATA_RE_CNT
            if ( 0 == repeat_cnt[sr_para->rid] ){
                enCaChe.ee->event_id = (((enCaChe.ee->event_id>0) ? (enCaChe.ee->event_id-1):0)<<BY_FAKE_DATA_RE_BITS);
            }
            else{
                enCaChe.ee->event_id++;
            }
#endif

            if (1){//BcAlertOnEachPacketInStream()) {
                //LogMessage("%s: out put to database, event_id %d\n", __func__, event_id);
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL, enCaChe.ep->s_pkt,
                        &enCaChe, enCaChe.ee->type);
            }
#ifdef BY_FAKE_DATA_RE_CNT
            if ( repeat_cnt[sr_para->rid]++ >= BY_FAKE_DATA_RE_CNT ) {
                SPOOLER_RING_EVENT_DEC(sr_para);
                repeat_cnt[sr_para->rid] = 0;
            }
#else
            SPOOLER_RING_EVENT_DEC(sr_para);
            cur_event_cnt += 2;
#endif

            cur_eventid[enCaChe.rid] = enCaChe.ee->event_id;
            break;
        }
        default:
            LogMessage("%s: Unknown type, skipped\n", __func__);
            SPOOLER_RING_DEC(sr_para)
            cur_event_cnt++;
            break;
        }

        if (0 != exit_signal)
            LogMessage("%s: get lock in exiting， rid %d\n", __func__, sr_para->rid);
        /* waldo operations occur after the output plugins are called */
        SPOOLER_WALDO_SET_REC(sr_para->waldo, timestamp, record_idx);
    }

    /*Flush out all record in database cache*/
    CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, NULL, UNIFIED2_IDS_FLUSH_OUT);
    CallOutputPlugins(OUTPUT_TYPE__FLUSH, NULL, NULL, UNIFIED2_IDS_SPO_EXIT);

    LogMessage("%s:  -----> exiting\n", __func__);

    return NULL;
}

/*
 * Get RING current position
 * */
int spoolerEventRingGetcp(void)
{
    return 0;
}

int spoolerEventCachePush(Spooler *spooler, uint32_t type, void *data,
        u_int32_t event_id, u_int32_t event_second)
{
    EventRecordNode *ernNode;
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"[%s], Caching event id[%u] second[%u] \n",
                    __FUNCTION__,
                    event_id,
                    event_second););
#ifndef SPOOLER_RECORD_RING
    /* allocate memory */
    ernNode = (EventRecordNode *)SnortAlloc(sizeof(EventRecordNode));
#else
    if (SPOOLER_RING_FULL(spooler->spara->sring)) {
        LogMessage("ERROR: Event RING buffer is full!\n");
        return -1;
    }
    ernNode = &(spooler->spara->sring->event_cache[spooler->spara->sring->event_prod]);
#endif

    /* create the new node */
    ernNode->type = type;
#ifndef SPOOLER_RECORD_RING
    ernNode->used = 0;
    ernNode->data = data;
#endif

    ernNode->event_id = event_id;
    ernNode->event_second = event_second;

#ifndef SPOOLER_RECORD_RING
    /* add new events to the front of the cache */
    ernNode->next = spooler->event_cache;

    spooler->event_cache = ernNode;
    spooler->events_cached++;
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Cached event: %d\n", spooler->events_cached););
#else
    SPOOLER_RING_INC(spooler->spara);
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Cached event: %d\n", spooler->event_cnt););
#endif

    return 0;
}

EventRecordNode *spoolerEventCacheGetByEventID(Spooler *spooler,
        uint32_t event_id, uint32_t event_second)
{
    EventRecordNode *ernCurrent;

#ifndef SPOOLER_RECORD_RING
    ernCurrent = spooler->event_cache
    while (ernCurrent != NULL) {
#else
    uint16_t ernCur;
    if (SPOOLER_RING_EMPTY(spooler->spara->sring))
        return NULL;

    ernCur = spooler->spara->sring->event_top;
    while (ernCur != spooler->spara->sring->event_prod) {
        ernCurrent = &(spooler->spara->sring->event_cache[ernCur]);
#endif
        if ((ernCurrent->event_id == event_id)
                && (ernCurrent->event_second == event_second)) {
#ifndef SPOOLER_RECORD_RING
            ernCurrent->time_used++;
#endif
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"[%s], Using cached event[%d] event second [%d] \n",
                            __FUNCTION__,event_id,event_second););
            return ernCurrent;
        }
#ifndef SPOOLER_RECORD_RING
        ernCurrent = ernCurrent->next;
#else
        ernCur = SPOOLER_RING_PLUSONE(ernCur);
#endif
    }

    return NULL;
}

EventRecordNode *spoolerEventCacheGetHead(Spooler *spooler)
{
    if (spooler == NULL)
        return NULL;
#ifndef SPOOLER_RECORD_RING
    return spooler->event_cache;
#else
    if (SPOOLER_RING_EMPTY(spooler->spara->sring))
        return NULL;
    return &(spooler->spara->sring->event_cache[spooler->spara->sring->event_top]);
#endif
}

uint8_t spoolerEventCacheHeadUsed(Spooler *spooler)
{
    if (spooler == NULL || spooler->spara->sring->event_cache == NULL)
        return 255;
#ifndef SPOOLER_RECORD_RING
    return spooler->event_cache->used;
#else
    if (SPOOLER_RING_EMPTY(spooler->spara->sring))
        return 255;
    return 0;
#endif
}
#ifndef SPOOLER_RECORD_RING
int spoolerEventCacheClean(Spooler *spooler)
{
    EventRecordNode *ernCurrent = NULL;
    EventRecordNode *ernPrev = NULL;
    EventRecordNode *ernNext = NULL;
    EventRecordNode *ernCandidate = NULL;
    EventRecordNode *ernCandidateNext = NULL;
    EventRecordNode *ernCandidatePrev = NULL;

    if (spooler == NULL || spooler->event_cache == NULL )
    return 1;

    ernPrev = spooler->event_cache;
    ernCurrent = spooler->event_cache;

    if(spooler->events_cached > barnyard2_conf->event_cache_size)
    {
        while (ernCurrent != NULL)
        {
            ernNext = ernCurrent->next;
            if(ernCurrent->used == 1 && ernCurrent->time_used >=1)
            {
                ernCandidateNext = ernNext;
                ernCandidatePrev = ernPrev;
                ernCandidate=ernCurrent;
            }

            if(ernCurrent != NULL)
            {
                ernPrev = ernCurrent;
            }

            ernCurrent = ernNext;
        }

        if ( ernCandidate != NULL)
        {
            /* Delete from list */
            if (ernCandidate == spooler->event_cache)
            {
                spooler->event_cache = NULL;
            }
            else
            {
                ernCandidatePrev->next = ernCandidateNext;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"[%s],Event currently cached [%d] Purging cached event[%d] event second [%d]\n",
                            __FUNCTION__,
                            spooler->events_cached,
                            ernCandidate->event_id,
                            ernCandidate->event_second););

            spooler->events_cached--;

            if(ernCandidate->data != NULL)
            {
                free(ernCandidate->data);
            }

            if(ernCandidate != NULL)
            {
                free(ernCandidate);
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"[%s],Can't find a purge candidate in event cache, oddness cached event [%d]!! \n",
                            __FUNCTION__,
                            spooler->events_cached););
        }

    }
    return 0;
}
#else
int spoolerEventCacheClean(Spooler *spooler)
{
    return 0;
}
#endif

void spoolerEventCacheFlush(Spooler *spooler)
{
#ifndef SPOOLER_RING_SIZE
    EventRecordNode *next_ptr = NULL;
    EventRecordNode *evt_ptr = NULL;
#endif

    if (spooler == NULL || spooler->spara->sring->event_cache == NULL)
        return;

#ifndef SPOOLER_RING_SIZE
    evt_ptr = spooler->event_cache;
    while(evt_ptr != NULL) {
        next_ptr = evt_ptr->next;

        if(evt_ptr->data) {
            free(evt_ptr->data);
            evt_ptr->data = NULL;
        }
        free(evt_ptr);

        evt_ptr = next_ptr;
    }

    spooler->event_cache = NULL;
    spooler->events_cached = 0;
#else
    if (SPOOLER_RING_EMPTY(spooler->spara->sring))
        return;
    SPOOLER_RING_FLUSHOUT(spooler->spara);
#endif

    return;
}

void spoolerFreeRecord(Record *record)
{
#ifndef SPOOLER_FIXED_BUF
    if (record->data)
    {
        free(record->data);
    }

    record->data = NULL;
#endif
}

/*
 ** WALDO FILE OPERATIONS
 */

/*
 ** spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
 **
 ** Description:
 **   Open the waldo file, non-blocking, defined in the Waldo structure
 */
int spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
{
    struct stat waldo_info;
    int waldo_file_flags = 0;
    mode_t waldo_file_mode = 0;
    int ret = 0;

    /* check if waldo file is already open and in the correct mode */
    if ((waldo->state & WALDO_STATE_OPEN) && (waldo->fd != -1)
            && (waldo->mode == mode)) {
        return WALDO_FILE_SUCCESS;
    }

    /* check that a waldo file has been specified */
    if (waldo->filepath == NULL) {
        return WALDO_FILE_EEXIST;
    }

    /* stat the file to see it exists */
    ret = stat(waldo->filepath, &waldo_info);

    if (mode == WALDO_MODE_READ) {
        waldo_file_flags = ( O_RDONLY);
        if (ret != 0)
            return WALDO_FILE_EEXIST;
    }
    else if (mode == WALDO_MODE_WRITE) {
        waldo_file_flags = ( O_CREAT | O_WRONLY);
        waldo_file_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }

    /* open the file non-blocking */
    LogMessage("%s: mode %x, path %s\n", __func__, mode, waldo->filepath);
    if ((waldo->fd = open(waldo->filepath, waldo_file_flags, waldo_file_mode))
            == -1) {
        LogMessage("WARNING: Unable to open waldo file '%s' (%s)\n",
                waldo->filepath, strerror(errno));
        return WALDO_FILE_EOPEN;
    }

    /* set waldo state and mode */
    waldo->state |= WALDO_STATE_OPEN;
    waldo->mode = mode;

    return WALDO_FILE_SUCCESS;
}

/*
 ** spoolerCloseWaldo(Waldo *waldo)
 **
 ** Description:
 **   Open the waldo file, non-blocking, defined in the Waldo structure
 **
 */
int spoolerCloseWaldo(Waldo *waldo)
{
    if (waldo == NULL)
        return WALDO_STRUCT_EMPTY;

    LogMessage("%s: state %x\n", __func__, waldo->state);

    /* check we have a valid file descriptor */
    if (!(waldo->state & WALDO_STATE_OPEN))
        return WALDO_FILE_EOPEN;

    /* close the file */
    if (waldo->fd > 0)
        close(waldo->fd);

    waldo->fd = -1;

    /* reset open state and mode */
    waldo->state &= (~WALDO_STATE_OPEN);
    waldo->mode = WALDO_MODE_NULL;

    return WALDO_FILE_SUCCESS;
}

/*
 ** spoolReadWaldo(Waldo *waldo)
 **
 ** Description:
 **   Read the waldo file defined in the Waldo structure and populate all values
 ** within.
 **
 */
int spoolerReadWaldo(Waldo *waldo)
{
    int ret;
    WaldoData wd;

    /* check if we have a file in the correct mode (READ) */
    if (waldo->mode != WALDO_MODE_READ) {
        /* close waldo if appropriate */
        //if (barnyard2_conf)
        spoolerCloseWaldo(waldo);

        if ((ret = spoolerOpenWaldo(waldo, WALDO_MODE_READ))
                != WALDO_FILE_SUCCESS)
            return ret;
    } else if (!(waldo->state & WALDO_STATE_OPEN)) {
        if ((ret = spoolerOpenWaldo(waldo, WALDO_MODE_READ))
                != WALDO_FILE_SUCCESS)
            return ret;
    } else {
        /* ensure we are at the beggining since we must be open and in read */
        lseek(waldo->fd, 0, SEEK_SET);
    }

    /* read values into temporary WaldoData structure */
    ret = read(waldo->fd, &wd, sizeof(WaldoData));

    /* TODO: additional checks on the waldo file data to test corruption */
    if (ret != sizeof(WaldoData))
        return WALDO_FILE_ETRUNC;

    /* copy waldo file contents to the directory structure */
    memcpy(&waldo->data, &wd, sizeof(WaldoData));

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
                    "Waldo read\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
                    waldo->data.spool_dir, waldo->data.spool_filebase,
                    waldo->data.timestamp, waldo->data.record_idx););

    /* close waldo if appropriate */
    if (barnyard2_conf)
        spoolerCloseWaldo(waldo);

    return WALDO_FILE_SUCCESS;
}

/*
 ** spoolerWriteWaldo(Waldo *waldo)
 **
 ** Description:
 **   Write to the waldo file
 **
 */
int spoolerWriteWaldo(Waldo *waldo, uint8_t islock)
{
    static int print_c = 0;
    int ret;
    WaldoData *pwd;
    static WaldoData wd = {"\n", "\n", 0, 0};

    if ( '\n' == wd.spool_filebase[0] ) {
        memcpy(wd.spool_filebase, waldo->data.spool_filebase, sizeof(wd.spool_filebase));
    }

    /* check if we are using waldo files */
    if (!(waldo->state & WALDO_STATE_ENABLED))
        return WALDO_STRUCT_EMPTY;

    /* check that a waldo file exists before continued */
    if (waldo == NULL)
        return WALDO_STRUCT_EMPTY;

    /* update fields */
    if (islock) {
    	if ( !waldo->updated )
    		return WALDO_FILE_SKIP;
        memcpy(wd.spool_dir, waldo->data.spool_dir, sizeof(wd.spool_dir));
        DEBUG_WRAP(LogMessage("%s: lock_get and write in %s\n", __func__, wd.spool_dir));
        SPOOLER_WALDO_GET_REC(waldo, wd.timestamp, wd.record_idx)
        pwd = &wd;
    }
    else{
        pwd = &(waldo->data);
    }

    /* check if we have a file in the correct mode (READ) */
    if (waldo->mode != WALDO_MODE_WRITE) {
        /* close waldo if appropriate */
        //if (barnyard2_conf)
        spoolerCloseWaldo(waldo);
        spoolerOpenWaldo(waldo, WALDO_MODE_WRITE);
    } else if (!(waldo->state & WALDO_STATE_OPEN)) {
        spoolerOpenWaldo(waldo, WALDO_MODE_WRITE);
    } else {
        /* ensure we are at the start since we must be open and in write */
        lseek(waldo->fd, 0, SEEK_SET);
    }

    /* write values */
    //ret = write(waldo->fd, &waldo->data, sizeof(WaldoData));
    ret = write(waldo->fd, pwd, sizeof(WaldoData));

    if (ret != sizeof(WaldoData))
        return WALDO_FILE_ETRUNC;

    //DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
    if ( print_c ++ > 5 ) {
        LogMessage("Waldo write\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
                waldo->data.spool_dir, waldo->data.spool_filebase,
                waldo->data.timestamp, waldo->data.record_idx);//);
        print_c = 0;
    }

    return WALDO_FILE_SUCCESS;
}

