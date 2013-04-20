/*
 * itrace: instruction traces + mem images for checked execution-driven simulation.
 *
 * Copyright (C) 2012 Chris Fallin <cfallin@c1f.net>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "itrace.h"
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
    int mode;
    gzFile regtrace, storetrace, pagedesc, pagedata;
} itrace;

void *itrace_open(const char *filename, int mode)
{
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    itrace *it = new itrace;
    memset(it, 0, sizeof(*it));
    it->mode = mode;
    const char *gzmode = (mode == ITRACE_READ) ? "rb" : "wb";

    char *p = NULL;

    if (mode == ITRACE_WRITE) {
        struct stat st;
        if (lstat(filename, &st) || !S_ISDIR(st.st_mode)) {
            if (mkdir(filename, 0755))
                return NULL;
        }
    }

    snprintf(buf, sizeof(buf), "%s/reg.gz", filename);
    it->regtrace = gzopen(buf, gzmode);
    if (!it->regtrace) goto err;

    snprintf(buf, sizeof(buf), "%s/store.gz", filename);
    it->storetrace = gzopen(buf, gzmode);
    if (!it->storetrace) goto err;
    
    snprintf(buf, sizeof(buf), "%s/pagedesc.gz", filename);
    it->pagedesc = gzopen(buf, gzmode);
    if (!it->pagedesc) goto err;

    snprintf(buf, sizeof(buf), "%s/page.gz", filename);
    it->pagedata = gzopen(buf, gzmode);
    if (!it->pagedata) goto err;

    return it;

err:
    itrace_close(it);
    return NULL;
}

void itrace_close(void *_it)
{
    itrace *it = (itrace *)_it;

    if (it->regtrace) gzclose(it->regtrace);
    if (it->storetrace) gzclose(it->storetrace);
    if (it->pagedesc) gzclose(it->pagedesc);
    if (it->pagedata) gzclose(it->pagedata);
    delete it;
}

void itrace_dump_page(void *_it, uint64_t lin_addr, void *data)
{
    itrace *it = (itrace *)_it;

    itrace_pagedesc_t pd;
    pd.lin_addr = lin_addr;
    gzwrite(it->pagedesc, &pd, sizeof(pd));

    if (data != NULL)
        gzwrite(it->pagedata, data, ITRACE_PAGESIZE);
}

void itrace_dump_insn(void *_it, itrace_rec_t *regs)
{
    itrace *it = (itrace *)_it;

    gzwrite(it->regtrace, regs, sizeof(itrace_rec_t));
}

void itrace_dump_store(void *_it, itrace_store_t *store)
{
    itrace *it = (itrace *)_it;

    gzwrite(it->storetrace, store, sizeof(itrace_store_t));
}

int itrace_read_pagedesc(void *_it, uint64_t *addr)
{
    itrace *it = (itrace *)_it;

    itrace_pagedesc_t pd;
    if (gzread(it->pagedesc, &pd, sizeof(itrace_pagedesc_t)) < sizeof(itrace_pagedesc_t))
        return 1;

    *addr = pd.lin_addr;
    return 0;
}
int itrace_read_page(void *_it, void *p)
{
    itrace *it = (itrace *)_it;

    if (gzread(it->pagedata, p, ITRACE_PAGESIZE) < ITRACE_PAGESIZE)
        return 1;

    return 0;
}

int itrace_read_rec(void *_it, itrace_rec_t *regs)
{
    itrace *it = (itrace *)_it;

    return gzread(it->regtrace, regs, sizeof(itrace_rec_t)) < sizeof(itrace_rec_t) ? 1 : 0;
}

int itrace_read_store(void *_it, itrace_store_t *store)
{
    itrace *it = (itrace *)_it;

    return gzread(it->storetrace, store, sizeof(itrace_store_t)) < sizeof(itrace_store_t) ? 1 : 0;
}

void itrace_flush(void *_it)
{
    itrace *it = (itrace *)_it;
    gzflush(it->regtrace, 0);
    gzflush(it->storetrace, 0);
    gzflush(it->pagedesc, 0);
    gzflush(it->pagedata, 0);
}
