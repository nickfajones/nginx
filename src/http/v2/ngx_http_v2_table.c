
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c,
    size_t size, ngx_uint_t is_request);


static ngx_http_v2_header_t  ngx_http_v2_static_table[] = {
    { ngx_string(":authority"), ngx_string("") },
    { ngx_string(":method"), ngx_string("GET") },
    { ngx_string(":method"), ngx_string("POST") },
    { ngx_string(":path"), ngx_string("/") },
    { ngx_string(":path"), ngx_string("/index.html") },
    { ngx_string(":scheme"), ngx_string("http") },
    { ngx_string(":scheme"), ngx_string("https") },
    { ngx_string(":status"), ngx_string("200") },
    { ngx_string(":status"), ngx_string("204") },
    { ngx_string(":status"), ngx_string("206") },
    { ngx_string(":status"), ngx_string("304") },
    { ngx_string(":status"), ngx_string("400") },
    { ngx_string(":status"), ngx_string("404") },
    { ngx_string(":status"), ngx_string("500") },
    { ngx_string("accept-charset"), ngx_string("") },
    { ngx_string("accept-encoding"), ngx_string("gzip, deflate") },
    { ngx_string("accept-language"), ngx_string("") },
    { ngx_string("accept-ranges"), ngx_string("") },
    { ngx_string("accept"), ngx_string("") },
    { ngx_string("access-control-allow-origin"), ngx_string("") },
    { ngx_string("age"), ngx_string("") },
    { ngx_string("allow"), ngx_string("") },
    { ngx_string("authorization"), ngx_string("") },
    { ngx_string("cache-control"), ngx_string("") },
    { ngx_string("content-disposition"), ngx_string("") },
    { ngx_string("content-encoding"), ngx_string("") },
    { ngx_string("content-language"), ngx_string("") },
    { ngx_string("content-length"), ngx_string("") },
    { ngx_string("content-location"), ngx_string("") },
    { ngx_string("content-range"), ngx_string("") },
    { ngx_string("content-type"), ngx_string("") },
    { ngx_string("cookie"), ngx_string("") },
    { ngx_string("date"), ngx_string("") },
    { ngx_string("etag"), ngx_string("") },
    { ngx_string("expect"), ngx_string("") },
    { ngx_string("expires"), ngx_string("") },
    { ngx_string("from"), ngx_string("") },
    { ngx_string("host"), ngx_string("") },
    { ngx_string("if-match"), ngx_string("") },
    { ngx_string("if-modified-since"), ngx_string("") },
    { ngx_string("if-none-match"), ngx_string("") },
    { ngx_string("if-range"), ngx_string("") },
    { ngx_string("if-unmodified-since"), ngx_string("") },
    { ngx_string("last-modified"), ngx_string("") },
    { ngx_string("link"), ngx_string("") },
    { ngx_string("location"), ngx_string("") },
    { ngx_string("max-forwards"), ngx_string("") },
    { ngx_string("proxy-authenticate"), ngx_string("") },
    { ngx_string("proxy-authorization"), ngx_string("") },
    { ngx_string("range"), ngx_string("") },
    { ngx_string("referer"), ngx_string("") },
    { ngx_string("refresh"), ngx_string("") },
    { ngx_string("retry-after"), ngx_string("") },
    { ngx_string("server"), ngx_string("") },
    { ngx_string("set-cookie"), ngx_string("") },
    { ngx_string("strict-transport-security"), ngx_string("") },
    { ngx_string("transfer-encoding"), ngx_string("") },
    { ngx_string("user-agent"), ngx_string("") },
    { ngx_string("vary"), ngx_string("") },
    { ngx_string("via"), ngx_string("") },
    { ngx_string("www-authenticate"), ngx_string("") },
};

#define NGX_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(ngx_http_v2_static_table)                                         \
     / sizeof(ngx_http_v2_header_t))


ngx_str_t *
ngx_http_v2_get_static_name(ngx_uint_t index)
{
    return &ngx_http_v2_static_table[index - 1].name;
}


ngx_str_t *
ngx_http_v2_get_static_value(ngx_uint_t index)
{
    return &ngx_http_v2_static_table[index - 1].value;
}


ngx_int_t
ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c, ngx_uint_t index,
    ngx_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    ngx_http_v2_header_t  *entry;

    if (index == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < NGX_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = ngx_http_v2_static_table[index];
        return NGX_OK;
    }

    index -= NGX_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack_dec.added - h2c->hpack_dec.deleted) {
        index = (h2c->hpack_dec.added - index - 1) % h2c->hpack_dec.allocated;
        entry = h2c->hpack_dec.entries[index];

        p = ngx_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack_dec.storage + NGX_HTTP_V2_HEADER_TABLE_SIZE -
               entry->name.data;

        if (entry->name.len > rest) {
            p = ngx_cpymem(p, entry->name.data, rest);
            p = ngx_cpymem(p, h2c->hpack_dec.storage, entry->name.len - rest);

        } else {
            p = ngx_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return NGX_OK;
        }

        p = ngx_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack_dec.storage + NGX_HTTP_V2_HEADER_TABLE_SIZE -
               entry->value.data;

        if (entry->value.len > rest) {
            p = ngx_cpymem(p, entry->value.data, rest);
            p = ngx_cpymem(p, h2c->hpack_dec.storage, entry->value.len - rest);

        } else {
            p = ngx_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return NGX_ERROR;
}


void
ngx_http_v2_get_header_index(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header, ngx_uint_t *index, ngx_uint_t *name_only)
{
    ngx_uint_t             i, static_index;
    ngx_http_v2_header_t  *stored_header;
    size_t                 rest;

    *index = 0;
    *name_only = 1;

    for (i = 0; i < NGX_HTTP_V2_STATIC_TABLE_ENTRIES; i++) {
        stored_header = &ngx_http_v2_static_table[i];

        if ((stored_header->name.len != header->name.len) ||
            (ngx_strncmp(stored_header->name.data, header->name.data,
                         stored_header->name.len) != 0)) {
            if (*index != 0) {
                /* passed by all headers with matching name,
                   in the static table, there will be no more matches,
                   keep result at previous index */
                *name_only = 1;

                break;
            }

            continue;
        }

        *index = i + 1;

        if ((stored_header->value.len > 0) &&
            (stored_header->value.len == header->value.len) &&
            (ngx_strncmp(stored_header->value.data, header->value.data,
                         stored_header->value.len) == 0)) {
            *name_only = 0;

            break;
        }
    }

    if ((*index > 0) && (*name_only == 0)) {
        return;
    }

    static_index = *index;
    *index = 0;

    for (i = h2c->hpack_enc.added; i > h2c->hpack_enc.deleted; i--) {
        stored_header = h2c->hpack_enc.entries[(i-1) % h2c->hpack_enc.allocated];

        rest = h2c->hpack_enc.storage + NGX_HTTP_V2_HEADER_TABLE_SIZE -
               stored_header->name.data;

        if ((stored_header->name.len != header->name.len) ||

            (((rest >= stored_header->name.len) &&
              (ngx_strncmp(stored_header->name.data, header->name.data,
                           header->name.len))) ||

             ((rest < stored_header->name.len) &&
               ((ngx_strncmp(stored_header->name.data, header->name.data,
                             rest)) ||
                (ngx_strncmp(h2c->hpack_enc.storage,
                             header->name.data + rest,
                             header->name.len - rest)))))) {
            /* dynamic hpack will not store repeated headers in order, so we
               must continue the search through the table */
            continue;
        }

        *index = h2c->hpack_enc.added - i + 1;

        rest = h2c->hpack_enc.storage + NGX_HTTP_V2_HEADER_TABLE_SIZE -
               stored_header->value.data;

        if ((stored_header->value.len == header->value.len) &&

            (((rest >= stored_header->value.len) &&
              (ngx_strncmp(stored_header->value.data, header->value.data,
                           header->value.len) == 0)) ||

             ((rest < stored_header->value.len) &&
               (ngx_strncmp(stored_header->value.data, header->value.data,
                            rest) == 0) &&
               (ngx_strncmp(h2c->hpack_enc.storage,
                            header->value.data + rest,
                            header->value.len - rest) == 0)))) {
            *name_only = 0;

            break;
        }
    }

    if ((static_index > 0) && ((index == 0) || (*name_only == 1))) {
        /* static only or static and dynamic name only match, prefer static */
        *index = static_index;
        return;
    }

    if (*index > 0) {
        /* full or name only match on dynamic table */
        *index += NGX_HTTP_V2_STATIC_TABLE_ENTRIES;
        return;
    }
}


ngx_int_t
ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header, ngx_uint_t is_request)
{
    size_t                 avail;
    ngx_uint_t             index;
    ngx_http_v2_hpack_t   *hpack;
    ngx_http_v2_header_t  *entry, **entries;

    hpack = (is_request) ? &h2c->hpack_dec : &h2c->hpack_enc;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 hpack %s table add: \"%V: %V\"",
                   is_request ? "decode" : "encode",
                   &header->name, &header->value);

    if (hpack->entries == NULL) {
        hpack->allocated = 64;

        hpack->entries = ngx_palloc(h2c->connection->pool,
                                    sizeof(ngx_http_v2_header_t *)
                                    * hpack->allocated);
        if (hpack->entries == NULL) {
            return NGX_ERROR;
        }

        hpack->storage = ngx_palloc(h2c->connection->pool,
                                    NGX_HTTP_V2_HEADER_TABLE_SIZE);
        if (hpack->storage == NULL) {
            return NGX_ERROR;
        }

        hpack->pos = hpack->storage;
    }

    if (ngx_http_v2_table_account(h2c, header->name.len + header->value.len,
                                  is_request) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (hpack->reused == hpack->deleted) {
        entry = ngx_palloc(h2c->connection->pool, sizeof(ngx_http_v2_header_t));
        if (entry == NULL) {
            return NGX_ERROR;
        }

    } else {
        entry = hpack->entries[hpack->reused++ % hpack->allocated];
    }

    avail = hpack->storage + NGX_HTTP_V2_HEADER_TABLE_SIZE - hpack->pos;

    entry->name.len = header->name.len;
    entry->name.data = hpack->pos;

    if (avail >= header->name.len) {
        hpack->pos = ngx_cpymem(hpack->pos, header->name.data,
                                header->name.len);
    } else {
        ngx_memcpy(hpack->pos, header->name.data, avail);
        hpack->pos = ngx_cpymem(hpack->storage,
                                header->name.data + avail,
                                header->name.len - avail);
        avail = NGX_HTTP_V2_HEADER_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = hpack->pos;

    if (avail >= header->value.len) {
        hpack->pos = ngx_cpymem(hpack->pos, header->value.data,
                                header->value.len);
    } else {
        ngx_memcpy(hpack->pos, header->value.data, avail);
        hpack->pos = ngx_cpymem(hpack->storage,
                                header->value.data + avail,
                                header->value.len - avail);
    }

    if (hpack->allocated == hpack->added - hpack->deleted) {

        entries = ngx_palloc(h2c->connection->pool,
                             sizeof(ngx_http_v2_header_t *)
                             * (hpack->allocated + 64));
        if (entries == NULL) {
            return NGX_ERROR;
        }

        index = hpack->deleted % hpack->allocated;

        ngx_memcpy(entries, &hpack->entries[index],
                   (hpack->allocated - index)
                   * sizeof(ngx_http_v2_header_t *));

        ngx_memcpy(&entries[hpack->allocated - index], hpack->entries,
                   index * sizeof(ngx_http_v2_header_t *));

        (void) ngx_pfree(h2c->connection->pool, hpack->entries);

        hpack->entries = entries;

        hpack->added = hpack->allocated;
        hpack->deleted = 0;
        hpack->reused = 0;
        hpack->allocated += 64;
    }

    hpack->entries[hpack->added++ % hpack->allocated] = entry;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c, size_t size,
    ngx_uint_t is_request)
{
    ngx_http_v2_hpack_t   *hpack;
    ngx_http_v2_header_t  *entry;

    hpack = (is_request) ? &h2c->hpack_dec : &h2c->hpack_enc;

    size += 32;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 hpack %s table account: %uz free:%uz",
                   is_request ? "decode" : "encode", size, hpack->free);

    if (size <= hpack->free) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 capacity available");
        hpack->free -= size;
        return NGX_OK;
    }

    if (size > hpack->size) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 declined: table size will be exceeded");
        return NGX_DECLINED;
    }

    do {
        entry = hpack->entries[hpack->deleted++ % hpack->allocated];
        hpack->free += 32 + entry->name.len + entry->value.len;
    } while (size > hpack->free);

    hpack->free -= size;

    return NGX_OK;
}


ngx_int_t
ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size,
    ngx_uint_t is_decode)
{
    ngx_http_v2_hpack_t   *hpack;
    ngx_http_v2_header_t  *entry;
    ssize_t                needed;

    hpack = (is_decode) ? &h2c->hpack_dec : &h2c->hpack_enc;

    if (size > NGX_HTTP_V2_HEADER_TABLE_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack %s table size: %uz was:%uz",
                   is_decode ? "decode" : "encode", size, hpack->size);

    needed = hpack->size - size;

    while (needed > (ssize_t) hpack->free) {
        entry = hpack->entries[hpack->deleted++ % hpack->allocated];
        hpack->free += 32 + entry->name.len + entry->value.len;
    }

    hpack->size = size;
    hpack->free -= needed;

    return NGX_OK;
}
