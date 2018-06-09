
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


u_char *
ngx_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
    ngx_uint_t lower)
{
    size_t  hlen;

    hlen = ngx_http_v2_huff_encode(src, len, tmp, lower);

    if (hlen > 0) {
        dst = ngx_http_v2_write_int(dst, NGX_HTTP_V2_ENCODE_HUFF,
                                    ngx_http_v2_prefix(7), hlen);
        return ngx_cpymem(dst, tmp, hlen);
    }

    dst = ngx_http_v2_write_int(dst, NGX_HTTP_V2_ENCODE_RAW,
                                ngx_http_v2_prefix(7), len);

    if (lower) {
        ngx_strlow(dst, src, len);
        return dst + len;
    }

    return ngx_cpymem(dst, src, len);
}


u_char *
ngx_http_v2_write_int(u_char *pos, u_char prefix, ngx_uint_t prefix_mark,
                      ngx_uint_t value)
{
    *pos = prefix;

    if (value < prefix_mark) {
        *pos++ |= value;
        return pos;
    }

    *pos++ |= prefix_mark;
    value -= prefix_mark;

    while (value >= 128) {
        *pos++ = value % 128 + 128;
        value /= 128;
    }

    *pos++ = (u_char) value;

    return pos;
}
