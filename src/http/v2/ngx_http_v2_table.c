
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

static ngx_http_v2_hpack_enc_entry_t ngx_http_v2_static_enc_full_table[] = {
    {  7930902124308826620ul,  0 }, /* :authority: "" */
    { 16556161913875496195ul,  1 }, /* :method: GET */
    {  5581715088721755990ul,  2 }, /* :method: POST */
    { 12569388942226350397ul,  3 }, /* :path: / */
    { 18315342779312286844ul,  4 }, /* :path: /index.html */
    {  5586470839951386811ul,  5 }, /* :scheme: http */
    { 12990899192966345900ul,  6 }, /* :scheme: https */
    { 14173581913127366553ul,  7 }, /* :status: 200 */
    { 13018957267366627308ul,  8 }, /* :status: 204 */
    { 15379226314916651743ul,  9 }, /* :status: 206 */
    {  5639357197209129792ul, 10 }, /* :status: 304 */
    {  7288233927842547030ul, 11 }, /* :status: 400 */
    {   793875631434317877ul, 12 }, /* :status: 404 */
    { 10170705574155068963ul, 13 }, /* :status: 500 */
    { 18095552766877331121ul, 14 }, /* accept-charset: "" */
    {  1404147295585426788ul, 15 }, /* accept-encoding: gzip, deflate */
    {  3726452509314975719ul, 16 }, /* accept-language: "" */
    {  1450788028883061342ul, 17 }, /* accept-ranges: "" */
    { 16586941235727972538ul, 18 }, /* accept: "" */
    {  6244117089557528040ul, 19 }, /* access-control-allow-origin: "" */
    {  2704864586977666278ul, 20 }, /* age: "" */
    {  9593550597197685980ul, 21 }, /* allow: "" */
    { 14798810162494615186ul, 22 }, /* authorization: "" */
    {  2249753082254473417ul, 23 }, /* cache-control: "" */
    {  9706502812455060590ul, 24 }, /* content-disposition: "" */
    {  9377643852818603767ul, 25 }, /* content-encoding: "" */
    { 17005641614473994805ul, 26 }, /* content-language: "" */
    {  1221970724825924886ul, 27 }, /* content-length: "" */
    {  2763048024164237926ul, 28 }, /* content-location: "" */
    { 15627664510606120604ul, 29 }, /* content-range: "" */
    {  7487485810796847128ul, 30 }, /* content-type: "" */
    {  5380327194959332652ul, 31 }, /* cookie: "" */
    { 11099700565874545875ul, 32 }, /* date: "" */
    {  7352334411471398903ul, 33 }, /* etag: "" */
    { 14799934122182282377ul, 34 }, /* expect: "" */
    { 14733304227254433610ul, 35 }, /* expires: "" */
    { 17017966462891111704ul, 36 }, /* from: "" */
    {    59788587024290203ul, 37 }, /* host: "" */
    { 14871730852366211411ul, 38 }, /* if-match: "" */
    { 17509322415770519612ul, 39 }, /* if-modified-since: "" */
    {  2811573654834693002ul, 40 }, /* if-none-match: "" */
    { 17637884581237071576ul, 41 }, /* if-range: "" */
    { 15445484826688669233ul, 42 }, /* if-unmodified-since: "" */
    {  8914557466183843580ul, 43 }, /* last-modified: "" */
    {  5467218237507582902ul, 44 }, /* link: "" */
    { 15844241323617952264ul, 45 }, /* location: "" */
    {  7770484417306104173ul, 46 }, /* max-forwards: "" */
    { 14096017103484144801ul, 47 }, /* proxy-authenticate: "" */
    {  9121218896778544394ul, 48 }, /* proxy-authorization: "" */
    {  3470583080269321282ul, 49 }, /* range: "" */
    {  7398459282158744308ul, 50 }, /* referer: "" */
    { 16293797482652177017ul, 51 }, /* refresh: "" */
    { 16356964317069167460ul, 52 }, /* retry-after: "" */
    {  4945192815418105098ul, 53 }, /* server: "" */
    { 11867955111006370602ul, 54 }, /* set-cookie: "" */
    {  4120305522607019724ul, 55 }, /* strict-transport-security: "" */
    {  6096697664450587461ul, 56 }, /* transfer-encoding: "" */
    { 12956997759898165842ul, 57 }, /* user-agent: "" */
    {   610943487516715839ul, 58 }, /* vary: "" */
    {  7440380291692037534ul, 59 }, /* via: "" */
    {  6855383945900453272ul, 60 }, /* www-authenticate: "" */
};

static ngx_http_v2_hpack_enc_entry_t ngx_http_v2_static_enc_name_table[] = {
    {  7600914442529934747ul,  0 }, /* :authority: "" */
    {  7104828102655441542ul,  1 }, /* :method: GET */
    {  7104828102655441542ul,  1 }, /* :method: POST */
    {  4909850700723249199ul,  3 }, /* :path: / */
    {  4909850700723249199ul,  3 }, /* :path: /index.html */
    {   852941517273296199ul,  5 }, /* :scheme: http */
    {   852941517273296199ul,  5 }, /* :scheme: https */
    {  8869120592431865114ul,  7 }, /* :status: 200 */
    {  8869120592431865114ul,  7 }, /* :status: 204 */
    {  8869120592431865114ul,  7 }, /* :status: 206 */
    {  8869120592431865114ul,  7 }, /* :status: 304 */
    {  8869120592431865114ul,  7 }, /* :status: 400 */
    {  8869120592431865114ul,  7 }, /* :status: 404 */
    {  8869120592431865114ul,  7 }, /* :status: 500 */
    {  8136842195541005114ul, 14 }, /* accept-charset: "" */
    {  9657239900619169210ul, 15 }, /* accept-encoding: gzip, deflate */
    { 11636270841606038749ul, 16 }, /* accept-language: "" */
    { 10123556281241726926ul, 17 }, /* accept-ranges: "" */
    { 11050918199421639190ul, 18 }, /* accept: "" */
    {  4813077765911355357ul, 19 }, /* access-control-allow-origin: "" */
    {  5067543017542899782ul, 20 }, /* age: "" */
    {  5784339438414663998ul, 21 }, /* allow: "" */
    { 11525305471857710557ul, 22 }, /* authorization: "" */
    {  2031481254565303738ul, 23 }, /* cache-control: "" */
    {  4294556913853696092ul, 24 }, /* content-disposition: "" */
    {  5345710297124483676ul, 25 }, /* content-encoding: "" */
    {  5365524218201502413ul, 26 }, /* content-language: "" */
    {  4589119184121926995ul, 27 }, /* content-length: "" */
    {  4715797522707651357ul, 28 }, /* content-location: "" */
    { 11137485735171887497ul, 29 }, /* content-range: "" */
    {  5539797019315040679ul, 30 }, /* content-type: "" */
    {  5316904464086903239ul, 31 }, /* cookie: "" */
    { 17678863558478449476ul, 32 }, /* date: "" */
    {  5184999631575257383ul, 33 }, /* etag: "" */
    { 13221733106289703788ul, 34 }, /* expect: "" */
    {  6007614503573575338ul, 35 }, /* expires: "" */
    { 11504140205408408862ul, 36 }, /* from: "" */
    {  7629597251412992868ul, 37 }, /* host: "" */
    { 17272288305552405351ul, 38 }, /* if-match: "" */
    {  4573745218546680857ul, 39 }, /* if-modified-since: "" */
    {  6903657269200681770ul, 40 }, /* if-none-match: "" */
    { 11768192364658690982ul, 41 }, /* if-range: "" */
    { 17485788610390165731ul, 42 }, /* if-unmodified-since: "" */
    { 17709685868234314375ul, 43 }, /* last-modified: "" */
    { 12647401329964979937ul, 44 }, /* link: "" */
    { 17846216310059527368ul, 45 }, /* location: "" */
    {  3610207678659293513ul, 46 }, /* max-forwards: "" */
    { 17138200894846632141ul, 47 }, /* proxy-authenticate: "" */
    {  1509347135493285444ul, 48 }, /* proxy-authorization: "" */
    {  6970961207237384438ul, 49 }, /* range: "" */
    { 12619996676014881279ul, 50 }, /* referer: "" */
    { 14550474011317613232ul, 51 }, /* refresh: "" */
    {  5854853401617385966ul, 52 }, /* retry-after: "" */
    { 15588515746699132660ul, 53 }, /* server: "" */
    { 17681179895922681052ul, 54 }, /* set-cookie: "" */
    {  6282106568677236749ul, 55 }, /* strict-transport-security: "" */
    { 11590809123446223263ul, 56 }, /* transfer-encoding: "" */
    { 14032585805028055580ul, 57 }, /* user-agent: "" */
    { 14538408305000304039ul, 58 }, /* vary: "" */
    {  5897875324894276315ul, 59 }, /* via: "" */
    { 10999755847414491563ul, 60 }, /* www-authenticate: "" */

};

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


static void
ngx_http_v2_lookup_static_entry(ngx_http_v2_header_t *header, uint64_t hash_val,
    ngx_uint_t name_only, ngx_http_v2_hpack_enc_entry_t **out)
{
    ngx_http_v2_hpack_enc_entry_t *enc_table;

    *out = NULL;

    enc_table = name_only ? ngx_http_v2_static_enc_name_table :
                            ngx_http_v2_static_enc_full_table;

    switch (header->name.len) {
    case 3:
        switch (header->name.data[0]) {
        case 'a':
            if (hash_val == enc_table[20].hash_val) {
                *out = &enc_table[20]; /* age */
            }
            break;
        case 'v':
            if (hash_val == enc_table[59].hash_val) {
                *out = &enc_table[59]; /* via */
            }
            break;
        };
        break;

    case 4:
        switch (header->name.data[0]) {
        case 'd':
            if (hash_val == enc_table[32].hash_val) {
                *out = &enc_table[32]; /* date */
            }
            break;

        case 'e':
            if (hash_val == enc_table[33].hash_val) {
                *out = &enc_table[33]; /* etag */
            }
            break;

        case 'f':
            if (hash_val == enc_table[36].hash_val) {
                *out = &enc_table[36]; /* from */
            }
            break;

        case 'h':
            if (hash_val == enc_table[37].hash_val) {
                *out = &enc_table[37]; /* host */
            }
            break;

        case 'l':
            if (hash_val == enc_table[44].hash_val) {
                *out = &enc_table[44]; /* link */
            }
            break;

        case 'v':
            if (hash_val == enc_table[58].hash_val) {
                *out = &enc_table[58]; /* link */
            }
            break;
        };
        break;

    case 5:
        switch (header->name.data[0]) {
        case ':':
            if (hash_val == enc_table[3].hash_val) {
                *out = &enc_table[3]; /* path or path / */
            } else if (!name_only && hash_val == enc_table[4].hash_val) {
                *out = &enc_table[4]; /* path /index.html */
            }
            break;

        case 'a':
            if (hash_val == enc_table[21].hash_val) {
                *out = &enc_table[21]; /* allow */
            }
            break;

        case 'r':
            if (hash_val == enc_table[49].hash_val) {
                *out = &enc_table[49]; /* range */
            }
            break;

        };
        break;

    case 6:
        switch (header->name.data[0]) {
        case 'a':
            if (hash_val == enc_table[18].hash_val) {
                *out = &enc_table[18]; /* accept */
            }
            break;

        case 'c':
            if (hash_val == enc_table[31].hash_val) {
                *out = &enc_table[31]; /* cookie */
            }
            break;

        case 'e':
            if (hash_val == enc_table[34].hash_val) {
                *out = &enc_table[34]; /* expect */
            }
            break;

        case 's':
            if (hash_val == enc_table[53].hash_val) {
                *out = &enc_table[53]; /* server */
            }
            break;

        };
        break;

    case 7:
        switch (header->name.data[0]) {
        case ':':
            switch (header->name.data[2]) {
            case 'e':
                if (hash_val == enc_table[1].hash_val) {
                    *out = &enc_table[1]; /* method or method GET */
                } else if (!name_only && hash_val == enc_table[2].hash_val) {
                    *out = &enc_table[2]; /* method POST */
                }
                break;

            case 'c':
                if (hash_val == enc_table[5].hash_val) {
                    *out = &enc_table[5]; /* scheme or scheme http */
                } else if (!name_only && hash_val == enc_table[6].hash_val) {
                    *out = &enc_table[6]; /* scheme https */
                }
                break;

            case 't':
                if (hash_val == enc_table[7].hash_val) {
                    *out = &enc_table[7]; /* status or status 200 */
                } else if (!name_only && (header->value.len == 3)) {
                    switch (header->value.data[0]) {
                    case '2':
                        if (hash_val == enc_table[8].hash_val) {
                            *out = &enc_table[8]; /* status 204 */
                        } else if (hash_val == enc_table[9].hash_val) {
                            *out = &enc_table[9]; /* status 206 */
                        }
                        break;

                    case '3':
                        if (hash_val == enc_table[10].hash_val) {
                            *out = &enc_table[10]; /* status 304 */
                        }
                        break;

                    case '4':
                        if (hash_val == enc_table[11].hash_val) {
                            *out = &enc_table[11]; /* status 400 */
                        } else if (hash_val == enc_table[12].hash_val) {
                            *out = &enc_table[12]; /* status 404 */
                        }
                        break;

                    case '5':
                        if (hash_val == enc_table[13].hash_val) {
                            *out = &enc_table[13]; /* status 500 */
                        }
                        break;
                    };
                }
            };
            break;

        case 'e':
            if (hash_val == enc_table[35].hash_val) {
                *out = &enc_table[35]; /* expires */
            }
            break;

        case 'r':
            if (header->name.data[3] == 'e') {
                if (hash_val == enc_table[50].hash_val) {
                    *out = &enc_table[50]; /* referer */
                }
            } else if (header->name.data[3] == 'r') {
                if (hash_val == enc_table[51].hash_val) {
                    *out = &enc_table[51]; /* refresh */
                }
            }
            break;

        };
        break;

    case 8:
        switch (header->name.data[0]) {
        case 'i':
            if (header->name.data[3] == 'm') {
                if (hash_val == enc_table[38].hash_val) {
                    *out = &enc_table[38]; /* if-match */
                }
            } else if (header->name.data[3] == 'r') {
                if (hash_val == enc_table[41].hash_val) {
                    *out = &enc_table[41]; /* if-range */
                }
            }
            break;

        case 'l':
            if (hash_val == enc_table[45].hash_val) {
                *out = &enc_table[45]; /* location */
            }
            break;

        };
        break;

    case 10:
        switch (header->name.data[0]) {
        case ':':
            if (hash_val == enc_table[0].hash_val) {
                *out = &enc_table[0]; /* :authority */
            }
            break;

        case 's':
            if (hash_val == enc_table[54].hash_val) {
                *out = &enc_table[54]; /* set-cookie */
            }
            break;

        case 'u':
            if (hash_val == enc_table[57].hash_val) {
                *out = &enc_table[57]; /* user-agent */
            }
            break;

        };
        break;

    case 11:
        if (hash_val == enc_table[52].hash_val) {
            *out = &enc_table[52]; /* retry-after */
        }
        break;

    case 12:
        switch (header->name.data[0]) {
        case 'c':
            if (hash_val == enc_table[30].hash_val) {
                *out = &enc_table[30]; /* content-type */
            }
            break;

        case 'm':
            if (hash_val == enc_table[46].hash_val) {
                *out = &enc_table[46]; /* max-forwards */
            }
            break;

        };
        break;

    case 13:
        switch (header->name.data[6]) {
        case '-':
            if (hash_val == enc_table[17].hash_val) {
                *out = &enc_table[17]; /* accept-ranges */
            }
            break;

        case 'i':
            if (hash_val == enc_table[22].hash_val) {
                *out = &enc_table[22]; /* authorization */
            }
            break;

        case 'c':
            if (hash_val == enc_table[23].hash_val) {
                *out = &enc_table[23]; /* cache-control */
            }
            break;

        case 't':
            if (hash_val == enc_table[29].hash_val) {
                *out = &enc_table[29]; /* content-range */
            }
            break;

        case 'e':
            if (hash_val == enc_table[40].hash_val) {
                *out = &enc_table[40]; /* if-none-match */
            }
            break;

        case 'o':
            if (hash_val == enc_table[43].hash_val) {
                *out = &enc_table[43]; /* last-modified */
            }
            break;

        };
        break;

    case 14:
        switch (header->name.data[0]) {
        case 'a':
            if (hash_val == enc_table[14].hash_val) {
                *out = &enc_table[14]; /* accept-charset */
            }
            break;

        case 'c':
            if (hash_val == enc_table[27].hash_val) {
                *out = &enc_table[27]; /* content-length */
            }
            break;

        };
        break;

    case 15:
        switch (header->name.data[7]) {
        case 'e':
            if (hash_val == enc_table[15].hash_val) {
                *out = &enc_table[15]; /* accept-encoding or $_ gzip, deflate */
            }
            break;

        case 'l':
            if (hash_val == enc_table[16].hash_val) {
                *out = &enc_table[16]; /* accept-language */
            }
            break;

        };
        break;

    case 16:
        switch (header->name.data[11]) {
        case 'o':
            if (hash_val == enc_table[25].hash_val) {
                *out = &enc_table[25]; /* content-encoding */
            }
            break;

        case 'g':
            if (hash_val == enc_table[26].hash_val) {
                *out = &enc_table[26]; /* content-language */
            }
            break;

        case 'a':
            if (hash_val == enc_table[28].hash_val) {
                *out = &enc_table[28]; /* content-location */
            }
            break;

        case 'i':
            if (hash_val == enc_table[60].hash_val) {
                *out = &enc_table[60]; /* www-authenticate */
            }
            break;

        };
        break;

    case 17:
        switch (header->name.data[0]) {
        case 'i':
            if (hash_val == enc_table[39].hash_val) {
                *out = &enc_table[39]; /* if-modified-since */
            }
            break;

        case 't':
            if (hash_val == enc_table[56].hash_val) {
                *out = &enc_table[56]; /* transfer-encoding */
            }
            break;

        };
        break;

    case 18:
        if (hash_val == enc_table[47].hash_val) {
            *out = &enc_table[47]; /* proxy-authenticate */
        }
        break;

    case 19:
        switch (header->name.data[0]) {
        case 'c':
            if (hash_val == enc_table[24].hash_val) {
                *out = &enc_table[24]; /* content-disposition */
            }
            break;

        case 'i':
            if (hash_val == enc_table[42].hash_val) {
                *out = &enc_table[42]; /* if-unmodified-since */
            }
            break;

        case 'p':
            if (hash_val == enc_table[48].hash_val) {
                *out = &enc_table[48]; /* proxy-authorization */
            }
            break;

        };
        break;

    case 25:
        if (hash_val == enc_table[55].hash_val) {
            *out = &enc_table[55]; /* strict-transport-security */
        }
        break;

    case 27:
        if (hash_val == enc_table[19].hash_val) {
            *out = &enc_table[19]; /* access-control-allow-origin */
        }
        break;

    };
}


static ngx_uint_t
ngx_http_v2_compare_dynamic_stored_str(ngx_http_v2_hpack_t *hpack,
    ngx_str_t *stored_str, ngx_str_t *str)
{
    size_t     rest;
    ngx_uint_t cmp;

    if (stored_str->len > str->len) {
        return stored_str->len - str->len;
    } else if (str->len > stored_str->len) {
        return str->len - stored_str->len;
    }

    rest = hpack->storage + NGX_HTTP_V2_HEADER_TABLE_SIZE - stored_str->data;

    if (rest >= stored_str->len) {
        return ngx_strncmp(stored_str->data, str->data, str->len);
    }

    if (((cmp = ngx_strncmp(stored_str->data, str->data, rest)) != 0) ||
        ((cmp = ngx_strncmp(hpack->storage, str->data + rest,
                            str->len - rest)) != 0)) {
        return cmp;
    }

    return 0;
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


static ngx_int_t
ngx_http_v2_lookup_dynamic_entry(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header, uint64_t hash_val, ngx_uint_t name_only,
    ngx_http_v2_hpack_enc_entry_t **out)
{
    ngx_http_v2_hpack_enc_entry_t **table, *entry;
    ngx_http_v2_header_t          *stored_header;
    size_t                         table_size;
    uint64_t                       temp_hash;

    if (name_only) {
        if (h2c->hpack_enc.htable_name == NULL) {
            h2c->hpack_enc.htable_name = ngx_pcalloc(h2c->connection->pool,
                                         sizeof(ngx_http_v2_hpack_enc_entry_t *)
                                         * NGX_HTTP_V2_HPACK_NAME_HSIZE);
            if (h2c->hpack_enc.htable_name == NULL) {
                return NGX_ERROR;
            }
        }

        table = h2c->hpack_enc.htable_name;
        table_size = NGX_HTTP_V2_HPACK_NAME_HSIZE;
    } else {
        if (h2c->hpack_enc.htable_full == NULL) {
            h2c->hpack_enc.htable_full = ngx_pcalloc(h2c->connection->pool,
                                         sizeof(ngx_http_v2_hpack_enc_entry_t *)
                                         * NGX_HTTP_V2_HPACK_FULL_HSIZE);
            if (h2c->hpack_enc.htable_full == NULL) {
                return NGX_ERROR;
            }
        }

        table = h2c->hpack_enc.htable_full;
        table_size = NGX_HTTP_V2_HPACK_FULL_HSIZE;
    }

    temp_hash = hash_val;

    *out = NULL;

    for (; temp_hash > 0; temp_hash >>= 8) {
        entry = table[temp_hash % table_size];
        if (entry == NULL) {
            entry = ngx_pcalloc(h2c->connection->pool,
                                sizeof(ngx_http_v2_hpack_enc_entry_t));
            if (entry == NULL) {
                return NGX_ERROR;
            }

            table[temp_hash % table_size] = entry;

            *out = entry;

            return NGX_OK;
        }

        if (entry->index <= h2c->hpack_enc.hpack.deleted) {
            /* stale entry, clear it and keep it if needed */
            entry->hash_val = 0;
            entry->index = 0;

            if (*out == NULL) {
                *out = entry;
            }
            continue;
        }

        if (entry->hash_val != hash_val) {
            continue;
        }

        stored_header = h2c->hpack_enc.hpack.entries[(entry->index - 1) %
                                                 h2c->hpack_enc.hpack.allocated];

        if (ngx_http_v2_compare_dynamic_stored_str(&h2c->hpack_enc.hpack,
                                                   &stored_header->name,
                                                   &header->name) != 0) {
            continue;
        }

        if (!name_only &&
            ngx_http_v2_compare_dynamic_stored_str(&h2c->hpack_enc.hpack,
                                                   &stored_header->value,
                                                   &header->value) != 0) {
            continue;
        }

        *out = entry;

        break;
    }

    return NGX_OK;
}


void
ngx_http_v2_find_and_insert_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header, ngx_uint_t *index,
    ngx_uint_t *name_only, ngx_uint_t *was_added)
{
    ngx_http_v2_hpack_enc_entry_t *full_entry, *name_entry, *static_name_entry;
    uint64_t                       full_hash, name_hash;

    *index = 0;
    *name_only = 1;
    *was_added = 0;

    name_hash = ngx_murmur_hash2_64(header->name.data, header->name.len,
                                    0x01234);
    full_hash = ngx_murmur_hash2_64(header->value.data, header->value.len,
                                    name_hash);

    ngx_http_v2_lookup_static_entry(header, full_hash, 0, &full_entry);
    if (full_entry != NULL) {
        *index = full_entry->index + 1;
        *name_only = 0;
	return;
    }

    if (ngx_http_v2_lookup_dynamic_entry(h2c, header, full_hash, 0,
                                         &full_entry) != NGX_OK) {
        return;
    }
    if ((full_entry != NULL) && (full_entry->hash_val != 0)) {
        *index = h2c->hpack_enc.hpack.added - full_entry->index +
                 1 + NGX_HTTP_V2_STATIC_TABLE_ENTRIES;
        *name_only = 0;
        return;
    }

    ngx_http_v2_lookup_static_entry(header, name_hash, 1, &static_name_entry);
    if (static_name_entry != NULL) {
        /* static name only match, prefer it over any dynamic name only match */
        name_entry = static_name_entry;
        *index = name_entry->index + 1;
    } else {
        /* no static name only match */
        if (ngx_http_v2_lookup_dynamic_entry(h2c, header, name_hash, 1,
                                             &name_entry) != NGX_OK) {
            return;
        }
        if ((name_entry != NULL) && (name_entry->hash_val != 0)) {
            *index = h2c->hpack_enc.hpack.added - name_entry->index +
                     1 + NGX_HTTP_V2_STATIC_TABLE_ENTRIES;
        }
    }

    if ((full_entry == NULL) || (name_entry == NULL)) {
        /* failed to find a free slot for one of the entries, don't index */
        return;
    }

    if (ngx_http_v2_add_header(h2c, header, 0) != NGX_OK) {
        return;
    }

    full_entry->hash_val = full_hash;
    full_entry->index = h2c->hpack_enc.hpack.added;

    if (name_entry->hash_val == 0) {
        /* only update the dynamic table name_entry (hash_val == 0) */
        name_entry->hash_val = name_hash;
        name_entry->index = h2c->hpack_enc.hpack.added;
    }

    *was_added = full_entry->index;
}


ngx_int_t
ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header, ngx_uint_t is_request)
{
    size_t                 avail;
    ngx_uint_t             index;
    ngx_http_v2_hpack_t   *hpack;
    ngx_http_v2_header_t  *entry, **entries;

    hpack = (is_request) ? &h2c->hpack_dec : &h2c->hpack_enc.hpack;

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
        entry = hpack->entries[hpack->reused % hpack->allocated];
        hpack->entries[hpack->reused++ % hpack->allocated] = NULL;
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

        index = (hpack->deleted - 1) % hpack->allocated;

        ngx_memcpy(&entries[(hpack->allocated + 64 - 1) -
                            (hpack->allocated - index)],
                   &hpack->entries[index],
                   (hpack->allocated - index)
                   * sizeof(ngx_http_v2_header_t *));

        ngx_memcpy(entries, hpack->entries,
                   index * sizeof(ngx_http_v2_header_t *));

        (void) ngx_pfree(h2c->connection->pool, hpack->entries);

        hpack->entries = entries;

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

    hpack = (is_request) ? &h2c->hpack_dec : &h2c->hpack_enc.hpack;

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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                     "http2 deleting entry: %uz",
                     hpack->deleted + 1 + NGX_HTTP_V2_STATIC_TABLE_ENTRIES);
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

    hpack = (is_decode) ? &h2c->hpack_dec : &h2c->hpack_enc.hpack;

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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 deleting entry: %uz",
                       hpack->deleted + 1 + NGX_HTTP_V2_STATIC_TABLE_ENTRIES);
        entry = hpack->entries[hpack->deleted++ % hpack->allocated];
        hpack->free += 32 + entry->name.len + entry->value.len;
    }

    hpack->size = size;
    hpack->free -= needed;

    return NGX_OK;
}
