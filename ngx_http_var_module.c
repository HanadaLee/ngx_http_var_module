
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>

#if (NGX_HTTP_SSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif


#define ngx_http_var_isspace(c)                                               \
    ((c) == ' ' || (c) == '\t' || (c) == CR || (c) == LF)                     \


typedef enum {
    NGX_HTTP_VAR_OP_AND = 0,
    NGX_HTTP_VAR_OP_OR,
    NGX_HTTP_VAR_OP_NOT,

    NGX_HTTP_VAR_OP_IF_EMPTY,
    NGX_HTTP_VAR_OP_IF_NOT_EMPTY,
    NGX_HTTP_VAR_OP_IF_IS_NUM,
    NGX_HTTP_VAR_OP_IF_STR_EQ,
    NGX_HTTP_VAR_OP_IF_STR_NE,
    NGX_HTTP_VAR_OP_IF_STARTS_WITH,
    NGX_HTTP_VAR_OP_IF_ENDS_WITH,
    NGX_HTTP_VAR_OP_IF_FIND,
    NGX_HTTP_VAR_OP_IF_STR_IN,

    NGX_HTTP_VAR_OP_COPY,
    NGX_HTTP_VAR_OP_LEN,
    NGX_HTTP_VAR_OP_UPPER,
    NGX_HTTP_VAR_OP_LOWER,
    NGX_HTTP_VAR_OP_TRIM,
    NGX_HTTP_VAR_OP_LTRIM,
    NGX_HTTP_VAR_OP_RTRIM,
    NGX_HTTP_VAR_OP_REVERSE,
    NGX_HTTP_VAR_OP_FIND,
    NGX_HTTP_VAR_OP_REPEAT,
    NGX_HTTP_VAR_OP_SUBSTR,
    NGX_HTTP_VAR_OP_REPLACE,
    NGX_HTTP_VAR_OP_EXTRACT_PARAM,

#if (NGX_PCRE)
    NGX_HTTP_VAR_OP_IF_RE_MATCH,

    NGX_HTTP_VAR_OP_RE_CAPTURE,
    NGX_HTTP_VAR_OP_RE_SUB,
#endif

    NGX_HTTP_VAR_OP_IF_EQ,
    NGX_HTTP_VAR_OP_IF_NE,
    NGX_HTTP_VAR_OP_IF_LT,
    NGX_HTTP_VAR_OP_IF_LE,
    NGX_HTTP_VAR_OP_IF_GT,
    NGX_HTTP_VAR_OP_IF_GE,
    NGX_HTTP_VAR_OP_IF_RANGE,
    NGX_HTTP_VAR_OP_IF_IN,

    NGX_HTTP_VAR_OP_ABS,
    NGX_HTTP_VAR_OP_MAX,
    NGX_HTTP_VAR_OP_MIN,
    NGX_HTTP_VAR_OP_ADD,
    NGX_HTTP_VAR_OP_SUB,
    NGX_HTTP_VAR_OP_MUL,
    NGX_HTTP_VAR_OP_DIV,
    NGX_HTTP_VAR_OP_MOD,
    NGX_HTTP_VAR_OP_ROUND,
    NGX_HTTP_VAR_OP_FLOOR,
    NGX_HTTP_VAR_OP_CEIL,
    NGX_HTTP_VAR_OP_RAND,
    NGX_HTTP_VAR_OP_HEXRAND,

    NGX_HTTP_VAR_OP_HEX_ENCODE,
    NGX_HTTP_VAR_OP_HEX_DECODE,
    NGX_HTTP_VAR_OP_DEC_TO_HEX,
    NGX_HTTP_VAR_OP_HEX_TO_DEC,
    NGX_HTTP_VAR_OP_ESCAPE_URI,
    NGX_HTTP_VAR_OP_ESCAPE_ARGS,
    NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT,
    NGX_HTTP_VAR_OP_ESCAPE_HTML,
    NGX_HTTP_VAR_OP_UNESCAPE_URI,
    NGX_HTTP_VAR_OP_BASE64_ENCODE,
    NGX_HTTP_VAR_OP_BASE64URL_ENCODE,
    NGX_HTTP_VAR_OP_BASE64_DECODE,
    NGX_HTTP_VAR_OP_BASE64URL_DECODE,

    NGX_HTTP_VAR_OP_CRC32,
    NGX_HTTP_VAR_OP_MD5,
    NGX_HTTP_VAR_OP_SHA1,

#if (NGX_HTTP_SSL)
    NGX_HTTP_VAR_OP_SHA224,
    NGX_HTTP_VAR_OP_SHA256,
    NGX_HTTP_VAR_OP_SHA384,
    NGX_HTTP_VAR_OP_SHA512,

    NGX_HTTP_VAR_OP_HMAC_MD5,
    NGX_HTTP_VAR_OP_HMAC_SHA1,
    NGX_HTTP_VAR_OP_HMAC_SHA224,
    NGX_HTTP_VAR_OP_HMAC_SHA256,
    NGX_HTTP_VAR_OP_HMAC_SHA384,
    NGX_HTTP_VAR_OP_HMAC_SHA512,
#endif

    NGX_HTTP_VAR_OP_IF_TIME_RANGE,

    NGX_HTTP_VAR_OP_GMT_TIME,
    NGX_HTTP_VAR_OP_LOCAL_TIME,
    NGX_HTTP_VAR_OP_UNIX_TIME,

    NGX_HTTP_VAR_OP_IF_IP_RANGE,

    NGX_HTTP_VAR_OP_UNKNOWN
} ngx_http_var_operator_e;


typedef struct {
    ngx_array_t                   *vars;
} ngx_http_var_conf_t;


typedef struct {
    ngx_str_t                      name;        /* variable name */
    ngx_int_t                      index;       /* variable index */
    ngx_http_var_operator_e        operator;    /* operator type */
    ngx_uint_t                     ignore_case; /* ignore case sensitivity */
    ngx_array_t                   *args;        /* operator extra args */
    ngx_http_complex_value_t      *filter;      /* filter complex value */
    ngx_uint_t                     negative;    /* negative filter */

#if (NGX_PCRE)
    ngx_http_regex_t              *regex;       /* compiled regex */
#endif
} ngx_http_var_variable_t;


typedef struct {
    ngx_uint_t                    *locked_vars;
} ngx_http_var_ctx_t;


typedef struct {
    ngx_str_t                      name;        /* operator string */
    ngx_http_var_operator_e        op;          /* operator enum */
    ngx_uint_t                     min_args;    /* min number of arguments */
    ngx_uint_t                     max_args;    /* max number of arguments */
} ngx_http_var_operator_enum_t;


static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_http_var_ctx_t *ngx_http_var_get_lock_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_variable_acquire_lock(ngx_http_request_t *r,
    ngx_int_t index);
static void ngx_http_variable_release_lock(ngx_http_request_t *r,
    ngx_int_t index);
static ngx_int_t ngx_http_var_find_variable(ngx_http_request_t *r,
    ngx_int_t index, ngx_http_var_conf_t *vcf,
    ngx_http_var_variable_t **var);
static ngx_int_t ngx_http_var_evaluate_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_var_utils_check_str_is_num(ngx_str_t num_str);
static ngx_int_t ngx_http_var_utils_auto_atoi(ngx_str_t val,
    ngx_int_t *int_val);
static ngx_int_t ngx_http_var_utils_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2);
static ngx_int_t ngx_http_var_utils_auto_atofp3(ngx_str_t val1, ngx_str_t val2,
    ngx_str_t val3, ngx_int_t *int_val1,
    ngx_int_t *int_val2, ngx_int_t *int_val3);
static ngx_int_t ngx_http_var_utils_parse_uint_range(ngx_str_t str,
    ngx_int_t *start, ngx_int_t *end);
static ngx_int_t ngx_http_var_utils_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    ngx_uint_t type);
static u_char *ngx_http_var_utils_strlstrn(u_char *s1, u_char *last,
    u_char *s2, size_t n);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_var_utils_sha(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    const EVP_MD *evp_md, size_t len);
static ngx_int_t ngx_http_var_utils_hmac(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    const EVP_MD *evp_md);
#endif

static ngx_int_t ngx_http_var_exec_and(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_or(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_not(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_if_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_not_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_is_num(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_str_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_str_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_starts_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_ends_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_str_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_extract_param(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_exec_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

static ngx_int_t ngx_http_var_exec_if_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_lt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_le(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_gt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_ge(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_if_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_abs(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_add(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_mul(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_div(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_mod(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_round(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_floor(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_ceil(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hexrand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_dec_to_hex(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hex_to_dec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_escape_uri_component(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_escape_html(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_base64_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_base64url_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_base64_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_base64url_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_crc32(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_var_exec_sha224(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha384(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha224(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha384(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

static ngx_int_t ngx_http_var_exec_if_time_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_gmt_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_local_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_unix_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_if_ip_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);


static ngx_http_var_operator_enum_t  ngx_http_var_operators[] = {
    { ngx_string("and"),              NGX_HTTP_VAR_OP_AND,             2, 99 },
    { ngx_string("or"),               NGX_HTTP_VAR_OP_OR,              2, 99 },
    { ngx_string("not"),              NGX_HTTP_VAR_OP_NOT,             1, 1  },

    { ngx_string("if_empty"),         NGX_HTTP_VAR_OP_IF_EMPTY,        1, 1  },
    { ngx_string("if_not_empty"),     NGX_HTTP_VAR_OP_IF_NOT_EMPTY,    1, 1  },
    { ngx_string("if_is_num"),        NGX_HTTP_VAR_OP_IF_IS_NUM,       1, 1  },
    { ngx_string("if_str_eq"),        NGX_HTTP_VAR_OP_IF_STR_EQ,       2, 2  },
    { ngx_string("if_str_ne"),        NGX_HTTP_VAR_OP_IF_STR_NE,       2, 2  },
    { ngx_string("if_starts_with"),   NGX_HTTP_VAR_OP_IF_STARTS_WITH,  2, 2  },
    { ngx_string("if_ends_with"),     NGX_HTTP_VAR_OP_IF_ENDS_WITH,    2, 2  },
    { ngx_string("if_find"),          NGX_HTTP_VAR_OP_IF_FIND,         2, 2  },
    { ngx_string("if_str_in"),        NGX_HTTP_VAR_OP_IF_STR_IN,       3, 99 },

    { ngx_string("copy"),             NGX_HTTP_VAR_OP_COPY,            1, 1  },
    { ngx_string("len"),              NGX_HTTP_VAR_OP_LEN,             1, 1  },
    { ngx_string("upper"),            NGX_HTTP_VAR_OP_UPPER,           1, 1  },
    { ngx_string("lower"),            NGX_HTTP_VAR_OP_LOWER,           1, 1  },
    { ngx_string("trim"),             NGX_HTTP_VAR_OP_TRIM,            1, 1  },
    { ngx_string("ltrim"),            NGX_HTTP_VAR_OP_LTRIM,           1, 1  },
    { ngx_string("rtrim"),            NGX_HTTP_VAR_OP_RTRIM,           1, 1  },
    { ngx_string("reverse"),          NGX_HTTP_VAR_OP_REVERSE,         1, 1  },
    { ngx_string("find"),             NGX_HTTP_VAR_OP_FIND,            2, 2  },
    { ngx_string("repeat"),           NGX_HTTP_VAR_OP_REPEAT,          2, 2  },
    { ngx_string("substr"),           NGX_HTTP_VAR_OP_SUBSTR,          2, 3  },
    { ngx_string("replace"),          NGX_HTTP_VAR_OP_REPLACE,         3, 3  },
    { ngx_string("extract_param"),    NGX_HTTP_VAR_OP_EXTRACT_PARAM,   2, 4  },

#if (NGX_PCRE)
    { ngx_string("if_re_match"),      NGX_HTTP_VAR_OP_IF_RE_MATCH,     2, 2  },

    { ngx_string("re_capture"),       NGX_HTTP_VAR_OP_RE_CAPTURE,      3, 3  },
    { ngx_string("re_sub"),           NGX_HTTP_VAR_OP_RE_SUB,          3, 3  },
#endif

    { ngx_string("if_eq"),            NGX_HTTP_VAR_OP_IF_EQ,           2, 2  },
    { ngx_string("if_ne"),            NGX_HTTP_VAR_OP_IF_NE,           2, 2  },
    { ngx_string("if_lt"),            NGX_HTTP_VAR_OP_IF_LT,           2, 2  },
    { ngx_string("if_le"),            NGX_HTTP_VAR_OP_IF_LE,           2, 2  },
    { ngx_string("if_gt"),            NGX_HTTP_VAR_OP_IF_GT,           2, 2  },
    { ngx_string("if_ge"),            NGX_HTTP_VAR_OP_IF_GE,           2, 2  },
    { ngx_string("if_range"),         NGX_HTTP_VAR_OP_IF_RANGE,        2, 3  },
    { ngx_string("if_in"),            NGX_HTTP_VAR_OP_IF_IN,           3, 99 },

    { ngx_string("abs"),              NGX_HTTP_VAR_OP_ABS,             1, 1  },
    { ngx_string("max"),              NGX_HTTP_VAR_OP_MAX,             2, 2  },
    { ngx_string("min"),              NGX_HTTP_VAR_OP_MIN,             2, 2  },
    { ngx_string("add"),              NGX_HTTP_VAR_OP_ADD,             2, 2  },
    { ngx_string("sub"),              NGX_HTTP_VAR_OP_SUB,             2, 2  },
    { ngx_string("mul"),              NGX_HTTP_VAR_OP_MUL,             2, 2  },
    { ngx_string("div"),              NGX_HTTP_VAR_OP_DIV,             2, 2  },
    { ngx_string("mod"),              NGX_HTTP_VAR_OP_MOD,             2, 2  },
    { ngx_string("round"),            NGX_HTTP_VAR_OP_ROUND,           2, 2  },
    { ngx_string("floor"),            NGX_HTTP_VAR_OP_FLOOR,           1, 1  },
    { ngx_string("ceil"),             NGX_HTTP_VAR_OP_CEIL,            1, 1  },
    { ngx_string("rand"),             NGX_HTTP_VAR_OP_RAND,            0, 2  },
    { ngx_string("hexrand"),          NGX_HTTP_VAR_OP_HEXRAND,         0, 1  },

    { ngx_string("hex_encode"),       NGX_HTTP_VAR_OP_HEX_ENCODE,      1, 1  },
    { ngx_string("hex_decode"),       NGX_HTTP_VAR_OP_HEX_DECODE,      1, 1  },
    { ngx_string("dec_to_hex"),       NGX_HTTP_VAR_OP_DEC_TO_HEX,      1, 1  },
    { ngx_string("hex_to_dec"),       NGX_HTTP_VAR_OP_HEX_TO_DEC,      1, 1  },
    { ngx_string("escape_uri"),       NGX_HTTP_VAR_OP_ESCAPE_URI,      1, 1  },
    { ngx_string("escape_args"),      NGX_HTTP_VAR_OP_ESCAPE_ARGS,     1, 1  },
    { ngx_string("escape_uri_component"),
                                NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT,  1, 1  },
    { ngx_string("escape_html"),      NGX_HTTP_VAR_OP_ESCAPE_HTML,     1, 1  },
    { ngx_string("unescape_uri"),     NGX_HTTP_VAR_OP_UNESCAPE_URI,    1, 1  },
    { ngx_string("base64_encode"),    NGX_HTTP_VAR_OP_BASE64_ENCODE,   1, 1  },
    { ngx_string("base64url_encode"),
                                     NGX_HTTP_VAR_OP_BASE64URL_ENCODE, 1, 1  },
    { ngx_string("base64_decode"),    NGX_HTTP_VAR_OP_BASE64_DECODE,   1, 1  },
    { ngx_string("base64url_decode"),
                                     NGX_HTTP_VAR_OP_BASE64URL_DECODE, 1, 1  },

    { ngx_string("crc32"),            NGX_HTTP_VAR_OP_CRC32,           1, 1  },
    { ngx_string("md5"),              NGX_HTTP_VAR_OP_MD5,             1, 1  },
    { ngx_string("sha1"),             NGX_HTTP_VAR_OP_SHA1,            1, 1  },

#if (NGX_HTTP_SSL)
    { ngx_string("sha224"),           NGX_HTTP_VAR_OP_SHA224,          1, 1  },
    { ngx_string("sha256"),           NGX_HTTP_VAR_OP_SHA256,          1, 1  },
    { ngx_string("sha384"),           NGX_HTTP_VAR_OP_SHA384,          1, 1  },
    { ngx_string("sha512"),           NGX_HTTP_VAR_OP_SHA512,          1, 1  },
    { ngx_string("hmac_md5"),         NGX_HTTP_VAR_OP_HMAC_MD5,        2, 2  },
    { ngx_string("hmac_sha1"),        NGX_HTTP_VAR_OP_HMAC_SHA1,       2, 2  },
    { ngx_string("hmac_sha224"),      NGX_HTTP_VAR_OP_HMAC_SHA224,     2, 2  },
    { ngx_string("hmac_sha256"),      NGX_HTTP_VAR_OP_HMAC_SHA256,     2, 2  },
    { ngx_string("hmac_sha384"),      NGX_HTTP_VAR_OP_HMAC_SHA384,     2, 2  },
    { ngx_string("hmac_sha512"),      NGX_HTTP_VAR_OP_HMAC_SHA512,     2, 2  },
#endif

    { ngx_string("if_time_range"),    NGX_HTTP_VAR_OP_IF_TIME_RANGE,   1, 8  },

    { ngx_string("gmt_time"),         NGX_HTTP_VAR_OP_GMT_TIME,        1, 2  },
    { ngx_string("local_time"),       NGX_HTTP_VAR_OP_LOCAL_TIME,      1, 2  },
    { ngx_string("unix_time"),        NGX_HTTP_VAR_OP_UNIX_TIME,       0, 3  },

    { ngx_string("if_ip_range"),      NGX_HTTP_VAR_OP_IF_IP_RANGE,     2, 99 },

    { ngx_null_string,                NGX_HTTP_VAR_OP_UNKNOWN,         0, 0  }
};


static ngx_command_t  ngx_http_var_commands[] = {

    { ngx_string("var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_var_create_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_var_create_loc_conf,          /* create location configuration */
    ngx_http_var_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_var_module = {
    NGX_MODULE_V1,
    &ngx_http_var_module_ctx,              /* module context */
    ngx_http_var_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_var_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


static char *
ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_var_conf_t *prev = parent;
    ngx_http_var_conf_t *conf = child;

    ngx_http_var_variable_t  *var;

    if (conf->vars == NULL) {
        conf->vars = prev->vars;

    } else if (prev->vars) {
        var = ngx_array_push_n(conf->vars, prev->vars->nelts);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(var, prev->vars->elts,
                   prev->vars->nelts * sizeof(ngx_http_var_variable_t));
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_conf_t         *vcf = conf;

    ngx_str_t                   *value;
    ngx_uint_t                   cur, last;
    ngx_str_t                    s;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   i;
    ngx_http_var_operator_e      op;
    ngx_uint_t                   ignore_case, args, min_args, max_args;
    ngx_http_complex_value_t    *filter;
    ngx_uint_t                   negative;

#if (NGX_PCRE)
    ngx_regex_compile_t          rc;
    u_char                       errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t                    regex;
    size_t                       regex_len;
#endif

    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len == 0 || value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: invalid variable name \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_strlow(value[1].data, value[1].data, value[1].len);
    value[1].len--;
    value[1].data++;

    ngx_strlow(value[2].data, value[2].data, value[2].len);

    op = NGX_HTTP_VAR_OP_UNKNOWN;
    for (i = 0; ngx_http_var_operators[i].name.len > 0; i++) {

        if (value[2].len == ngx_http_var_operators[i].name.len
            && ngx_strncmp(value[2].data,
                       ngx_http_var_operators[i].name.data, value[2].len) == 0)
        {
            op = ngx_http_var_operators[i].op;
            min_args = ngx_http_var_operators[i].min_args;
            max_args = ngx_http_var_operators[i].max_args;
            break;
        }
    }

    if (op == NGX_HTTP_VAR_OP_UNKNOWN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: unsupported operator \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    filter = NULL;
    negative = 0;
    if (cf->args->nelts > 3
        && (ngx_strncmp(value[last].data, "if=", 3) == 0
            || ngx_strncmp(value[last].data, "if!=", 4) == 0))
    {
        if (value[last].data[2] == '=') {
            s.len = value[last].len - 3;
            s.data = value[last].data + 3;
            negative = 0;

        } else {
            s.len = value[last].len - 4;
            s.data = value[last].data + 4;
            negative = 1;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &s;
        ccv.complex_value = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
        if (ccv.complex_value == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        filter = ccv.complex_value;
        args = cf->args->nelts - 4;
        last--;

    } else {
        args = cf->args->nelts - 3;
    }

    cur = 3;
    ignore_case = 0;
    if (cur <= last && value[cur].len == 2
        && value[cur].data[0] == '-' && value[cur].data[1] == 'i')
    {
        ignore_case = 1;
        args--;
        cur++;
    }

    if (args < min_args || args > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: invalid number of arguments "
                           "for operator \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (vcf->vars == NULL) {
        vcf->vars = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_http_var_variable_t));
        if (vcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_array_push(vcf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->name = value[1];
    var->operator = op;
    var->ignore_case = ignore_case;
    var->filter = filter;
    var->negative = negative;

#if (NGX_PCRE)

    if (op == NGX_HTTP_VAR_OP_IF_RE_MATCH
        || op == NGX_HTTP_VAR_OP_RE_CAPTURE
        || op == NGX_HTTP_VAR_OP_RE_SUB)
    {
        if (args < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http var: regex operators "
                               "requires at least 2 arguments");
            return NGX_CONF_ERROR;
        }

        args--;

        var->args = ngx_array_create(cf->pool, ngx_max(args, 1),
            sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        cv = ngx_array_push(var->args);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[cur];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        cur++;

        if (op == NGX_HTTP_VAR_OP_RE_SUB) {
            regex_len = value[cur].len + 2;
            regex.data = ngx_pnalloc(cf->pool, regex_len);
            if (regex.data == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(regex.data, value[cur].data, value[cur].len);
            ngx_memcpy(regex.data + value[cur].len, "()", 2);
            regex.len = regex_len;

        } else {
            regex = value[cur];
        }

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = regex;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ignore_case == 1) {
            rc.options = NGX_REGEX_CASELESS;
        }

        var->regex = ngx_http_regex_compile(cf, &rc);
        if (var->regex == NULL) {
            return NGX_CONF_ERROR;
        }

        cur++;

        if (op != NGX_HTTP_VAR_OP_IF_RE_MATCH) {
            if (args != 2) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http var: re_capture or re_sub "
                               "operators requires 3 arguments");
                return NGX_CONF_ERROR;
            }

            cv = ngx_array_push(var->args);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[cur];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

    } else {

#endif

        var->args = ngx_array_create(cf->pool, ngx_max(args, 1),
                                     sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < args; i++) {
            cv = ngx_array_push(var->args);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[cur + i];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

#if (NGX_PCRE)

    }

#endif

    v = ngx_http_add_variable(cf, &value[1],
                             NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler && v->get_handler != ngx_http_var_variable_handler) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "http var: variable \"%V\" already has a handler",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    var->index = ngx_http_get_variable_index(cf, &value[1]);
    v->data = (uintptr_t) &var->index;

    v->get_handler = ngx_http_var_variable_handler;

    return NGX_CONF_OK;
}


static ngx_http_var_ctx_t *
ngx_http_var_get_lock_ctx(ngx_http_request_t *r)
{
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_var_ctx_t  *ctx;

    /* attempt to get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx != NULL) {
        return ctx;
    }

    /* if the context does not exist, create and attach it to the request */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_var_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    /* initialize the variable lock array */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    ctx->locked_vars = ngx_pcalloc(r->pool,
        cmcf->variables.nelts * sizeof(ngx_uint_t));
    if (ctx->locked_vars == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_var_module);

    return ctx;
}


static ngx_int_t
ngx_http_variable_acquire_lock(ngx_http_request_t *r, ngx_int_t index)
{
    ngx_http_var_ctx_t       *ctx;

    /* get or create the context */
    ctx = ngx_http_var_get_lock_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* check if it is already locked */
    if (ctx->locked_vars[index] == 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http var: circular reference detected "
                      "for variable index %ui", index);
        return NGX_ERROR;
    }

    /* mark the variable as locked */
    ctx->locked_vars[index] = 1;

    return NGX_OK;
}


static void
ngx_http_variable_release_lock(ngx_http_request_t *r, ngx_int_t index)
{
    ngx_http_var_ctx_t       *ctx;

    /* get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx == NULL) {
        return;
    }

    /* clear the lock mark */
    ctx->locked_vars[index] = 0;
}


static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r, ngx_int_t index,
    ngx_http_var_conf_t *vcf, ngx_http_var_variable_t **var)
{
    ngx_http_var_variable_t    *vars;
    ngx_uint_t                  i;
    ngx_str_t                   val;

    vars = vcf->vars->elts;

    /* linear search */
    for (i = 0; i < vcf->vars->nelts; i++) {

        if (vars[i].index == index) {

            if (vars[i].filter) {

                if (ngx_http_complex_value(r, vars[i].filter, &val)
                        != NGX_OK)
                {
                    return NGX_ERROR;
                }

                if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {

                    if (!vars[i].negative) {
                        continue;
                    }

                } else {

                    if (vars[i].negative) {
                        continue;
                    }
                }
            }

            /* found the variable */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http var: variable \"%V\" definition found",
                           &vars[i].name);

            /* return the found variable */
            *var = &vars[i];

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* Expression evaluation function */
static ngx_int_t
ngx_http_var_evaluate_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_int_t  rc;

    /* acquire lock for variable to avoid loopback exception */
    if (ngx_http_variable_acquire_lock(r, var->index) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    switch (var->operator) {

    case NGX_HTTP_VAR_OP_AND:
        rc = ngx_http_var_exec_and(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_OR:
        rc = ngx_http_var_exec_or(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_NOT:
        rc = ngx_http_var_exec_not(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_EMPTY:
        rc = ngx_http_var_exec_if_empty(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_NOT_EMPTY:
        rc = ngx_http_var_exec_if_not_empty(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_IS_NUM:
        rc = ngx_http_var_exec_if_is_num(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_STR_EQ:
        rc = ngx_http_var_exec_if_str_eq(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_STR_NE:
        rc = ngx_http_var_exec_if_str_ne(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_STARTS_WITH:
        rc = ngx_http_var_exec_if_starts_with(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_ENDS_WITH:
        rc = ngx_http_var_exec_if_ends_with(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_FIND:
        rc = ngx_http_var_exec_if_find(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_STR_IN:
        rc = ngx_http_var_exec_if_str_in(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_COPY:
        rc = ngx_http_var_exec_copy(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LEN:
        rc = ngx_http_var_exec_len(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UPPER:
        rc = ngx_http_var_exec_upper(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LOWER:
        rc = ngx_http_var_exec_lower(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_TRIM:
        rc = ngx_http_var_exec_trim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LTRIM:
        rc = ngx_http_var_exec_ltrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RTRIM:
        rc = ngx_http_var_exec_rtrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REVERSE:
        rc = ngx_http_var_exec_reverse(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_FIND:
        rc = ngx_http_var_exec_find(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPEAT:
        rc = ngx_http_var_exec_repeat(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SUBSTR:
        rc = ngx_http_var_exec_substr(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPLACE:
        rc = ngx_http_var_exec_replace(r, v, var);
        break;

#if (NGX_PCRE)
    case NGX_HTTP_VAR_OP_IF_RE_MATCH:
        rc = ngx_http_var_exec_if_re_match(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_CAPTURE:
        rc = ngx_http_var_exec_re_capture(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_SUB:
        rc = ngx_http_var_exec_re_sub(r, v, var);
        break;
#endif

    case NGX_HTTP_VAR_OP_IF_EQ:
        rc = ngx_http_var_exec_if_eq(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_NE:
        rc = ngx_http_var_exec_if_ne(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_LT:
        rc = ngx_http_var_exec_if_lt(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_LE:
        rc = ngx_http_var_exec_if_le(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_GT:
        rc = ngx_http_var_exec_if_gt(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_GE:
        rc = ngx_http_var_exec_if_ge(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_RANGE:
        rc = ngx_http_var_exec_if_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_IN:
        rc = ngx_http_var_exec_if_in(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ABS:
        rc = ngx_http_var_exec_abs(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MAX:
        rc = ngx_http_var_exec_max(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MIN:
        rc = ngx_http_var_exec_min(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ADD:
        rc = ngx_http_var_exec_add(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SUB:
        rc = ngx_http_var_exec_sub(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MUL:
        rc = ngx_http_var_exec_mul(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_DIV:
        rc = ngx_http_var_exec_div(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MOD:
        rc = ngx_http_var_exec_mod(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ROUND:
        rc = ngx_http_var_exec_round(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_FLOOR:
        rc = ngx_http_var_exec_floor(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CEIL:
        rc = ngx_http_var_exec_ceil(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RAND:
        rc = ngx_http_var_exec_rand(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEXRAND:
        rc = ngx_http_var_exec_hexrand(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_ENCODE:
        rc = ngx_http_var_exec_hex_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_DEC_TO_HEX:
        rc = ngx_http_var_exec_dec_to_hex(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_TO_DEC:
        rc = ngx_http_var_exec_hex_to_dec(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_DECODE:
        rc = ngx_http_var_exec_hex_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI:
        rc = ngx_http_var_exec_escape_uri(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_ARGS:
        rc = ngx_http_var_exec_escape_args(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT:
        rc = ngx_http_var_exec_escape_uri_component(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_HTML:
        rc = ngx_http_var_exec_escape_html(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UNESCAPE_URI:
        rc = ngx_http_var_exec_unescape_uri(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64_ENCODE:
        rc = ngx_http_var_exec_base64_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64URL_ENCODE:
        rc = ngx_http_var_exec_base64url_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64_DECODE:
        rc = ngx_http_var_exec_base64_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64URL_DECODE:
        rc = ngx_http_var_exec_base64url_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CRC32:
        rc = ngx_http_var_exec_crc32(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MD5:
        rc = ngx_http_var_exec_md5(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA1:
        rc = ngx_http_var_exec_sha1(r, v, var);
        break;

#if (NGX_HTTP_SSL)
    case NGX_HTTP_VAR_OP_SHA224:
        rc = ngx_http_var_exec_sha224(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA256:
        rc = ngx_http_var_exec_sha256(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA384:
        rc = ngx_http_var_exec_sha384(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA512:
        rc = ngx_http_var_exec_sha512(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_MD5:
        rc = ngx_http_var_exec_hmac_md5(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA1:
        rc = ngx_http_var_exec_hmac_sha1(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA224:
        rc = ngx_http_var_exec_hmac_sha224(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA256:
        rc = ngx_http_var_exec_hmac_sha256(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA384:
        rc = ngx_http_var_exec_hmac_sha384(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA512:
        rc = ngx_http_var_exec_hmac_sha512(r, v, var);
        break;
#endif

    case NGX_HTTP_VAR_OP_IF_TIME_RANGE:
        rc = ngx_http_var_exec_if_time_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_GMT_TIME:
        rc = ngx_http_var_exec_gmt_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LOCAL_TIME:
        rc = ngx_http_var_exec_local_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UNIX_TIME:
        rc = ngx_http_var_exec_unix_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_IP_RANGE:
        rc = ngx_http_var_exec_if_ip_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_EXTRACT_PARAM:
        rc = ngx_http_var_exec_extract_param(r, v, var);
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http var: unknown operator");
        ngx_http_variable_release_lock(r, var->index);
        v->not_found = 1;
        return NGX_ERROR;
    }

    /* evaluation is complete, release the lock */
    ngx_http_variable_release_lock(r, var->index);

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http var: evaluated variable \"%V\", "
                   "length: %uz, value: \"%*s\"",
                   &var->name, v->len, v->len, v->data);

    return rc;
}


static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vcf;
    ngx_http_var_variable_t      *var;
    ngx_int_t                     index;
    ngx_int_t                     rc;

    vcf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);

    if (vcf == NULL || vcf->vars == NULL || vcf->vars->nelts == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http var: not variable defined");
        v->not_found = 1;
        return NGX_OK;
    }

    index = *(ngx_int_t *) data;

    /* Search */
    rc = ngx_http_var_find_variable(r, index, vcf, &var);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http var: evaluating the expression of variable \"%V\"",
                   &var->name);

    /* evaluate the variable expression */
    rc = ngx_http_var_evaluate_variable(r, v, var);

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_check_str_is_num(ngx_str_t val)
{
    ngx_str_t    val_abs;
    ngx_int_t    num;
    ngx_uint_t   decimal_places;
    ngx_uint_t   i;

    val_abs = val;
    decimal_places = 0;

    if (val_abs.len > 0 && val_abs.data[0] == '-') {
        val_abs.data++;
        val_abs.len--;
    }

    if (val_abs.len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < val_abs.len; i++) {

        if (val_abs.data[i] == '.') {
            decimal_places = val_abs.len - i - 1;
            break;
        }
    }

    if (decimal_places == 0) {
        num = ngx_atoi(val_abs.data, val_abs.len);

    } else {
        num = ngx_atofp(val_abs.data, val_abs.len, decimal_places);
    }

    if (num == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_auto_atoi(ngx_str_t val, ngx_int_t *int_val)
{
    ngx_int_t  is_negative;

    is_negative = 0;

    if (val.len == 0) {
        return NGX_ERROR;
    }

    if (val.data[0] == '-') {

        if (val.len == 1) {
            return NGX_ERROR;
        }

        *int_val = ngx_atoi(val.data + 1, val.len - 1);
        is_negative = 1;

    } else {
        *int_val = ngx_atoi(val.data, val.len);
    }

    if (*int_val == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (is_negative) {
        *int_val = -*int_val;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2)
{
    ngx_uint_t   decimal_places1, decimal_places2, max_decimal_places;
    ngx_uint_t   is_negative1, is_negative2;
    ngx_uint_t   i;

    decimal_places1 = 0;
    decimal_places2 = 0;
    is_negative1 = 0;
    is_negative2 = 0;

    if (val1.len == 0 || val2.len == 0) {
        return NGX_ERROR;
    }

    if (val1.data[0] == '-') {

        if (val1.len == 1) {
            return NGX_ERROR;
        }

        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.data[0] == '-') {

        if (val2.len == 1) {
            return NGX_ERROR;
        }

        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    for (i = 0; i < val1.len; i++) {

        if (val1.data[i] == '.') {
            decimal_places1 = val1.len - i - 1;
            break;
        }
    }

    for (i = 0; i < val2.len; i++) {

        if (val2.data[i] == '.') {
            decimal_places2 = val2.len - i - 1;
            break;
        }
    }

    max_decimal_places = ngx_max(decimal_places1, decimal_places2);

    if (max_decimal_places == 0) {
        *int_val1 = ngx_atoi(val1.data, val1.len);
        *int_val2 = ngx_atoi(val2.data, val2.len);

    } else {
        *int_val1 = ngx_atofp(val1.data, val1.len, max_decimal_places);
        *int_val2 = ngx_atofp(val2.data, val2.len, max_decimal_places);
    }

    if (*int_val1 == NGX_ERROR || *int_val2 == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        *int_val1 = -*int_val1;
    }

    if (is_negative2 == 1) {
        *int_val2 = -*int_val2;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_auto_atofp3(ngx_str_t val1, ngx_str_t val2, ngx_str_t val3,
    ngx_int_t *int_val1, ngx_int_t *int_val2, ngx_int_t *int_val3)
{
    ngx_uint_t  decimal_places1, decimal_places2, decimal_places3;
    ngx_uint_t  max_decimal_places;
    ngx_uint_t  is_negative1, is_negative2, is_negative3;
    ngx_uint_t  i;

    decimal_places1 = 0;
    decimal_places2 = 0;
    decimal_places3 = 0;
    is_negative1 = 0;
    is_negative2 = 0;
    is_negative3 = 0;

    if (val1.len == 0 || val2.len == 0 || val3.len == 0) {
        return NGX_ERROR;
    }

    if (val1.data[0] == '-') {

        if (val1.len == 1) {
            return NGX_ERROR;
        }

        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.data[0] == '-') {

        if (val2.len == 1) {
            return NGX_ERROR;
        }

        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (val3.data[0] == '-') {

        if (val3.len == 1) {
            return NGX_ERROR;
        }

        is_negative3 = 1;
        val3.data++;
        val3.len--;
    }

    for (i = 0; i < val1.len; i++) {

        if (val1.data[i] == '.') {
            decimal_places1 = val1.len - i - 1;
            break;
        }
    }

    for (i = 0; i < val2.len; i++) {

        if (val2.data[i] == '.') {
            decimal_places2 = val2.len - i - 1;
            break;
        }
    }

    for (i = 0; i < val3.len; i++) {

        if (val3.data[i] == '.') {
            decimal_places3 = val3.len - i - 1;
            break;
        }
    }


    max_decimal_places = ngx_max(decimal_places1, decimal_places2);
    max_decimal_places = ngx_max(max_decimal_places, decimal_places3);

    if (max_decimal_places == 0) {
        *int_val1 = ngx_atoi(val1.data, val1.len);
        *int_val2 = ngx_atoi(val2.data, val2.len);
        *int_val3 = ngx_atoi(val3.data, val3.len);

    } else {
        *int_val1 = ngx_atofp(val1.data, val1.len, max_decimal_places);
        *int_val2 = ngx_atofp(val2.data, val2.len, max_decimal_places);
        *int_val3 = ngx_atofp(val3.data, val3.len, max_decimal_places);
    }

    if (*int_val1 == NGX_ERROR || *int_val2 == NGX_ERROR
        || *int_val3 == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        *int_val1 = -*int_val1;
    }

    if (is_negative2 == 1) {
        *int_val2 = -*int_val2;
    }

    if (is_negative3 == 1) {
        *int_val3 = -*int_val3;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_parse_uint_range(ngx_str_t val,
    ngx_int_t *start, ngx_int_t *end)
{
    ngx_uint_t   i;
    ngx_str_t    val_start, val_end;

    if (val.len == 0) {
        return NGX_ERROR;
    }

    for (i = 1; i < val.len; i++) {

        if (val.data[i] == '-') {
            break;
        }
    }

    if (i == val.len) {
        *start = ngx_atoi(val.data, val.len);
        if (*start == NGX_ERROR) {
            return NGX_ERROR;
        }

        *end = *start;
        return NGX_OK;
    }

    val_start.data = val.data;
    val_start.len = i;
    val_end.data = val.data + i + 1;
    val_end.len = val.len - i - 1;

    if (val_end.len == 0) {
        return NGX_ERROR;
    }

    *start = ngx_atoi(val_start.data, val_start.len);
    if (*start == NGX_ERROR) {
        return NGX_ERROR;
    }

    *end = ngx_atoi(val_end.data, val_end.len);
    if (*end == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (*start > *end) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    ngx_uint_t type)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    src = val.data;

    escape = 2 * ngx_escape_uri(NULL, src, val.len, type);
    len = val.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    if (escape == 0) {
        ngx_memcpy(dst, src, val.len);

    } else {
        ngx_escape_uri(dst, src, val.len, type);
    }

    v->len = len;
    v->data = dst;

    return NGX_OK;
}


/*
 * same as ngx_strlcasestrn(), but case-sensitive.
 * ngx_http_var_utils_strlstrn() is intended to search for static substring
 * with known length in string until the argument last. The argument n
 * must be length of the second substring - 1.
 */
static u_char *
ngx_http_var_utils_strlstrn(u_char *s1, u_char *last, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    c2 = (ngx_uint_t) *s2++;

    last -= n;

    do {
        do {
            if (s1 >= last) {
                return NULL;
            }

            c1 = (ngx_uint_t) *s1++;

        } while (c1 != c2);

    } while (ngx_strncmp(s1, s2, n) != 0);

    return --s1;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_var_utils_sha(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    const EVP_MD *evp_md, size_t hash_len)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    EVP_MD_CTX                *md;
    u_char                     hash[EVP_MAX_MD_SIZE];

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, evp_md, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, val.data, val.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    if (EVP_DigestFinal_ex(md, hash, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    v->data = ngx_pnalloc(r->pool, hash_len * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash, hash_len);
    v->len = hash_len * 2;

    return NGX_OK;

failed:

    EVP_MD_CTX_destroy(md);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_var_utils_hmac(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    const EVP_MD *evp_md)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val_src, val_secret;
    unsigned int               md_len;
    unsigned char              md[EVP_MAX_MD_SIZE];

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val_src) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &val_secret) != NGX_OK) {
        return NGX_ERROR;
    }

    md_len = 0;

    HMAC(evp_md, val_secret.data, val_secret.len,
         val_src.data, val_src.len, md, &md_len);

    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, md_len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, &md, md_len);
    v->len = md_len;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_var_exec_and(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_uint_t                 i;
    ngx_str_t                  val;

    args = var->args->elts;

    for (i = 0; i < var->args->nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &val) != NGX_OK) {
            return NGX_ERROR;
        }

        if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
            v->len = 1;
            v->data = (u_char *) "0";
            return NGX_OK;
        }
    }

    v->len = 1;
    v->data = (u_char *) "1";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_or(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_uint_t                 i;
    ngx_str_t                  val;

    args = var->args->elts;

    for (i = 0; i < var->args->nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &val) != NGX_OK) {
            return NGX_ERROR;
        }

        if (val.len > 0 && (val.len != 1 || val.data[0] != '0')) {
            v->len = 1;
            v->data = (u_char *) "1";
            return NGX_OK;
        }
    }

    v->len = 1;
    v->data = (u_char *) "0";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_not(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;
    if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;
    if (val.len == 0) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_not_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;
    if (val.len == 0) {
        v->data = (u_char *) "0";

    } else {
        v->data = (u_char *) "1";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_is_num(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;
    if (ngx_http_var_utils_check_str_is_num(val) != NGX_OK) {
        v->data = (u_char *) "0";

    } else {
        v->data = (u_char *) "1";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_str_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    v->len = 1;

    if (val1.len != val2.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (val1.len == 0 && val2.len == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    if (var->ignore_case) {
        v->data = (ngx_strncasecmp(val1.data, val2.data, val1.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";

    } else {
        v->data = (ngx_strncmp(val1.data, val2.data, val1.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_str_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    if (ngx_http_var_exec_if_str_eq(r, v, var) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (v->data[0] == '0') ? (u_char *) "1" : (u_char *) "0";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_starts_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, prefix;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &prefix) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    if (prefix.len == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    if (prefix.len > val.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (var->ignore_case) {
        v->data = (ngx_strncasecmp(val.data, prefix.data, prefix.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";

    } else {
        v->data = (ngx_strncmp(val.data, prefix.data, prefix.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_ends_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, suffix;
    u_char                    *val_end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &suffix) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    if (suffix.len == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    if (suffix.len > val.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    val_end = val.data + val.len - suffix.len;

    if (var->ignore_case) {
        v->data = (ngx_strncasecmp(val_end, suffix.data, suffix.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";

    } else {
        v->data = (ngx_strncmp(val_end, suffix.data, suffix.len) == 0)
                  ? (u_char *) "1" : (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, sub;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &sub) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    if (sub.len == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    if (sub.len > val.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (var->ignore_case) {
        p = ngx_strlcasestrn(val.data, val.data + val.len,
                sub.data, sub.len - 1);

    } else {
        p = ngx_http_var_utils_strlstrn(val.data, val.data + val.len,
                sub.data, sub.len - 1);
    }

    v->data = (p != NULL) ? (u_char *) "1" : (u_char *) "0";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_str_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    for (i = 1; i < var->args->nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &val2) != NGX_OK) {
            return NGX_ERROR;
        }

        if (val1.len != val2.len) {
            continue;
        }

        if (var->ignore_case) {

            if (ngx_strncasecmp(val1.data, val2.data, val1.len) == 0) {
                v->data = (u_char *) "1";
                return NGX_OK;
            }

        } else if (ngx_strncmp(val1.data, val2.data, val1.len) == 0) {
            v->data = (u_char *) "1";
            return NGX_OK;
        }
    }

    v->data = (u_char *) "0";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uz", val.len) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_toupper(val.data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_tolower(val.data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    /* Trim left */
    while (start <= end && ngx_http_var_isspace(*start)) {
        start++;
    }

    /* Trim right */
    while (end >= start && ngx_http_var_isspace(*end)) {
        end--;
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    /* Trim left */
    while (start <= end && ngx_http_var_isspace(*start)) {
        start++;
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    /* Trim right */
    while (end >= start && ngx_http_var_isspace(*end)) {
        end--;
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p, *q;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    /* Reverse the string */
    p = v->data;
    q = val.data + val.len - 1;

    while (q >= val.data) {
        *p++ = *q--;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, sub;
    u_char                    *p, *found;
    ngx_int_t                  pos;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &sub) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Empty substring is found at position 1 */
    if (sub.len == 0) {
        pos = 1;
        goto covert_pos;
    }

    /* Non-empty substring not found in empty string */
    if (val.len == 0 || sub.len > val.len) {
        pos = 0;
        goto covert_pos;
    }

    /* Search for substring */
    if (var->ignore_case) {
        found = ngx_strlcasestrn(val.data, val.data + val.len,
                                 sub.data, sub.len - 1);

    } else {
        found = ngx_http_var_utils_strlstrn(val.data, val.data + val.len,
                                            sub.data, sub.len - 1);
    }

    if (found != NULL) {
        pos = (ngx_int_t) (found - val.data) + 1;

    } else {
        pos = 0;
    }

covert_pos:

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", pos) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, times_str;
    ngx_int_t                  times;
    u_char                    *p;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &times_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    times = ngx_atoi(times_str.data, times_str.len);
    if (times == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid repeat times \"%V\"", &times_str);
        return NGX_ERROR;
    }

    if (times == 0 || val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, val.len * times);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_uint_t) times; i++) {
        ngx_memcpy(p + i * val.len, val.data, val.len);
    }

    v->len = val.len * (ngx_uint_t) times;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, val_start, val_len;
    ngx_int_t                  start, len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val_start) != NGX_OK)
    {
        return NGX_ERROR;
    }

    start = ngx_atoi(val_start.data, val_start.len);
    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid start \"%V\" in substr", &val_start);
        return NGX_ERROR;
    }

    if ((ngx_uint_t) start >= val.len) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (var->args->nelts == 3
        && ngx_http_complex_value(r, &args[2], &val_len) == NGX_OK)
    {
        len = ngx_atoi(val_len.data, val_len.len);
        if (len == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid length \"%V\" in substr",
                          &val_len);
            return NGX_ERROR;
        }

        /* adjust len if it exceeds the remaining string length */
        if ((ngx_uint_t) (start + len) > val.len) {
            len = val.len - start;
        }

    } else {
        /* default len to the remaining string length */
        len = val.len - start;
    }

    v->len = len;
    v->data = val.data + start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, val_search, val_replace;
    u_char                    *p, *q;
    size_t                     count, new_len;
    ngx_uint_t                 i;
    ngx_int_t                  rc;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val_search) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &val_replace) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (val_search.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: search string is empty in replace");
        return NGX_ERROR;
    }

    /* count occurrences */
    count = 0;
    p = val.data;

    for (i = 0; i <= val.len - val_search.len; /* void */ ) {

        if (var->ignore_case) {
            rc = ngx_strncasecmp(p + i, val_search.data, val_search.len);

        } else {
            rc = ngx_strncmp(p + i, val_search.data, val_search.len);
        }

        if (rc == 0) {
            count++;
            i += val_search.len;

        } else {
            i++;
        }
    }

    /* no replacements needed */
    if (count == 0) {
        v->len = val.len;
        v->data = val.data;
        return NGX_OK;
    }

    /* calculate new length */
    new_len = val.len + count * (val_replace.len - val_search.len);

    if (new_len > NGX_MAX_SIZE_T_VALUE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: replacement result too large");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, new_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /* perform replacement */
    q = p;
    i = 0;

    while (i < val.len) {

        if (i <= val.len - val_search.len) {

            if (var->ignore_case) {
                rc = ngx_strncasecmp(val.data + i, val_search.data,
                                     val_search.len);

            } else {
                rc = ngx_strncmp(val.data + i, val_search.data,
                                 val_search.len);
            }

            if (rc == 0) {
                ngx_memcpy(q, val_replace.data, val_replace.len);
                q += val_replace.len;
                i += val_search.len;
                continue;
            }
        }

        *q++ = val.data[i++];
    }

    v->len = q - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_extract_param(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  name, val, separator, delimiter;
    u_char                    *p, *back, *last, sep, del;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &name) != NGX_OK) {
        return NGX_ERROR;
    }

    while (name.len && ngx_http_var_isspace(name.data[0])) {
        name.data++;
        name.len--;
    }

    while (name.len && ngx_http_var_isspace(name.data[name.len - 1])) {
        name.len--;
    }

    if (name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, &args[1], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    while (val.len && ngx_http_var_isspace(val.data[0])) {
        val.data++;
        val.len--;
    }

    while (val.len && ngx_http_var_isspace(val.data[val.len - 1]))
    {
        val.len--;
    }

    if (val.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (var->args->nelts > 2) {
        if (ngx_http_complex_value(r, &args[2], &separator) != NGX_OK) {
            return NGX_ERROR;
        }

        if (separator.len != 1) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid separator: \"%V\"",
                          &separator);
            ngx_str_set(&separator, "&");
        }

    } else {
        ngx_str_set(&separator, "&");
    }

    if (var->args->nelts == 4) {
        if (ngx_http_complex_value(r, &args[3], &delimiter) != NGX_OK) {
            return NGX_ERROR;
        }

        if (delimiter.len != 1) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid delimiter: \"%V\"",
                          &delimiter);
            ngx_str_set(&delimiter, "=");
        }

    } else {
        ngx_str_set(&delimiter, "=");
    }

    sep = separator.data[0];
    del = delimiter.data[0];

    p = val.data;
    last = p + val.len;

    for ( /* void */ ; p < last; p++) {

        /* we need separator after name, so drop one char from last */

        if (var->ignore_case) {
            p = ngx_strlcasestrn(p, last - 1, name.data, name.len - 1);

        } else {
            p = ngx_http_var_utils_strlstrn(p, last - 1, name.data, name.len - 1);
        }

        if (p == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (*(p + name.len) != del) {
            continue;
        }

        if (p > val.data) {
            back = p - 1;

            while (back > val.data && *back == ' ') {
                back--;
            }

            if (*back != sep) {
                continue;
            }
        }

        p += name.len + 1;

        back = ngx_strlchr(p, last, sep);

        if (back) {
            last = back;
        }

        while (p < last && *p == ' ') {
            p++;
        }

        while (last > p && *(last - 1) == ' ') {
            last--;
        }

        v->data = p;
        v->len = last - p;

        return NGX_OK;
    }

    v->not_found = 1;
    return NGX_OK;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_http_var_exec_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    val;
    ngx_int_t                    rc;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    rc = ngx_http_regex_exec(r, var->regex, &val);

    if (rc == NGX_OK) {
        v->data = (u_char *) "1";
        return NGX_OK;
    } 
    
    if (rc == NGX_DECLINED) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex match failed");
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_var_exec_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    val, assign_val;
    ngx_int_t                    rc;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_regex_exec(r, var->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex match failed");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &assign_val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = assign_val.len;
    v->data = assign_val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    val, replacement;
    ngx_int_t                    rc;
    u_char                      *p;
    ngx_uint_t                   start, end, len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_regex_exec(r, var->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = val.len;
        v->data = val.data;
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex substitution failed");
        return NGX_ERROR;
    }

    /* ensure captures are available */
    if (r->ncaptures < 2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: insufficient captures");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    start = r->captures[0];
    end = r->captures[1];

    len = start + replacement.len + (val.len - end);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    p = ngx_cpymem(p, val.data, start);
    p = ngx_cpymem(p, replacement.data, replacement.len);
    p = ngx_cpymem(p, val.data + end, val.len - end);

    v->len = p - v->data;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_var_exec_if_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_eq\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 == int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_ne\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 != int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_lt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_lt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 < int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_le(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_le\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 <= int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_gt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_gt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 > int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_ge(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_gt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (int_val1 >= int_val2) {
        v->data = (u_char *) "1";

    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, val_start, val_end;
    ngx_int_t                  fp_val, fp_start, fp_end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (var->args->nelts == 2) {
        /* 2-arg mode: if_range(num, upper) checks [0, upper] */
        if (ngx_http_complex_value(r, &args[1], &val_end) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_var_utils_auto_atofp(val, val_end, &fp_val, &fp_end)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: \"if_range\" failed to convert "
                          "values (2-arg mode: num, upper) to fixed point");
            return NGX_ERROR;
        }

        v->len = 1;
        v->data = (fp_val >= 0 && fp_val <= fp_end)
                  ? (u_char *) "1" : (u_char *) "0";
        return NGX_OK;
    }

    /* 3-arg mode: if_range(num, start, end) checks [start, end] */
    if (ngx_http_complex_value(r, &args[1], &val_start) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &val_end) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp3(val, val_start, val_end,
                                       &fp_val, &fp_start, &fp_end) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: \"if_range\" failed to convert "
                        "values (3-arg mode: num, start, end) to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (fp_val >= fp_start && fp_val <= fp_end)
              ? (u_char *) "1" : (u_char *) "0";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, val_cmp;
    ngx_int_t                  fp_val, fp_cmp;
    ngx_uint_t                 i, nelts;

    args = var->args->elts;
    nelts = var->args->nelts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 1; i < nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &val_cmp) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_var_utils_auto_atofp(val, val_cmp,
                                          &fp_val, &fp_cmp) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: \"if_in\" failed to convert "
                          "value at position %ui to fixed point", i);
            continue;
        }

        if (fp_val == fp_cmp) {
            v->len = 1;
            v->data = (u_char *) "1";
            return NGX_OK;
        }
    }

    v->len = 1;
    v->data = (u_char *) "0";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_abs(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_check_str_is_num(val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len > 0 && val.data[0] == '-') {
        val.data++;
        val.len--;
    }

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  fp_val1, fp_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &fp_val1, &fp_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"max\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (fp_val1 >= fp_val2) {
        v->len = val1.len;
        v->data = val1.data;

    } else {
        v->len = val2.len;
        v->data = val2.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  fp_val1, fp_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atofp(val1, val2, &fp_val1, &fp_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"min\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (fp_val1 <= fp_val2) {
        v->len = val1.len;
        v->data = val1.data;

    } else {
        v->len = val2.len;
        v->data = val2.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_add(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"add\" operator");
        return NGX_ERROR;
    }

    if (int_val2 > 0 && int_val1 > NGX_MAX_INT_T_VALUE - int_val2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: integer overflow in \"add\" operator");
        return NGX_ERROR;
    }

    if (int_val2 < 0 && int_val1 < -NGX_MAX_INT_T_VALUE - int_val2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: integer underflow in \"add\" operator");
        return NGX_ERROR;
    }

    result = int_val1 + int_val2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"sub\" operator");
        return NGX_ERROR;
    }

    if (int_val2 < 0 && int_val1 > NGX_MAX_INT_T_VALUE + int_val2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: integer overflow in \"sub\" operator");
        return NGX_ERROR;
    }

    if (int_val2 > 0 && int_val1 < -NGX_MAX_INT_T_VALUE + int_val2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: integer underflow in \"sub\" operator");
        return NGX_ERROR;
    }

    result = int_val1 - int_val2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_mul(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"mul\" operator");
        return NGX_ERROR;
    }

    /* Check for multiplication overflow */
    if (int_val1 > 0) {

        if (int_val2 > 0 && int_val1 > NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: integer overflow in \"mul\" operator");
            return NGX_ERROR;
        }

        if (int_val2 < 0 && int_val2 < -NGX_MAX_INT_T_VALUE / int_val1) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: integer underflow in \"mul\" operator");
            return NGX_ERROR;
        }

    } else if (int_val1 < 0) {

        if (int_val2 > 0 && int_val1 < -NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: integer underflow in \"mul\" operator");
            return NGX_ERROR;
        }

        if (int_val2 < 0 && int_val1 < NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: integer overflow in \"mul\" operator");
            return NGX_ERROR;
        }
    }

    result = int_val1 * int_val2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_div(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"div\" operator");
        return NGX_ERROR;
    }

    /* Check for division by zero */
    if (int_val2 == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: division by zero in \"div\" operator");
        return NGX_ERROR;
    }

    result = int_val1 / int_val2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_mod(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"mod\" operator");
        return NGX_ERROR;
    }

    /* Check for modulo by zero */
    if (int_val2 == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: modulo by zero in \"mod\" operator");
        return NGX_ERROR;
    }

    result = int_val1 % int_val2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_round(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, val_precision;
    ngx_int_t                  precision, i, decimal_point;
    u_char                    *num_data, *result, *p;
    size_t                     num_len, int_len, frac_len;
    ngx_int_t                  is_negative;
    u_char                    *int_part, *frac_part;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val_precision) != NGX_OK)
    {
        return NGX_ERROR;
    }

    precision = ngx_atoi(val_precision.data, val_precision.len);
    if (precision == NGX_ERROR || precision < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid precision value for "
                      "\"round\" operator");
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty input for \"round\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        int_len = num_len;
        int_part = num_data;
        frac_len = 0;
        frac_part = NULL;

    } else {

        if (decimal_point == (ngx_int_t) (num_len - 1)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: decimal point at the end of number");
            return NGX_ERROR;
        }

        int_len = decimal_point;
        int_part = num_data;
        frac_len = num_len - decimal_point - 1;
        frac_part = num_data + decimal_point + 1;
    }

    if (frac_len == (size_t) precision) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    /* truncate without rounding */
    if (frac_len > (size_t) precision && frac_part[precision] < '5') {
        v->data = val.data;
        v->len = (is_negative ? 1 : 0) + int_len
                 + (precision > 0 ? 1 + precision : 0);
        return NGX_OK;
    }

    /* pad with zeros */
    if (frac_len < (size_t) precision) {
        /* calculate how many characters to add */
        i = (decimal_point == -1)
            ? (1 + precision) : (precision - (ngx_int_t) frac_len);

        result = ngx_palloc(r->pool, val.len + i + 1);
        if (result == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(result, val.data, val.len);

        if (decimal_point == -1) {
            *p++ = '.';
        }

        ngx_memset(p, '0', precision - frac_len);

        v->len = val.len + i;
        v->data = result;
        return NGX_OK;
    }

    /* need to round up */
    result = ngx_palloc(r->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    if (is_negative) {
        *p++ = '-';
    }

    p = ngx_cpymem(p, int_part, int_len);

    if (precision > 0) {
        *p++ = '.';
        p = ngx_cpymem(p, frac_part, precision);
    }

    /* remember the end position */
    i = p - result;

    /* apply carry from right to left */
    p--;
    while (p > result) {
        if (*p == '.' || *p == '-') {
            p--;
            continue;
        }

        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' */
    if (is_negative) {
        /* for negative: copy '-' to reserved byte, insert '1' after */
        result[0] = result[1];  /* copy '-' */
        result[1] = '1';
        v->data = result;
        v->len = i;

    } else {
        /* for positive: use reserved byte */
        result[0] = '1';
        v->data = result;
        v->len = i;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_floor(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  i, decimal_point;
    u_char                    *num_data, *result, *p;
    size_t                     num_len, int_len, frac_len;
    ngx_int_t                  is_negative;
    u_char                    *int_part, *frac_part;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty input for \"floor\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    if (decimal_point == (ngx_int_t) (num_len - 1)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: decimal point at the end of number");
        return NGX_ERROR;
    }

    int_len = decimal_point;
    int_part = num_data;
    frac_len = num_len - decimal_point - 1;
    frac_part = num_data + decimal_point + 1;

    /* positive number: truncate decimal part */
    if (!is_negative) {
        v->data = val.data;
        v->len = int_len;
        return NGX_OK;
    }

    /* check if fractional part is all zeros */
    for (i = 0; i < (ngx_int_t) frac_len; i++) {
        if (frac_part[i] != '0') {
            break;
        }
    }

    /* negative with zero fraction: truncate decimal part */
    if (i == (ngx_int_t) frac_len) {
        v->data = val.data;
        v->len = 1 + int_len;
        return NGX_OK;
    }

    /* negative with non-zero fraction: subtract 1 from absolute value */
    result = ngx_palloc(r->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    *p++ = '-';
    p = ngx_cpymem(p, int_part, int_len);

    /* remember the end position */
    i = p - result;

    /* add 1 to absolute value (subtract 1 from negative number) */
    p--;
    while (p > result + 1) {
        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' after '-' */
    result[0] = result[1];  /* copy '-' */
    result[1] = '1';
    v->data = result;
    v->len = i;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_ceil(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  i, decimal_point;
    u_char                    *num_data, *result, *p;
    size_t                     num_len, int_len, frac_len;
    ngx_int_t                  is_negative;
    u_char                    *int_part, *frac_part;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty input for \"ceil\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        int_len = num_len;
        int_part = num_data;
        frac_len = 0;
        frac_part = NULL;

    } else {

        if (decimal_point == (ngx_int_t) (num_len - 1)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: decimal point at the end of number");
            return NGX_ERROR;
        }

        int_len = decimal_point;
        int_part = num_data;
        frac_len = num_len - decimal_point - 1;
        frac_part = num_data + decimal_point + 1;
    }

    /* no fractional part: return as-is */
    if (frac_len == 0) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    /* negative number: truncate decimal part */
    if (is_negative) {
        v->data = val.data;
        v->len = 1 + int_len;
        return NGX_OK;
    }

    /* check if fractional part is all zeros */
    for (i = 0; i < (ngx_int_t) frac_len; i++) {
        if (frac_part[i] != '0') {
            break;
        }
    }

    /* positive with zero fraction: truncate decimal part */
    if (i == (ngx_int_t) frac_len) {
        v->data = val.data;
        v->len = int_len;
        return NGX_OK;
    }

    /* positive with non-zero fraction: add 1 to absolute value */
    result = ngx_palloc(r->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    p = ngx_cpymem(p, int_part, int_len);

    /* remember the end position */
    i = p - result;

    /* add 1 */
    p--;
    while (p > result) {
        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' */
    result[0] = '1';
    v->data = result;
    v->len = i;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  s;
    ngx_int_t                  start, end, result;
    u_char                    *p;

    if (var->args->nelts == 0) {
        p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%ui", ngx_random()) - p;
        v->data = p;
        
        return NGX_OK;
    }

    args = var->args->elts;

    /* Compute the start and end values */
    if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
        return NGX_ERROR;
    }

    if (s.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty argument for \"rand\"");
        return NGX_ERROR;
    }

    start = ngx_atoi(s.data, s.len);

    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid start value for \"rand\"");
        return NGX_ERROR;
    }

    if (var->args->nelts == 2) {

        if (ngx_http_complex_value(r, &args[1], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (s.len == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: empty argument for \"rand\"");
            return NGX_ERROR;
        }

        end = ngx_atoi(s.data, s.len);

        if (end == NGX_ERROR || start > end) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: invalid end value for \"rand\"");
            return NGX_ERROR;
        }

    } else {
        end = start;
        start = 0;
    }

    if (start == end) {
        v->len = 1;
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    /* Generate a random number between start and end (inclusive) */
    result = start + (ngx_random() % (end - start + 1));

    /* Allocate memory for the result string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_hexrand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    u_char                    *p;
    ngx_str_t                  s;
    ngx_int_t                  n;

#if (NGX_OPENSSL)
    u_char                     random_bytes[16];
#endif

    if (var->args->nelts == 0) {
        n = 32;

    } else {
        args = var->args->elts;

        if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (s.len == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: empty argument for \"hexrand\"");
            return NGX_ERROR;
        }

        n = ngx_atoi(s.data, s.len);
        if (n == NGX_ERROR || n <= 0 || n > 32) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid length value for \"hexrand\"");
            return NGX_ERROR;
        }
    }

    p = ngx_pnalloc(r->pool, 32);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = (size_t) n;
    v->data = p;

#if (NGX_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        ngx_hex_dump(p, random_bytes, 16);
        return NGX_OK;
    }

    ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    ngx_sprintf(p, "%08xD%08xD%08xD%08xD",
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->len = val.len << 1;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, val.data, val.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p;
    ngx_int_t                  n;
    size_t                     i;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len % 2 != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"hex_decode\" requires even-length string");
        return NGX_ERROR;
    }

    p = val.data;
    len = val.len >> 1;

    v->data = ngx_palloc(r->pool, len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid value in \"hex_decode\"");
            return NGX_ERROR;
        }

        p += 2;
        v->data[i] = (u_char) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_dec_to_hex(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  dec;
    u_char                    *p;
    ngx_flag_t                 is_negative;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty input for \"dec_to_hex\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    dec = ngx_atoi(val.data, val.len);
    if (dec == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid decimal value for \"dec_to_hex\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%xi", dec) - p;

    } else {
        v->len = ngx_sprintf(p, "%xi", dec) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_hex_to_dec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  dec;
    u_char                    *p;
    ngx_flag_t                 is_negative;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: empty input for \"hex_to_dec\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    dec = ngx_hextoi(val.data, val.len);
    if (dec == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid hex value for \"hex_to_dec\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%i", dec) - p;

    } else {
        v->len = ngx_sprintf(p, "%i", dec) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_escape_uri(r, v, var, NGX_ESCAPE_URI);
}


static ngx_int_t
ngx_http_var_exec_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_escape_uri(r, v, var, NGX_ESCAPE_ARGS);
}


static ngx_int_t
ngx_http_var_exec_escape_uri_component(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_escape_uri(r, v, var, NGX_ESCAPE_URI_COMPONENT);
}


static ngx_int_t
ngx_http_var_exec_escape_html(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_escape_uri(r, v, var, NGX_ESCAPE_HTML);
}


static ngx_int_t
ngx_http_var_exec_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *src, *dst, *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, val.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    src = val.data;
    dst = p;

    ngx_unescape_uri(&dst, &src, val.len, NGX_UNESCAPE_URI);

    v->data = p;
    v->len = dst - p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_encoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&dst, &val);

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64url_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_encoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64url(&dst, &val);

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_decoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&dst, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to decode base64 string");
        return NGX_ERROR;
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64url_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_decoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&dst, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to decode base64url string");
        return NGX_ERROR;
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_crc32(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 crc;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len < 64) {
        crc = ngx_crc32_short(val.data, val.len);

    } else {
        crc = ngx_crc32_long(val.data, val.len);
    }

    p = ngx_pnalloc(r->pool, 8 + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                     hash[16];
    ngx_md5_t                  md5;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, 16 * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(hash, &md5);

    ngx_hex_dump(v->data, hash, 16);
    v->len = 16 * 2;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                     hash[20];
    ngx_sha1_t                 sha1;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, 20 * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, val.data, val.len);
    ngx_sha1_final(hash, &sha1);

    ngx_hex_dump(v->data, hash, 20);
    v->len = 20 * 2;

    return NGX_OK;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_var_exec_sha224(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_sha(r, v, var, EVP_sha224(), 28);
}


static ngx_int_t
ngx_http_var_exec_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_sha(r, v, var, EVP_sha256(), 32);
}


static ngx_int_t
ngx_http_var_exec_sha384(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_sha(r, v, var, EVP_sha384(), 48);
}


static ngx_int_t
ngx_http_var_exec_sha512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_sha(r, v, var, EVP_sha512(), 64);
}


static ngx_int_t
ngx_http_var_exec_hmac_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_md5());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_sha1());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha224(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_sha224());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_sha256());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha384(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_sha384());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_hmac(r, v, var, EVP_sha512());
}

#endif


static ngx_int_t
ngx_http_var_exec_if_time_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  s;
    ngx_int_t                  year_start, year_end;
    ngx_int_t                  month_start, month_end;
    ngx_int_t                  day_start, day_end;
    ngx_int_t                  wday_start, wday_end;
    ngx_int_t                  hour_start, hour_end;
    ngx_int_t                  min_start, min_end;
    ngx_int_t                  sec_start, sec_end;
    ngx_int_t                  tz_offset;
    ngx_uint_t                 i, j;
    time_t                     raw_time;
    struct tm                  tm;

    args = var->args->elts;

    year_start = -1;
    year_end = -1;
    month_start = -1;
    month_end = -1;
    day_start = -1;
    day_end = -1;
    wday_start = -1;
    wday_end = -1;
    hour_start = -1;
    hour_end = -1;
    min_start = -1;
    min_end = -1;
    sec_start = -1;
    sec_end = -1;
    tz_offset = 0;

    for (i = 0; i < var->args->nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncmp(s.data, "year=", 5) == 0) {

            s.len = s.len - 5;
            s.data = s.data + 5;

            if (ngx_http_var_utils_parse_uint_range(s, &year_start, &year_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid year range value");
                return NGX_ERROR;
            }

            if (year_start < 1970 || year_end < year_start) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid year range value");
                return NGX_ERROR;
            }

            year_start = year_start - 1900;
            year_end = year_end - 1900;

            continue;
        } 
        
        if (ngx_strncmp(s.data, "month=", 6) == 0) {

            s.len = s.len - 6;
            s.data = s.data + 6;

            if (ngx_http_var_utils_parse_uint_range(s, &month_start,
                                                    &month_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid month range value");
                return NGX_ERROR;
            }

            if (month_start < 1 || month_start > 12
                || month_end < month_start || month_end > 12)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid month range value");
                return NGX_ERROR;
            }

            month_start--;
            month_end--;

            continue;
        }

        if (ngx_strncmp(s.data, "day=", 4) == 0) {

            s.len = s.len - 4;
            s.data = s.data + 4;

            if (ngx_http_var_utils_parse_uint_range(s, &day_start, &day_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid day range value");
                return NGX_ERROR;
            }

            if (day_start < 1 || day_start > 31
                || day_end < day_start || day_end > 31)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid day range value");
                return NGX_ERROR;
            }

            continue;
        }
        
        if (ngx_strncmp(s.data, "wday=", 5) == 0) {

            s.len = s.len - 5;
            s.data = s.data + 5;

            if (ngx_http_var_utils_parse_uint_range(s, &wday_start, &wday_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid wday range value");
                return NGX_ERROR;
            }

            if (wday_start < 0 || wday_start > 6
                || wday_end < wday_start || wday_end > 6)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid wday range value");
                return NGX_ERROR;
            }

            continue;
        }
        
        if (ngx_strncmp(s.data, "hour=", 5) == 0) {

            s.len = s.len - 5;
            s.data = s.data + 5;

            if (ngx_http_var_utils_parse_uint_range(s, &hour_start, &hour_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid hour range value");
                return NGX_ERROR;
            }

            if (hour_start < 0 || hour_start > 23
                || hour_end < hour_start || hour_end > 23)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid hour range value");
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(s.data, "min=", 4) == 0) {

            s.len = s.len - 4;
            s.data = s.data + 4;

            if (ngx_http_var_utils_parse_uint_range(s, &min_start, &min_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid minute range value");
                return NGX_ERROR;
            }

            if (min_start < 0 || min_start > 59
                || min_end < min_start || min_end > 59)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid minute range value");
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(s.data, "sec=", 4) == 0) {

            s.len = s.len - 4;
            s.data = s.data + 4;

            if (ngx_http_var_utils_parse_uint_range(s, &sec_start, &sec_end)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid second range value");
                return NGX_ERROR;
            }

            if (sec_start < 0 || sec_start > 59
                || sec_end < sec_start || sec_end > 59)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid second range value");
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(s.data, "timezone=", 9) == 0) {

            if (var->args->nelts == 1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: at least one time range "
                              "args must be present");
                return NGX_ERROR;
            }

            s.len = s.len - 9;
            s.data = s.data + 9;

            if (ngx_strncasecmp(s.data, "gmt", 3) != 0) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid timezone format");
                return NGX_ERROR;
            }

            s.len = s.len - 3;
            s.data = s.data + 3;

            if (s.len == 0) {
                tz_offset = 0;
                continue;
            }

            if (s.len != 5 || (s.data[0] != '+' && s.data[0] != '-')) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid timezone format");
                return NGX_ERROR;
            }

            for (j = 1; j < s.len; j++) {

                if (s.data[j] < '0' || s.data[j] > '9') {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            }

            tz_offset = (s.data[1] - '0') * 10 * 60 * 60;
            tz_offset += (s.data[2] - '0') * 60 * 60;
            tz_offset += (s.data[3] - '0') * 10 * 60;
            tz_offset += (s.data[4] - '0') * 60;

            if (s.data[0] == '-') {
                tz_offset = -tz_offset;
            }

            continue;
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid parameter \"%V\"", &s);

        return NGX_ERROR;
    }

    /* get current time */
    raw_time = ngx_time() + (time_t) tz_offset;

    ngx_libc_gmtime(raw_time, &tm);

    /* check year */
    if (year_start != -1
        && (tm.tm_year < year_start || tm.tm_year > year_end))
    {
        goto range_miss;
    }

    /* check month */
    if (month_start != -1
        && (tm.tm_mon < month_start || tm.tm_mon > month_end))
    {
        goto range_miss;
    }

    if (day_start != -1 && (tm.tm_mday < day_start || tm.tm_mday > day_end)) {
        goto range_miss;
    }

    /* check weekday */
    if (wday_start != -1
        && (tm.tm_wday < wday_start || tm.tm_wday > wday_end))
    {
        goto range_miss;
    }

    /* check hour */
    if (hour_start != -1
        && (tm.tm_hour < hour_start || tm.tm_hour > hour_end))
    {
        goto range_miss;
    }

    /* check minute */
    if (min_start != -1 && (tm.tm_min < min_start || tm.tm_min > min_end)) {
        goto range_miss;
    }

    /* check second */
    if (sec_start != -1 && (tm.tm_sec < sec_start || tm.tm_sec > sec_end)) {
        goto range_miss;
    }

    v->len = 1;
    v->data = (u_char *) "1";

    return NGX_OK;

range_miss:

    v->len = 1;
    v->data = (u_char *) "0";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_gmt_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  s;
    time_t                     ts;
    u_char                    *p;
    struct tm                  tm;
    char                       buf[2048];

    args = var->args->elts;

    if (var->args->nelts == 1) {

        if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(s.data, s.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &s) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (s.len == 9 && ngx_strncmp(s.data, "http_time", 9) == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (s.len == 11 && ngx_strncmp(s.data, "cookie_time", 11) == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Thu, 18-Nov-10 11:27:35 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_cookie_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (s.len >= sizeof(buf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: time format too long");
        return NGX_ERROR;
    }

    if (s.len == sizeof("%s") - 1 && s.data[0] == '%' && s.data[1] == 's') {
        v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;
        return NGX_OK;
    }

    ngx_memcpy(buf, s.data, s.len);
    buf[s.len] = '\0';

    ngx_libc_gmtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), buf, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_local_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  s;
    time_t                     ts;
    u_char                    *p;
    struct tm                  tm;
    char                       buf[2048];

    args = var->args->elts;

    if (var->args->nelts == 1) {

        if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_http_complex_value(r, &args[0], &s) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(s.data, s.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &s) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (s.len >= sizeof(buf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: date format too long");
        return NGX_ERROR;
    }

    if (s.len == sizeof("%s") - 1 && s.data[0] == '%' && s.data[1] == 's') {
        v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;

        return NGX_OK;
    }

    ngx_memcpy(buf, s.data, s.len);
    buf[s.len] = '\0';

    ngx_libc_localtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), buf, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_unix_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, timefmt, tz;
    ngx_tm_t                   tm;
    time_t                     ts;
    ngx_int_t                  tz_offset;
    u_char                    *p;
    ngx_uint_t                 i;
    char                       buf[2048];

    args = var->args->elts;

    if (var->args->nelts == 0) {
        ts = ngx_time();
        goto set_unix_time;
    }

    if (var->args->nelts == 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: illegal number of parameters");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &timefmt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (timefmt.len == 9 && ngx_strncmp(timefmt.data, "http_time", 9) == 0) {
        ts = ngx_parse_http_time(val.data, val.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: failed to parse http_time");
            return NGX_ERROR;
        }

        goto set_unix_time;
    }

    tz_offset = 0;

    if (var->args->nelts == 3) {

        if (ngx_http_complex_value(r, &args[2], &tz) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncasecmp(tz.data, "gmt", 3) != 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid timezone format");
            return NGX_ERROR;
        }

        tz.len = tz.len - 3;
        tz.data = tz.data + 3;

        if (tz.len != 0) {

            if (tz.len != 5 || (tz.data[0] != '+' && tz.data[0] != '-')) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid timezone format");
                return NGX_ERROR;
            }

            for (i = 1; i < tz.len; i++) {

                if (tz.data[i] < '0' || tz.data[i] > '9') {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "http var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            }

            tz_offset = (tz.data[1] - '0') * 10 * 60 * 60;
            tz_offset += (tz.data[2] - '0') * 60 * 60;
            tz_offset += (tz.data[3] - '0') * 10 * 60;
            tz_offset += (tz.data[4] - '0') * 60;

            if (tz.data[0] == '-') {
                tz_offset = -tz_offset;
            }
        }
    }

    if (timefmt.len >= sizeof(buf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: date format too long");
        return NGX_ERROR;
    }

    ngx_memcpy(buf, timefmt.data, timefmt.len);
    buf[timefmt.len] = '\0';

    ngx_memzero(&tm, sizeof(ngx_tm_t));

    if (strptime((char *) val.data, buf, &tm) == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to parse date string");
        return NGX_ERROR;
    }

    ts = timegm(&tm) - tz_offset;

set_unix_time:

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", ts) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_ip_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  ip_str, range_str;
    ngx_uint_t                 i;
    ngx_cidr_t                 cidr;
    in_addr_t                  ipv4_addr, start_addr, end_addr;
    u_char                    *p;

#if (NGX_HAVE_INET6)
    u_char                     ipv6_buf[16];
    struct in6_addr            ipv6_addr;
    ngx_uint_t                 n;
#endif

    args = var->args->elts;

    /* Get the IP address to match */
    if (ngx_http_complex_value(r, &args[0], &ip_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Parse IPv4 address */
    ipv4_addr = ngx_inet_addr(ip_str.data, ip_str.len);
    if (ipv4_addr == INADDR_NONE) {

#if (NGX_HAVE_INET6)
        /* If it's not IPv4, try to parse as IPv6 */
        if (ngx_inet6_addr(ip_str.data, ip_str.len, ipv6_buf) == NGX_OK) {
            /* IPv6 address */
            ngx_memcpy(&ipv6_addr, ipv6_buf,
                       sizeof(struct in6_addr));

            /* Check if the IPv6 address is an IPv4-mapped address */
            if (IN6_IS_ADDR_V4MAPPED(&ipv6_addr)) {
                /* Extract the IPv4 address from the mapped IPv6 address */
                ipv4_addr = ipv6_addr.s6_addr[12] << 24;
                ipv4_addr += ipv6_addr.s6_addr[13] << 16;
                ipv4_addr += ipv6_addr.s6_addr[14] << 8;
                ipv4_addr += ipv6_addr.s6_addr[15];
                ipv4_addr = htonl(ipv4_addr);
            }

            goto ip_range_match_handler;
        }
#endif

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid IP address: \"%V\"", &ip_str);
        return NGX_ERROR;

    }

ip_range_match_handler:

    /* Iterate over all IP ranges to find a match */
    for (i = 1; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &range_str) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Try to parse the range as a CIDR */
        if (ngx_ptocidr(&range_str, &cidr) == NGX_OK) {
            /* Check if the IP is within the CIDR range */
            if (cidr.family == AF_INET) {
                if (ipv4_addr != INADDR_NONE && 
                    (ipv4_addr & cidr.u.in.mask) == cidr.u.in.addr) {
                    v->len = 1;
                    v->data = (u_char *) "1";
                    return NGX_OK;
                }

#if (NGX_HAVE_INET6)
            } else if (cidr.family == AF_INET6) {
                for (n = 0; n < 16; n++) {
                    if ((ipv6_addr.s6_addr[n] & cidr.u.in6.mask.s6_addr[n])
                        != cidr.u.in6.addr.s6_addr[n]) {
                        continue;
                    }
                }

                v->len = 1;
                v->data = (u_char *) "1";
                return NGX_OK;
#endif

            }

        } else if (ipv4_addr != INADDR_NONE) {
            p = ngx_strlchr(range_str.data,
                range_str.data + range_str.len, '-');
            if (p == NULL) {
                goto invalid_ip_range;
            }

            start_addr = ngx_inet_addr(range_str.data,
                p - range_str.data);

            p++;

            end_addr = ngx_inet_addr(p,
                range_str.data + range_str.len - p);

            if (start_addr == INADDR_NONE || end_addr == INADDR_NONE) {
                goto invalid_ip_range;
            }

            start_addr = ntohl(start_addr);
            end_addr = ntohl(end_addr);
            ipv4_addr = ntohl(ipv4_addr);

            /* Check if IPv4 address is in the given range */
            if (ipv4_addr >= start_addr && ipv4_addr <= end_addr) {
                v->len = 1;
                v->data = (u_char *) "1";
                return NGX_OK;
            }

        } else {
            goto invalid_ip_range;
        }
    }

    /* No matching range found */
    v->len = 1;
    v->data = (u_char *) "0";

    return NGX_OK;

invalid_ip_range:
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "http var: invalid IP or CIDR range: \"%V\"",
                    &range_str);
    return NGX_ERROR;
}
