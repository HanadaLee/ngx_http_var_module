
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

typedef enum {
    NGX_HTTP_VAR_OP_AND = 0,
    NGX_HTTP_VAR_OP_OR,
    NGX_HTTP_VAR_OP_NOT,

    NGX_HTTP_VAR_OP_IF_EMPTY,
    NGX_HTTP_VAR_OP_IF_NOT_EMPTY,
    NGX_HTTP_VAR_OP_IF_IS_NUM,
    NGX_HTTP_VAR_OP_IF_STR_EQ,
    NGX_HTTP_VAR_OP_IF_HAS_PREFIX,
    NGX_HTTP_VAR_OP_IF_HAS_SUFFIX,
    NGX_HTTP_VAR_OP_IF_FIND,

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

#if (NGX_PCRE)
    NGX_HTTP_VAR_OP_IF_RE_MATCH,

    NGX_HTTP_VAR_OP_RE_CAPTURE,
    NGX_HTTP_VAR_OP_RE_SUB,
    NGX_HTTP_VAR_OP_RE_GSUB,
#endif

    NGX_HTTP_VAR_OP_IF_EQ,
    NGX_HTTP_VAR_OP_IF_NE,
    NGX_HTTP_VAR_OP_IF_LT,
    NGX_HTTP_VAR_OP_IF_LE,
    NGX_HTTP_VAR_OP_IF_GT,
    NGX_HTTP_VAR_OP_IF_GE,
    NGX_HTTP_VAR_OP_IF_RANGE,

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
    NGX_HTTP_VAR_OP_RAND_RANGE,

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

    NGX_HTTP_VAR_OP_CRC32_SHORT,
    NGX_HTTP_VAR_OP_CRC32_LONG,
    NGX_HTTP_VAR_OP_MD5SUM,
    NGX_HTTP_VAR_OP_SHA1SUM,

#if (NGX_HTTP_SSL)
    NGX_HTTP_VAR_OP_SHA256SUM,
    NGX_HTTP_VAR_OP_SHA384SUM,
    NGX_HTTP_VAR_OP_SHA512SUM,
    NGX_HTTP_VAR_OP_HMAC_SHA1,
    NGX_HTTP_VAR_OP_HMAC_SHA256,
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
    ngx_http_var_operator_e        operator;    /* operator type */
    ngx_uint_t                     ignore_case; /* ignore case sensitivity */
    ngx_array_t                   *args;        /* operator extra args */
    ngx_http_complex_value_t      *filter;
    ngx_uint_t                     negative;

#if (NGX_PCRE)
    ngx_http_regex_t              *regex;       /* compiled regex */
#endif
} ngx_http_var_variable_t;


typedef struct {
    ngx_uint_t                    *locked_vars;
    ngx_uint_t                     count;
} ngx_http_var_ctx_t;


typedef struct {
    ngx_str_t                      name;        /* operator string */
    ngx_http_var_operator_e        op;          /* operator enum */
    ngx_uint_t                     ignore_case; /* ignore case for regex */
    ngx_uint_t                     min_args;    /* min number of arguments */
    ngx_uint_t                     max_args;    /* max number of arguments */
} ngx_http_var_operator_enum_t;


static ngx_http_var_operator_enum_t ngx_http_var_operators[] = {
    { ngx_string("and"),             NGX_HTTP_VAR_OP_AND,            0, 2, 9 },
    { ngx_string("or"),              NGX_HTTP_VAR_OP_OR,             0, 2, 9 },
    { ngx_string("not"),             NGX_HTTP_VAR_OP_NOT,            0, 1, 1 },

    { ngx_string("if_empty"),        NGX_HTTP_VAR_OP_IF_EMPTY,       0, 1, 1 },
    { ngx_string("if_not_empty"),    NGX_HTTP_VAR_OP_IF_NOT_EMPTY,   0, 1, 1 },
    { ngx_string("if_is_num"),       NGX_HTTP_VAR_OP_IF_IS_NUM,      0, 1, 1 },
    { ngx_string("if_str_eq"),       NGX_HTTP_VAR_OP_IF_STR_EQ,      0, 2, 2 },
    { ngx_string("if_str_eq_i"),     NGX_HTTP_VAR_OP_IF_STR_EQ,      1, 2, 2 },
    { ngx_string("if_has_prefix"),   NGX_HTTP_VAR_OP_IF_HAS_PREFIX,  0, 2, 2 },
    { ngx_string("if_has_prefix_i"), NGX_HTTP_VAR_OP_IF_HAS_PREFIX,  1, 2, 2 },
    { ngx_string("if_has_suffix"),   NGX_HTTP_VAR_OP_IF_HAS_SUFFIX,  0, 2, 2 },
    { ngx_string("if_has_suffix_i"), NGX_HTTP_VAR_OP_IF_HAS_SUFFIX,  1, 2, 2 },
    { ngx_string("if_find"),         NGX_HTTP_VAR_OP_IF_FIND,        0, 2, 2 },
    { ngx_string("if_find_i"),       NGX_HTTP_VAR_OP_IF_FIND,        1, 2, 2 },

    { ngx_string("copy"),            NGX_HTTP_VAR_OP_COPY,           0, 1, 1 },
    { ngx_string("len"),             NGX_HTTP_VAR_OP_LEN,            0, 1, 1 },
    { ngx_string("upper"),           NGX_HTTP_VAR_OP_UPPER,          0, 1, 1 },
    { ngx_string("lower"),           NGX_HTTP_VAR_OP_LOWER,          0, 1, 1 },
    { ngx_string("trim"),            NGX_HTTP_VAR_OP_TRIM,           0, 1, 1 },
    { ngx_string("ltrim"),           NGX_HTTP_VAR_OP_LTRIM,          0, 1, 1 },
    { ngx_string("rtrim"),           NGX_HTTP_VAR_OP_RTRIM,          0, 1, 1 },
    { ngx_string("reverse"),         NGX_HTTP_VAR_OP_REVERSE,        0, 1, 1 },
    { ngx_string("find"),            NGX_HTTP_VAR_OP_FIND,           0, 2, 2 },
    { ngx_string("repeat"),          NGX_HTTP_VAR_OP_REPEAT,         0, 2, 2 },
    { ngx_string("substr"),          NGX_HTTP_VAR_OP_SUBSTR,         0, 3, 3 },
    { ngx_string("replace"),         NGX_HTTP_VAR_OP_REPLACE,        0, 3, 3 },

#if (NGX_PCRE)
    { ngx_string("if_re_match"),     NGX_HTTP_VAR_OP_IF_RE_MATCH,    0, 2, 2 },

    { ngx_string("if_re_match_i"),   NGX_HTTP_VAR_OP_IF_RE_MATCH,    1, 2, 2 },

    { ngx_string("re_capture"),      NGX_HTTP_VAR_OP_RE_CAPTURE,     0, 3, 3 },
    { ngx_string("re_capture_i"),    NGX_HTTP_VAR_OP_RE_CAPTURE,     1, 3, 3 },
    { ngx_string("re_sub"),          NGX_HTTP_VAR_OP_RE_SUB,         0, 3, 3 },
    { ngx_string("re_sub_i"),        NGX_HTTP_VAR_OP_RE_SUB,         1, 3, 3 },
    { ngx_string("re_gsub"),         NGX_HTTP_VAR_OP_RE_GSUB,        0, 3, 3 },
    { ngx_string("re_gsub_i"),       NGX_HTTP_VAR_OP_RE_GSUB,        1, 3, 3 },
#endif

    { ngx_string("if_eq"),           NGX_HTTP_VAR_OP_IF_EQ,          0, 2, 2 },
    { ngx_string("if_ne"),           NGX_HTTP_VAR_OP_IF_NE,          0, 2, 2 },
    { ngx_string("if_lt"),           NGX_HTTP_VAR_OP_IF_LT,          0, 2, 2 },
    { ngx_string("if_le"),           NGX_HTTP_VAR_OP_IF_LE,          0, 2, 2 },
    { ngx_string("if_gt"),           NGX_HTTP_VAR_OP_IF_GE,          0, 2, 2 },
    { ngx_string("if_ge"),           NGX_HTTP_VAR_OP_IF_GE,          0, 2, 2 },
    { ngx_string("if_range"),        NGX_HTTP_VAR_OP_IF_RANGE,       0, 2, 2 },

    { ngx_string("abs"),             NGX_HTTP_VAR_OP_ABS,            0, 1, 1 },
    { ngx_string("max"),             NGX_HTTP_VAR_OP_MAX,            0, 2, 2 },
    { ngx_string("min"),             NGX_HTTP_VAR_OP_MIN,            0, 2, 2 },
    { ngx_string("add"),             NGX_HTTP_VAR_OP_ADD,            0, 2, 2 },
    { ngx_string("sub"),             NGX_HTTP_VAR_OP_SUB,            0, 2, 2 },
    { ngx_string("mul"),             NGX_HTTP_VAR_OP_MUL,            0, 2, 2 },
    { ngx_string("div"),             NGX_HTTP_VAR_OP_DIV,            0, 2, 2 },
    { ngx_string("mod"),             NGX_HTTP_VAR_OP_MOD,            0, 2, 2 },
    { ngx_string("round"),           NGX_HTTP_VAR_OP_ROUND,          0, 2, 2 },
    { ngx_string("floor"),           NGX_HTTP_VAR_OP_FLOOR,          0, 1, 1 },
    { ngx_string("ceil"),            NGX_HTTP_VAR_OP_CEIL,           0, 1, 1 },
    { ngx_string("rand"),            NGX_HTTP_VAR_OP_RAND,           0, 0, 0 },
    { ngx_string("rand_range"),      NGX_HTTP_VAR_OP_RAND_RANGE,     0, 1, 1 },

    { ngx_string("hex_encode"),      NGX_HTTP_VAR_OP_HEX_ENCODE,     0, 1, 1 },
    { ngx_string("hex_decode"),      NGX_HTTP_VAR_OP_HEX_DECODE,     0, 1, 1 },
    { ngx_string("dec_to_hex"),      NGX_HTTP_VAR_OP_DEC_TO_HEX,     0, 1, 1 },
    { ngx_string("hex_to_dec"),      NGX_HTTP_VAR_OP_HEX_TO_DEC,     0, 1, 1 },
    { ngx_string("escape_uri"),      NGX_HTTP_VAR_OP_ESCAPE_URI,     0, 1, 1 },
    { ngx_string("escape_args"),     NGX_HTTP_VAR_OP_ESCAPE_ARGS,    0, 1, 1 },
    { ngx_string("escape_uri_component"),
                               NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT, 0, 1, 1 },
    { ngx_string("escape_html"),     NGX_HTTP_VAR_OP_ESCAPE_HTML,    0, 1, 1 },
    { ngx_string("unescape_uri"),    NGX_HTTP_VAR_OP_UNESCAPE_URI,   0, 1, 1 },
    { ngx_string("base64_encode"),   NGX_HTTP_VAR_OP_BASE64_ENCODE,  0, 1, 1 },
    { ngx_string("base64url_encode"),
                                   NGX_HTTP_VAR_OP_BASE64URL_ENCODE, 0, 1, 1 },
    { ngx_string("base64_decode"),   NGX_HTTP_VAR_OP_BASE64_DECODE,  0, 1, 1 },
    { ngx_string("base64url_decode"),
                                   NGX_HTTP_VAR_OP_BASE64URL_DECODE, 0, 1, 1 },

    { ngx_string("crc32_short"),     NGX_HTTP_VAR_OP_CRC32_SHORT,    0, 1, 1 },
    { ngx_string("crc32_long"),      NGX_HTTP_VAR_OP_CRC32_LONG,     0, 1, 1 },
    { ngx_string("md5sum"),          NGX_HTTP_VAR_OP_MD5SUM,         0, 1, 1 },
    { ngx_string("sha1sum"),         NGX_HTTP_VAR_OP_SHA1SUM,        0, 1, 1 },

#if (NGX_HTTP_SSL)
    { ngx_string("sha256sum"),       NGX_HTTP_VAR_OP_SHA256SUM,      0, 1, 1 },
    { ngx_string("sha384sum"),       NGX_HTTP_VAR_OP_SHA384SUM,      0, 1, 1 },
    { ngx_string("sha512sum"),       NGX_HTTP_VAR_OP_SHA512SUM,      0, 1, 1 },
    { ngx_string("hmac_sha1"),       NGX_HTTP_VAR_OP_HMAC_SHA1,      0, 2, 2 },
    { ngx_string("hmac_sha256"),     NGX_HTTP_VAR_OP_HMAC_SHA256,    0, 2, 2 },
#endif

    { ngx_string("if_time_range"),   NGX_HTTP_VAR_OP_IF_TIME_RANGE,  0, 1, 8 },

    { ngx_string("gmt_time"),        NGX_HTTP_VAR_OP_GMT_TIME,       0, 1, 2 },
    { ngx_string("local_time"),      NGX_HTTP_VAR_OP_LOCAL_TIME,     0, 1, 2 },
    { ngx_string("unix_time"),       NGX_HTTP_VAR_OP_UNIX_TIME,      0, 0, 3 },

    { ngx_string("if_ip_range"),     NGX_HTTP_VAR_OP_IF_IP_RANGE,    0, 2, 9 },

    { ngx_null_string,               NGX_HTTP_VAR_OP_UNKNOWN,        0, 0, 0 }
};


static void *ngx_http_var_create_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_var_create_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_http_var_ctx_t *ngx_http_var_get_lock_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_variable_acquire_lock(ngx_http_request_t *r,
    ngx_str_t *var_name);
static void ngx_http_variable_release_lock(ngx_http_request_t *r,
    ngx_str_t *var_name);
static ngx_int_t ngx_http_var_find_variable(ngx_http_request_t *r,
    ngx_str_t *var_name, ngx_http_var_conf_t *vconf,
    ngx_http_var_variable_t **found_var);
static ngx_int_t ngx_http_var_evaluate_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_var_check_str_is_num(ngx_str_t num_str);
static ngx_int_t ngx_http_var_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2);
static ngx_int_t ngx_http_var_auto_atofp3(ngx_str_t val1, ngx_str_t val2,
    ngx_str_t val3, ngx_int_t *int_val1,
    ngx_int_t *int_val2, ngx_int_t *int_val3);
static ngx_int_t ngx_http_var_parse_int_range(ngx_str_t str,
    ngx_int_t *start, ngx_int_t *end);

static ngx_int_t ngx_http_var_do_and(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_or(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_not(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_if_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_not_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_is_num(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_str_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_has_prefix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_has_suffix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_do_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_re_gsub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

static ngx_int_t ngx_http_var_do_if_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_lt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_le(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_gt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_ge(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_if_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_abs(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_add(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_mul(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_div(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_mod(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_round(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_floor(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_ceil(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_rand_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_dec_to_hex(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_hex_to_dec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_escape_uri_component(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_escape_html(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_base64_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_base64url_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_base64_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_base64url_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_crc32_short(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_crc32_long(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_md5sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_sha1sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_var_do_sha256sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_sha384sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_sha512sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_hmac_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_hmac_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

static ngx_int_t ngx_http_var_do_if_time_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_gmt_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_local_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_do_unix_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_do_if_ip_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);


static ngx_command_t ngx_http_var_commands[] = {

    { ngx_string("var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_var_create_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_var_create_conf,              /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_var_create_conf,              /* create server configuration */
    ngx_http_var_merge_conf,               /* merge server configuration */

    ngx_http_var_create_conf,              /* create location configuration */
    ngx_http_var_merge_conf                /* merge location configuration */
};


ngx_module_t ngx_http_var_module = {
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


/* Create configuration */
static void *
ngx_http_var_create_conf(ngx_conf_t *cf)
{
    ngx_http_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


/* Merge configurations */
static char *
ngx_http_var_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_var_conf_t *prev = parent;
    ngx_http_var_conf_t *conf = child;

    if (conf->vars == NULL) {
        conf->vars = prev->vars;
    } else if (prev->vars) {
        ngx_http_var_variable_t *var;

        var = ngx_array_push_n(conf->vars, prev->vars->nelts);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(var, prev->vars->elts,
            prev->vars->nelts * sizeof(ngx_http_var_variable_t));
    }

    return NGX_CONF_OK;
}


/* "var" directive handler */
static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_conf_t         *vconf = conf;
    ngx_str_t                   *value;
    ngx_uint_t                   last;
    ngx_str_t                    var_name, operator_str, s;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_uint_t                   i, n;
    ngx_http_var_operator_e      op = NGX_HTTP_VAR_OP_UNKNOWN;
    ngx_uint_t                   ignore_case = 0, min_args = 0, max_args = 0;
    ngx_uint_t                   args_count;
    size_t                       operators_count;
    ngx_http_complex_value_t    *filter = NULL;
    ngx_uint_t                   negative = 0;

    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_var: invalid number of arguments "
                           "in \"var\" directive");
        return NGX_CONF_ERROR;
    }

    var_name = value[1];
    operator_str = value[2];

    if (var_name.len == 0 || var_name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_var: invalid variable name \"%V\"",
                           &var_name);
        return NGX_CONF_ERROR;
    }

    /* Remove the leading '$' from variable name */
    var_name.len--;
    var_name.data++;

    /* Map operator string to enum and get argument counts */
    operators_count = sizeof(ngx_http_var_operators) / 
                  sizeof(ngx_http_var_operator_enum_t);
    for (i = 0; i < operators_count; i++) {
        if (operator_str.len == ngx_http_var_operators[i].name.len
            && ngx_strncmp(operator_str.data,
                ngx_http_var_operators[i].name.data, operator_str.len) == 0)
        {
            op = ngx_http_var_operators[i].op;
            ignore_case = ngx_http_var_operators[i].ignore_case;
            min_args = ngx_http_var_operators[i].min_args;
            max_args = ngx_http_var_operators[i].max_args;
            break;
        }
    }

    if (op == NGX_HTTP_VAR_OP_UNKNOWN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_var: unsupported operator \"%V\"",
                           &operator_str);
        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[last].data, "if=", 3) == 0
        || ngx_strncmp(value[last].data, "if!=", 4) == 0)
    {
        if (ngx_strncmp(value[last].data, "if=", 3) == 0) {
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
        args_count = cf->args->nelts - 4;

    } else {
        args_count = cf->args->nelts - 3;
    }

    if (args_count < min_args || args_count > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_var: invalid number of arguments "
                           "for operator \"%V\"", &operator_str);
        return NGX_CONF_ERROR;
    }

    /* Initialize vars array if necessary */
    if (vconf->vars == NULL) {
        vconf->vars = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_var_variable_t));
        if (vconf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Add variable definition */
    var = ngx_array_push(vconf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->name.len = var_name.len;
    var->name.data = ngx_pstrdup(cf->pool, &var_name);
    if (var->name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    var->operator = op;
    var->ignore_case = ignore_case;
    var->filter = filter;
    var->negative = negative;

#if (NGX_PCRE)
    if (op == NGX_HTTP_VAR_OP_IF_RE_MATCH
        || op == NGX_HTTP_VAR_OP_RE_CAPTURE
        || op == NGX_HTTP_VAR_OP_RE_SUB
        || op == NGX_HTTP_VAR_OP_RE_GSUB)
    {
        /* src_string, regex_pattern */
        if (args_count < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http_var: regex operators "
                               "requires at least 2 arguments");
            return NGX_CONF_ERROR;
        }
        args_count--;

        /* Compile src_string (complex variable) */
        var->args = ngx_array_create(cf->pool, args_count ? args_count : 1,
            sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_http_complex_value_t *cv_src;
        cv_src = ngx_array_push(var->args);
        if (cv_src == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[3];
        ccv.complex_value = cv_src;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Compile assign_value */
        if (op != NGX_HTTP_VAR_OP_IF_RE_MATCH) {
            if (args_count != 2) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http_var: regex operators "
                               "requires 3 arguments");
                return NGX_CONF_ERROR;
            }

            ngx_http_complex_value_t *cv_value;
            cv_value = ngx_array_push(var->args);
            if (cv_value == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[5];
            ccv.complex_value = cv_value;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        /* Compile regex pattern */
        ngx_regex_compile_t        rc;
        u_char                     errstr[NGX_MAX_CONF_ERRSTR];
        ngx_str_t                  regex_pattern;
        size_t                     pattern_len;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        if (op == NGX_HTTP_VAR_OP_RE_SUB || op == NGX_HTTP_VAR_OP_RE_GSUB) {
            pattern_len = value[4].len + 2;
            regex_pattern.data = ngx_pnalloc(cf->pool, pattern_len);
            if (regex_pattern.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(regex_pattern.data, value[4].data, value[4].len);
            ngx_memcpy(regex_pattern.data + value[4].len, "()", 2);
            regex_pattern.len = pattern_len;

        } else {
            regex_pattern = value[4];
        }

        rc.pattern = regex_pattern;
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

    } else {
#endif

        /* Initialize args array */
        var->args = ngx_array_create(cf->pool, args_count ? args_count : 1,
                                    sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        /* Compile all arguments */
        for (n = 0; n < args_count; n++) {
            ngx_http_complex_value_t   *cv;

            cv = ngx_array_push(var->args);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[3 + n];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

#if (NGX_PCRE)
    }
#endif

    /* Add variable to Nginx */
    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    v = ngx_http_add_variable(cf, &var_name, flags);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL
        || v->get_handler == ngx_http_var_variable_handler)
    {
        v->get_handler = ngx_http_var_variable_handler;

        /* Store variable name */
        ngx_str_t *var_name_copy;

        var_name_copy = ngx_palloc(cf->pool, sizeof(ngx_str_t));
        if (var_name_copy == NULL) {
            return NGX_CONF_ERROR;
        }

        var_name_copy->len = var_name.len;
        var_name_copy->data = ngx_pstrdup(cf->pool, &var_name);
        if (var_name_copy->data == NULL) {
            return NGX_CONF_ERROR;
        }

        v->data = (uintptr_t) var_name_copy;
    } else {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "http_var: variable \"$%V\" already has a handler",
                           &var_name);
    }

    return NGX_CONF_OK;
}


static ngx_http_var_ctx_t *
ngx_http_var_get_lock_ctx(ngx_http_request_t *r)
{
    ngx_http_var_ctx_t  *ctx;

    /* Attempt to get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);

    /* If the context does not exist, create and attach it to the request */
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_var_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to create lock context");
            return NULL;
        }

        /* Initialize the variable lock array, assuming a maximum number of variables */
        ctx->count = 32;  /* Set initial variable count to 32 */
        ctx->locked_vars = ngx_pcalloc(r->pool,
            ctx->count * sizeof(ngx_uint_t));
        if (ctx->locked_vars == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_var_module);
    }

    return ctx;
}


static ngx_int_t
ngx_http_variable_acquire_lock(ngx_http_request_t *r, ngx_str_t *var_name)
{
    ngx_http_var_ctx_t       *ctx;
    ngx_uint_t                var_index;
    ngx_uint_t                new_count;
    ngx_uint_t               *new_locked_vars;

    /* Get or create the context */
    ctx = ngx_http_var_get_lock_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR; /* Context creation failed */
    }

    /* Calculate the variable index */
    var_index = ngx_hash_key(var_name->data, var_name->len) % ctx->count;

    /* Dynamically expand the lock array */
    if (var_index >= ctx->count) {
        new_count = ctx->count * 2;
        new_locked_vars = ngx_pcalloc(r->pool,
            new_count * sizeof(ngx_uint_t));
        if (new_locked_vars == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http_var: failed to expand lock array");
            return NGX_ERROR;
        }
        ngx_memcpy(new_locked_vars, ctx->locked_vars,
            ctx->count * sizeof(ngx_uint_t));
        ctx->locked_vars = new_locked_vars;
        ctx->count = new_count;
    }

    /* Check if it is already locked */
    if (ctx->locked_vars[var_index]) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: circular reference detected "
                      "for variable: \"$%V\"", var_name);
        return NGX_ERROR;
    }

    /* Mark the variable as locked */
    ctx->locked_vars[var_index] = 1;

    return NGX_OK;
}


static void
ngx_http_variable_release_lock(ngx_http_request_t *r, ngx_str_t *var_name)
{
    ngx_http_var_ctx_t       *ctx;
    ngx_uint_t                var_index;

    /* Get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx == NULL) {
        return;
    }

    /* Calculate the variable index */
    var_index = ngx_hash_key(var_name->data, var_name->len) % ctx->count;

    /* Clear the lock mark */
    ctx->locked_vars[var_index] = 0;
}


/* Helper function to find variable */
static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r,
    ngx_str_t *var_name, ngx_http_var_conf_t *vconf,
    ngx_http_var_variable_t **found_var)
{
    ngx_http_var_variable_t      *vars;
    ngx_uint_t                    i;

    if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http_var: not variable defined in conf");
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_var: searching variable \"$%V\" in conf",
                   var_name);

    vars = vconf->vars->elts;

    /* Linear search */
    for (i = 0; i < vconf->vars->nelts; i++) {
        if (vars[i].name.len == var_name->len
            && ngx_strncmp(vars[i].name.data,
                   var_name->data, var_name->len) == 0) {
            if (vars[i].filter) {
                ngx_str_t  val;
                if (ngx_http_complex_value(r, vars[i].filter, &val)
                        != NGX_OK) {
                    return NGX_ERROR;
                }

                if ((val.len == 0 || (val.len == 1 && val.data[0] == '0'))) {
                    if (!vars[i].negative) {
                        /* Skip this variable due to filter*/
                        continue;
                    }
                } else {
                    if (vars[i].negative) {
                        /* Skip this variable due to negative filter*/
                        continue;
                    }
                }
            }

            /* Found the variable */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http_var: variable \"$%V\" found in conf",
                           var_name);

            /* Return the found variable */
            *found_var = &vars[i];

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
    ngx_int_t rc;

    /* Acquire lock for variable to avoid loopback exception */
    if (ngx_http_variable_acquire_lock(r, &var->name) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    switch (var->operator) {
    case NGX_HTTP_VAR_OP_AND:
        rc = ngx_http_var_do_and(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_OR:
        rc = ngx_http_var_do_or(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_NOT:
        rc = ngx_http_var_do_not(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_EMPTY:
        rc = ngx_http_var_do_if_empty(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_NOT_EMPTY:
        rc = ngx_http_var_do_if_not_empty(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_IS_NUM:
        rc = ngx_http_var_do_if_is_num(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_STR_EQ:
        rc = ngx_http_var_do_if_str_eq(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_HAS_PREFIX:
        rc = ngx_http_var_do_if_has_prefix(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_HAS_SUFFIX:
        rc = ngx_http_var_do_if_has_suffix(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_FIND:
        rc = ngx_http_var_do_if_find(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_COPY:
        rc = ngx_http_var_do_copy(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LEN:
        rc = ngx_http_var_do_len(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UPPER:
        rc = ngx_http_var_do_upper(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LOWER:
        rc = ngx_http_var_do_lower(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_TRIM:
        rc = ngx_http_var_do_trim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LTRIM:
        rc = ngx_http_var_do_ltrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RTRIM:
        rc = ngx_http_var_do_rtrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REVERSE:
        rc = ngx_http_var_do_reverse(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_FIND:
        rc = ngx_http_var_do_find(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPEAT:
        rc = ngx_http_var_do_repeat(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SUBSTR:
        rc = ngx_http_var_do_substr(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPLACE:
        rc = ngx_http_var_do_replace(r, v, var);
        break;

#if (NGX_PCRE)
    case NGX_HTTP_VAR_OP_IF_RE_MATCH:
        rc = ngx_http_var_do_if_re_match(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_CAPTURE:
        rc = ngx_http_var_do_re_capture(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_SUB:
        rc = ngx_http_var_do_re_sub(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_GSUB:
        rc = ngx_http_var_do_re_gsub(r, v, var);
        break;
#endif

    case NGX_HTTP_VAR_OP_IF_EQ:
        rc = ngx_http_var_do_if_eq(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_NE:
        rc = ngx_http_var_do_if_ne(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_LT:
        rc = ngx_http_var_do_if_lt(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_LE:
        rc = ngx_http_var_do_if_le(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_GT:
        rc = ngx_http_var_do_if_gt(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_GE:
        rc = ngx_http_var_do_if_ge(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_RANGE:
        rc = ngx_http_var_do_if_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ABS:
        rc = ngx_http_var_do_abs(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MAX:
        rc = ngx_http_var_do_max(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MIN:
        rc = ngx_http_var_do_min(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ADD:
        rc = ngx_http_var_do_add(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SUB:
        rc = ngx_http_var_do_sub(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MUL:
        rc = ngx_http_var_do_mul(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_DIV:
        rc = ngx_http_var_do_div(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MOD:
        rc = ngx_http_var_do_mod(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ROUND:
        rc = ngx_http_var_do_round(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_FLOOR:
        rc = ngx_http_var_do_floor(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CEIL:
        rc = ngx_http_var_do_ceil(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RAND:
        rc = ngx_http_var_do_rand(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RAND_RANGE:
        rc = ngx_http_var_do_rand_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_ENCODE:
        rc = ngx_http_var_do_hex_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_DEC_TO_HEX:
        rc = ngx_http_var_do_dec_to_hex(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_TO_DEC:
        rc = ngx_http_var_do_hex_to_dec(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_DECODE:
        rc = ngx_http_var_do_hex_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI:
        rc = ngx_http_var_do_escape_uri(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_ARGS:
        rc = ngx_http_var_do_escape_args(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT:
        rc = ngx_http_var_do_escape_uri_component(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_HTML:
        rc = ngx_http_var_do_escape_html(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UNESCAPE_URI:
        rc = ngx_http_var_do_unescape_uri(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64_ENCODE:
        rc = ngx_http_var_do_base64_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64URL_ENCODE:
        rc = ngx_http_var_do_base64url_encode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64_DECODE:
        rc = ngx_http_var_do_base64_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_BASE64URL_DECODE:
        rc = ngx_http_var_do_base64url_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CRC32_SHORT:
        rc = ngx_http_var_do_crc32_short(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CRC32_LONG:
        rc = ngx_http_var_do_crc32_long(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MD5SUM:
        rc = ngx_http_var_do_md5sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA1SUM:
        rc = ngx_http_var_do_sha1sum(r, v, var);
        break;

#if (NGX_HTTP_SSL)
    case NGX_HTTP_VAR_OP_SHA256SUM:
        rc = ngx_http_var_do_sha256sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA384SUM:
        rc = ngx_http_var_do_sha384sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA512SUM:
        rc = ngx_http_var_do_sha512sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA1:
        rc = ngx_http_var_do_hmac_sha1(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA256:
        rc = ngx_http_var_do_hmac_sha256(r, v, var);
        break;
#endif

    case NGX_HTTP_VAR_OP_IF_TIME_RANGE:
        rc = ngx_http_var_do_if_time_range(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_GMT_TIME:
        rc = ngx_http_var_do_gmt_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LOCAL_TIME:
        rc = ngx_http_var_do_local_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UNIX_TIME:
        rc = ngx_http_var_do_unix_time(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_IF_TIME_RANGE:
        rc = ngx_http_var_do_if_time_range(r, v, var);
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: unknown operator");
        ngx_http_variable_release_lock(r, &var->name);
        v->not_found = 1;
        return NGX_ERROR;
    }

    /* Evaluation is complete, release the lock */
    ngx_http_variable_release_lock(r, &var->name);

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_var: evaluated variable \"$%V\", "
                   "result length: %uz, value: \"%*s\"",
                   &var->name, v->len, v->len, v->data);

    return rc;
}


/* Variable handler */
static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vconf;
    ngx_str_t                     var_name;
    ngx_str_t                    *var_name_ptr;
    ngx_int_t                     rc;
    ngx_http_var_variable_t      *found_var = NULL;

    /* Get variable name from data */
    var_name_ptr = (ngx_str_t *) data;
    var_name.len = var_name_ptr->len;
    var_name.data = var_name_ptr->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_var: handling variable \"$%V\"", &var_name);

    /* Search in conf */
    vconf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Variable not found */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_var: variable \"$%V\" not found", &var_name);

    v->not_found = 1;
    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_var: evaluating the expression of variable \"$%V\"",
                   &var_name);

    /* Evaluate the variable expression */
    rc = ngx_http_var_evaluate_variable(r, v, found_var);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_check_str_is_num(ngx_str_t num_str)
{
    ngx_str_t  num_abs_str = num_str;
    ngx_int_t  num;
    ngx_uint_t decimal_places = 0;

    if (num_abs_str.len > 0 && num_abs_str.data[0] == '-') {
        num_abs_str.data++;
        num_abs_str.len--;
    }

    for (ngx_uint_t i = 0; i < num_abs_str.len; i++) {
        if (num_abs_str.data[i] == '.') {
            decimal_places = num_abs_str.len - i - 1;
            break;
        }
    }

    if (decimal_places == 0) {
        num = ngx_atoi(num_abs_str.data, num_abs_str.len);
    } else {
        num = ngx_atofp(num_abs_str.data, num_abs_str.len, decimal_places);
    }

    if (num == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2)
{
    ngx_uint_t decimal_places1 = 0, decimal_places2 = 0;

    for (ngx_uint_t i = 0; i < val1.len; i++) {
        if (val1.data[i] == '.') {
            decimal_places1 = val1.len - i - 1;
            break;
        }
    }

    for (ngx_uint_t i = 0; i < val2.len; i++) {
        if (val2.data[i] == '.') {
            decimal_places2 = val2.len - i - 1;
            break;
        }
    }

    ngx_uint_t max_decimal_places = (decimal_places1 > decimal_places2)
        ? decimal_places1 : decimal_places2;

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

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_auto_atofp3(ngx_str_t val1, ngx_str_t val2, ngx_str_t val3,
    ngx_int_t *int_val1, ngx_int_t *int_val2, ngx_int_t *int_val3)
{
    ngx_uint_t decimal_places1 = 0, decimal_places2 = 0, decimal_places3 = 0;

    for (ngx_uint_t i = 0; i < val1.len; i++) {
        if (val1.data[i] == '.') {
            decimal_places1 = val1.len - i - 1;
            break;
        }
    }

    for (ngx_uint_t i = 0; i < val2.len; i++) {
        if (val2.data[i] == '.') {
            decimal_places2 = val2.len - i - 1;
            break;
        }
    }

    for (ngx_uint_t i = 0; i < val3.len; i++) {
        if (val3.data[i] == '.') {
            decimal_places2 = val3.len - i - 1;
            break;
        }
    }

    ngx_uint_t max_decimal_places = decimal_places1;

    if (decimal_places2 > max_decimal_places) {
        max_decimal_places = decimal_places2;
    }

    if (decimal_places3 > max_decimal_places) {
        max_decimal_places = decimal_places3;
    }

    if (max_decimal_places == 0) {
        *int_val1 = ngx_atoi(val1.data, val1.len);
        *int_val2 = ngx_atoi(val2.data, val2.len);
        *int_val3 = ngx_atoi(val3.data, val3.len);
    } else {
        *int_val1 = ngx_atofp(val1.data, val1.len, max_decimal_places);
        *int_val2 = ngx_atofp(val2.data, val2.len, max_decimal_places);
        *int_val3 = ngx_atofp(val3.data, val3.len, max_decimal_places);
    }

    if (*int_val1 == NGX_ERROR
        || *int_val2 == NGX_ERROR
        || *int_val3 == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_parse_int_range(ngx_str_t str,
    ngx_int_t *start, ngx_int_t *end)
{
    ngx_uint_t i = 0;
    ngx_int_t temp_start = 0, temp_end = 0;
    ngx_int_t is_range = 0;

    while (i < str.len) {
        if (str.data[i] == '-') {
            is_range = 1;
            i++;
            break;
        }
        if (str.data[i] < '0' || str.data[i] > '9') {
            return NGX_ERROR;
        }
        temp_start = temp_start * 10 + (str.data[i] - '0');
        i++;
    }

    if (is_range) {
        while (i < str.len) {
            if (str.data[i] < '0' || str.data[i] > '9') {
                return NGX_ERROR;
            }
            temp_end = temp_end * 10 + (str.data[i] - '0');
            i++;
        }
    }

    *start = temp_start;
    *end = is_range ? temp_end : temp_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_and(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_uint_t                 i;
    ngx_str_t                  val;


    args = var->args->elts;

    for (i = 0; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: \"and\" failed to evaluate argument");
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
ngx_http_var_do_or(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_uint_t                 i;
    ngx_str_t                  val;

    args = var->args->elts;

    for (i = 0; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: \"or\" failed to evaluate argument");
            return NGX_ERROR;
        }

        if (!(val.len == 0 || (val.len == 1 && val.data[0] == '0'))) {
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
ngx_http_var_do_not(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"not\" failed to evaluate argument");
        return NGX_ERROR;
    }

    if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_empty\" failed to "
                      "evaluate argument");
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_not_empty(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_not_empty\" failed to "
                      "evaluate argument");
        return NGX_ERROR;
    }

    if (val.len > 0) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_is_num(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_is_num\" failed to "
                      "evaluate argument");
        return NGX_ERROR;
    }

    v->len = 1;

    if (ngx_http_var_check_str_is_num(val) != NGX_OK) {
        v->data = (u_char *) "0";
    } else {
        v->data = (u_char *) "1";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_str_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    if (val1.len != val2.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (var->ignore_case == 1) {
        if (ngx_strncasecmp(val1.data,
                val2.data, val1.len) == 0) {
            v->data = (u_char *) "1";
            return NGX_OK;
        }

    } else if (ngx_strncmp(val1.data,
                        val2.data, val1.len) == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    v->data = (u_char *) "0";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_has_prefix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  str, prefix;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_has_prefix / if_has_prefix_i\" "
                      "failed to evaluate the first argument");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &prefix) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_has_prefix / if_has_prefix_i\" "
                      "failed to evaluate the second argument");
        return NGX_ERROR;
    }

    v->len = 1;

    if (prefix.len > str.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (var->ignore_case == 1) {
        if (ngx_strncasecmp(str.data, prefix.data, prefix.len) == 0) {
            v->data = (u_char *) "1";
            return NGX_OK;
        }

    } else if (ngx_strncmp(str.data, prefix.data, prefix.len) == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    v->data = (u_char *) "0";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_has_suffix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  str, suffix;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_has_suffix / if_has_suffix_i\" "
                      "failed to evaluate the first argument");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &suffix) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_has_suffix / if_has_suffix_i\" "
                      "failed to evaluate the second argument");
        return NGX_ERROR;
    }

    v->len = 1;

    if (suffix.len > str.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    u_char *str_end = str.data + str.len - suffix.len;
    if (var->ignore_case == 1) {
        if (ngx_strncasecmp(str_end, suffix.data, suffix.len) == 0) {
            v->data = (u_char *) "1";
            return NGX_OK;
        }

    } else if (ngx_strncmp(str_end, suffix.data, suffix.len) == 0) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    v->data = (u_char *) "0";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  str, sub_str;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_find / if_find_i\" failed to "
                      "evaluate the first argument");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &sub_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_find / if_find_i\" failed to "
                      "evaluate the second argument");
        return NGX_ERROR;
    }

    if (var->ignore_case == 1) {
        p = ngx_strcasestrn(str.data, (char *)sub_str.data, sub_str.len - 1);
    } else {
        p = ngx_strstrn(str.data, (char *)sub_str.data, sub_str.len - 1);
    }
    v->len = 1;

    if (p != NULL) {
        v->data = (u_char *) "1";
    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute variable value");
        return NGX_ERROR;
    }

    v->len = val.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val.data, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *p;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for len operator");
        return NGX_ERROR;
    }

    /* Convert length to string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = src_str.len;
    v->len = ngx_sprintf(p, "%uz", len) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  value_str;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for upper operator");
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, value_str.data, v->len);

    /* Convert to uppercase */
    ngx_uint_t i;
    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_toupper(v->data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  value_str;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for lower operator");
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, value_str.data, v->len);

    /* Convert to lowercase */
    ngx_uint_t i;
    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_tolower(v->data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for trim operator");
        return NGX_ERROR;
    }

    start = src_str.data;
    end = src_str.data + src_str.len - 1;

    /* Trim left */
    while (start <= end && isspace((unsigned char)*start)) {
        start++;
    }

    /* Trim right */
    while (end >= start && isspace((unsigned char)*end)) {
        end--;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for ltrim operator");
        return NGX_ERROR;
    }

    start = src_str.data;
    end = src_str.data + src_str.len - 1;

    /* Trim left */
    while (start <= end && isspace((unsigned char)*start)) {
        start++;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for rtrim operator");
        return NGX_ERROR;
    }

    start = src_str.data;
    end = src_str.data + src_str.len - 1;

    /* Trim right */
    while (end >= start && isspace((unsigned char)*end)) {
        end--;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, reversed_str;
    u_char                    *p, *q;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for reverse operator");
        return NGX_ERROR;
    }

    reversed_str.len = src_str.len;
    reversed_str.data = ngx_pnalloc(r->pool, reversed_str.len);
    if (reversed_str.data == NULL) {
        return NGX_ERROR;
    }

    p = reversed_str.data;
    q = src_str.data + src_str.len - 1;

    for (; q >= src_str.data; q--) {
        *p++ = *q;
    }

    /* Set variable value */
    v->len = reversed_str.len;
    v->data = reversed_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, sub_str;
    u_char                    *p;
    ngx_int_t                  pos = 0;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &sub_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for find operator");
        return NGX_ERROR;
    }

    if (sub_str.len == 0 || src_str.len == 0) {
        /* If sub_str is empty or src_str is empty, return 0 */
        pos = 0;
    } else {
        p = ngx_strnstr(src_str.data, (char *)sub_str.data, src_str.len);
        if (p) {
            /* Position starts from 1 */
            pos = (ngx_int_t)(p - src_str.data) + 1;
        } else {
            pos = 0;
        }
    }

    /* Convert find to string */
    u_char *buf = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(buf, "%i", pos) - buf;
    v->data = buf;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, repeat_times_str;
    ngx_int_t                  times;
    size_t                     total_len;
    u_char                    *p;
    ngx_uint_t                 i;

    args = var->args->elts;

    /* Compute arguments */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &repeat_times_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for repeat operator");
        return NGX_ERROR;
    }

    /* Parse repeat times */
    times = ngx_atoi(repeat_times_str.data, repeat_times_str.len);
    if (times == NGX_ERROR || times < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid repeat times");
        return NGX_ERROR;
    }

    /* If times is zero, return an empty string */
    if (times == 0 || src_str.len == 0) {
        return NGX_ERROR;
    }

    /* Calculate total length */
    total_len = src_str.len * times;

    /* Allocate memory */
    p = ngx_pnalloc(r->pool, total_len);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for repeat result");
        return NGX_ERROR;
    }

    /* Fill the result with repeated strings */
    for (i = 0; i < (ngx_uint_t)times; i++) {
        ngx_memcpy(p + i * src_str.len, src_str.data, src_str.len);
    }

    /* Set variable value */
    v->len = total_len;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, start_str, len_str;
    ngx_int_t                  start, len;
    ngx_uint_t                 src_len;

    args = var->args->elts;

    /* Compute arguments */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &start_str) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &len_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for substr operator");
        return NGX_ERROR;
    }

    /* Parse start and length values */
    start = ngx_atoi(start_str.data, start_str.len);
    len = ngx_atoi(len_str.data, len_str.len);

    if (start == NGX_ERROR || len == NGX_ERROR || start < 0 || len < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid start or length in substr");
        return NGX_ERROR;
    }

    src_len = src_str.len;

    /* Handle the case where start is beyond the string length */
    if ((ngx_uint_t)start >= src_len) {
        return NGX_ERROR;
    } else {
        /* Adjust len if it exceeds the string length */
        if ((ngx_uint_t)(start + len) > src_len) {
            len = src_len - start;
        }

        /* Allocate memory for the substring */
        v->len = len;
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: memory allocation failed "
                          "for substr result");
            return NGX_ERROR;
        }
        ngx_memcpy(v->data, src_str.data + start, v->len);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, search_str, replace_str, result_str;
    u_char                    *p, *q;
    size_t                     count = 0, new_len;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &search_str) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &replace_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for replace operator");
        return NGX_ERROR;
    }

    if (search_str.len == 0) {
        /* Prevent infinite loop */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: search string is empty in replace");
        return NGX_ERROR;
    }

    /* Count occurrences */
    p = src_str.data;
    for (i = 0; i <= src_str.len - search_str.len;) {
        if (ngx_strncmp(p + i, search_str.data, search_str.len) == 0) {
            count++;
            i += search_str.len;
        } else {
            i++;
        }
    }

    /* No replacements needed, just return the original string */
    if (count == 0) {
        v->len = src_str.len;
        v->data = src_str.data;
        return NGX_OK;
    }

    /* Calculate new length */
    new_len = src_str.len + count * (replace_str.len - search_str.len);

    if (new_len > NGX_MAX_SIZE_T_VALUE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: replacement result too large");
        return NGX_ERROR;
    }

    result_str.data = ngx_pnalloc(r->pool, new_len);
    if (result_str.data == NULL) {
        return NGX_ERROR;
    }

    /* Perform replacement */
    p = src_str.data;
    q = result_str.data;
    i = 0;

    while (i < src_str.len) {
        if (i <= src_str.len - search_str.len
            && ngx_strncmp(p + i, search_str.data, search_str.len) == 0) {
            ngx_memcpy(q, replace_str.data, replace_str.len);
            q += replace_str.len;
            i += search_str.len;
        } else {
            *q++ = p[i++];
        }
    }

    result_str.len = q - result_str.data;

    /* Set variable value */
    v->len = result_str.len;
    v->data = result_str.data;

    return NGX_OK;
}


#if (NGX_PCRE)
static ngx_int_t
ngx_http_var_do_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject;
    ngx_int_t                    rc;

    ngx_http_complex_value_t    *args = var->args->elts;

    /* Calculate the value of src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    /* Perform regex match */
    rc = ngx_http_regex_exec(r, var->regex, &subject);
    if (rc == NGX_DECLINED) {
        v->data = (u_char *) "0";
        return NGX_OK;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: regex match failed");
        return NGX_ERROR;
    }

    v->data = (u_char *) "1";
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject, assign_value;
    ngx_int_t                    rc;

    ngx_http_complex_value_t    *args = var->args->elts;

    /* Calculate the value of src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Perform regex match */
    rc = ngx_http_regex_exec(r, var->regex, &subject);
    if (rc == NGX_DECLINED) {
        return NGX_ERROR;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: regex match failed");
        return NGX_ERROR;
    }

    /* Calculate the value of assign_value */
    if (ngx_http_complex_value(r, &args[1], &assign_value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Set the variable value */
    v->len = assign_value.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, assign_value.data, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject, replacement, result;
    ngx_int_t                    rc;
    u_char                      *p;
    ngx_uint_t                   start, end, len;

    ngx_http_complex_value_t    *args = var->args->elts;

    /* Calculate the value of src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Perform regex match */
    rc = ngx_http_regex_exec(r, var->regex, &subject);
    if (rc == NGX_DECLINED) {
        /* No match, return the original string */
        v->len = subject.len;
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(v->data, subject.data, v->len);
        return NGX_OK;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: regex substitution failed");
        return NGX_ERROR;
    }

    /* Ensure captures are available */
    if (r->ncaptures < 2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: insufficient captures");
        return NGX_ERROR;
    }

    /* Compute the replacement string */
    if (ngx_http_complex_value(r, &args[1], &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Build the result string */
    start = r->captures[0];
    end = r->captures[1];

    len = start + replacement.len + (subject.len - end);

    result.data = ngx_pnalloc(r->pool, len);
    if (result.data == NULL) {
        return NGX_ERROR;
    }

    p = result.data;

    /* Copy the part before the match */
    ngx_memcpy(p, subject.data, start);
    p += start;

    /* Copy the replacement */
    ngx_memcpy(p, replacement.data, replacement.len);
    p += replacement.len;

    /* Copy the part after the match */
    ngx_memcpy(p, subject.data + end, subject.len - end);
    p += subject.len - end;

    result.len = p - result.data;

    /* Set the variable value */
    v->len = result.len;
    v->data = result.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_re_gsub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject, replacement, result;
    ngx_http_complex_value_t    *args = var->args->elts;
    ngx_uint_t                   offset = 0;
    u_char                      *p;
    ngx_int_t                    rc;
    int                         *captures;
    ngx_uint_t                   allocated;
    ngx_uint_t                   required;

    /* Calculate the value of src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Calculate the replacement string template */
    if (ngx_http_complex_value(r, &args[1], &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Initialize the result string, initially allocate 2 times the original length */
    allocated = subject.len * 2;
    /* Set a smaller initial buffer limit to avoid excessive allocation for very small strings */
    if (allocated < 256) {  
        allocated = 256;
    }
    result.len = 0;
    result.data = ngx_pnalloc(r->pool, allocated);
    if (result.data == NULL) {
        return NGX_ERROR;
    }

    p = result.data;

    while (offset < subject.len) {
        ngx_str_t       sub;
        sub.len = subject.len - offset;
        sub.data = subject.data + offset;

        /* Perform regex match */
        rc = ngx_http_regex_exec(r, var->regex, &sub);

        if (rc == NGX_DECLINED) {
            /* No more matches, copy the remaining part */
            required = (ngx_uint_t)(p - result.data) + sub.len;
            if (required > allocated) {
                /* Need to expand the buffer */
                while (required > allocated) {
                    allocated *= 2;
                }
                u_char *new_data = ngx_pnalloc(r->pool, allocated);
                if (new_data == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(new_data, result.data, p - result.data);
                result.data = new_data;
                p = new_data + (p - result.data);
            }
            ngx_memcpy(p, sub.data, sub.len);
            p += sub.len;
            result.len += sub.len;
            break;
        } else if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: regex substitution failed");
            return NGX_ERROR;
        }

        /* Retrieve capture group information */
        captures = r->captures;
        /* captures is an array of ints, representing the start and end positions of the capture groups */
        int match_start = captures[0];
        int match_end = captures[1];

        /* Copy the part before the match */
        if (match_start > 0) {
            required = (ngx_uint_t)(p - result.data) + match_start;
            if (required > allocated) {
                /* Need to expand the buffer */
                while (required > allocated) {
                    allocated *= 2;
                }
                u_char *new_data = ngx_pnalloc(r->pool, allocated);
                if (new_data == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(new_data, result.data, p - result.data);
                result.data = new_data;
                p = new_data + (p - result.data);
            }
            ngx_memcpy(p, sub.data, match_start);
            p += match_start;
            result.len += match_start;
        }

        /* Compute the replacement string, handling $n */
        ngx_str_t replaced;
        if (ngx_http_complex_value(r, &args[1], &replaced) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Ensure the replacement string has enough space */
        required = (ngx_uint_t)(p - result.data) + replaced.len
            + (subject.len - offset - match_end);
        if (required > allocated) {
            /* Expand the buffer to a sufficient size */
            while (required > allocated) {
                allocated *= 2;
            }
            u_char *new_data = ngx_pnalloc(r->pool, allocated);
            if (new_data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(new_data, result.data, p - result.data);
            result.data = new_data;
            p = new_data + (p - result.data);
        }

        /* Copy the replacement string */
        ngx_memcpy(p, replaced.data, replaced.len);
        p += replaced.len;
        result.len += replaced.len;

        /* Update the offset to the end of the match */
        offset += match_end;

        /* Prevent infinite loop */
        if (match_end == match_start) {
            offset++;
            if (offset > subject.len) {
                break;
            }
        }
    }

    /* Set the variable value */
    v->len = p - result.data;
    v->data = result.data;

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_var_do_if_eq(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_eq\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 == int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_ne(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_ne\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 != int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_lt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_lt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 < int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_le(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_le\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 <= int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_gt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_gt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 > int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_ge(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &val2) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_gt\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    if (int_val1 >= int_val2) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, range_val;
    ngx_int_t                  is_negative_val = 0;
    ngx_int_t                  is_negative_start = 0, is_negative_end = 0;
    ngx_int_t                  src_val, start_val, end_val;
    ngx_str_t                  start_str, end_str;
    u_char                    *dash;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &range_val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len > 0 && val.data[0] == '-') {
        is_negative_val = 1;
        val.data++;
        val.len--;
    }

    dash = ngx_strlchr(range_val.data, range_val.data + range_val.len, '-');
    if (dash == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_range\" failed to "
                      "parse range, missing '-'");
        return NGX_ERROR;
    }

    start_str.data = range_val.data;
    start_str.len = dash - range_val.data;

    end_str.data = dash + 1;
    end_str.len = range_val.data + range_val.len - (dash + 1);

    if (start_str.len > 0 && start_str.data[0] == '-') {
        is_negative_start = 1;
        start_str.data++;
        start_str.len--;
    }

    if (end_str.len > 0 && end_str.data[0] == '-') {
        is_negative_end = 1;
        end_str.data++;
        end_str.len--;
    }

    if (ngx_http_var_auto_atofp3(val, start_str, end_str,
        &src_val, &start_val, &end_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"if_range\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative_val == 1) {
        src_val = -src_val;
    }

    if (is_negative_start == 1) {
        start_val = -start_val;
    }

    if (is_negative_end == 1) {
        end_val = -end_val;
    }

    if (src_val >= start_val && src_val <= end_val) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_abs(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;

    args = var->args->elts;

    /* Evaluate argument */
    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Check if is number */
    if (ngx_http_var_check_str_is_num(num_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid number for abs operator");
        return NGX_ERROR;
    }

    /* Convert arguments to integers */
    if (num_str.len > 0 && num_str.data[0] == '-') {
        num_str.data++;
        num_str.len--;
    }

    v->len = num_str.len;
    v->data = num_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str, val1, val2;
    ngx_int_t                  int_val1, int_val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;

    args = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute second argument");
        return NGX_ERROR;
    }

    val1 = int1_str;
    val2 = int2_str;

    /* Convert arguments to integers */
    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"max\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    /* Compute max */
    if (int_val1 > int_val2) {
        v->len = int1_str.len;
        v->data = int1_str.data;
    } else {
        v->len = int2_str.len;
        v->data = int2_str.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str, val1, val2;
    ngx_int_t                  int_val1, int_val2;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;

    args = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute second argument");
        return NGX_ERROR;
    }

    val1 = int1_str;
    val2 = int2_str;

    /* Convert arguments to integers */
    if (val1.len > 0 && val1.data[0] == '-') {
        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.len > 0 && val2.data[0] == '-') {
        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    if (ngx_http_var_auto_atofp(val1, val2, &int_val1, &int_val2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: \"min\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int_val1 = -int_val1;
    }

    if (is_negative2 == 1) {
        int_val2 = -int_val2;
    }

    /* Compute min */
    if (int_val1 < int_val2) {
        v->len = int1_str.len;
        v->data = int1_str.data;
    } else {
        v->len = int2_str.len;
        v->data = int2_str.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_add(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments for "
                      "add operator");
        return NGX_ERROR;
    }

    if (int1_str.len > 0 && int1_str.data[0] == '-') {
        int1 = ngx_atoi(int1_str.data + 1, int1_str.len - 1);
        is_negative1 = 1;
    } else {
        int1 = ngx_atoi(int1_str.data, int1_str.len);
    }

    if (int2_str.len > 0 && int2_str.data[0] == '-') {
        int2 = ngx_atoi(int2_str.data + 1, int2_str.len - 1);
        is_negative2 = 1;
    } else {
        int2 = ngx_atoi(int2_str.data, int2_str.len);
    }

    if (int1 == NGX_ERROR || int2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid integer value for add operator");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int1 = -int1;
    }

    if (is_negative2 == 1) {
        int2 = -int2;
    }

    result = int1 + int2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for add result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments for sub "
                      "operator");
        return NGX_ERROR;
    }

    if (int1_str.len > 0 && int1_str.data[0] == '-') {
        int1 = ngx_atoi(int1_str.data + 1, int1_str.len - 1);
        is_negative1 = 1;
    } else {
        int1 = ngx_atoi(int1_str.data, int1_str.len);
    }

    if (int2_str.len > 0 && int2_str.data[0] == '-') {
        int2 = ngx_atoi(int2_str.data + 1, int2_str.len - 1);
        is_negative2 = 1;
    } else {
        int2 = ngx_atoi(int2_str.data, int2_str.len);
    }

    if (int1 == NGX_ERROR || int2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid integer value for sub operator");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int1 = -int1;
    }

    if (is_negative2 == 1) {
        int2 = -int2;
    }

    result = int1 - int2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for sub result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_mul(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments for "
                      "mul operator");
        return NGX_ERROR;
    }

    if (int1_str.len > 0 && int1_str.data[0] == '-') {
        int1 = ngx_atoi(int1_str.data + 1, int1_str.len - 1);
        is_negative1 = 1;
    } else {
        int1 = ngx_atoi(int1_str.data, int1_str.len);
    }

    if (int2_str.len > 0 && int2_str.data[0] == '-') {
        int2 = ngx_atoi(int2_str.data + 1, int2_str.len - 1);
        is_negative2 = 1;
    } else {
        int2 = ngx_atoi(int2_str.data, int2_str.len);
    }

    if (int1 == NGX_ERROR || int2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid integer value for mul operator");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int1 = -int1;
    }

    if (is_negative2 == 1) {
        int2 = -int2;
    }

    result = int1 * int2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for mul result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_div(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments for "
                      "div operator");
        return NGX_ERROR;
    }

    if (int1_str.len > 0 && int1_str.data[0] == '-') {
        int1 = ngx_atoi(int1_str.data + 1, int1_str.len - 1);
        is_negative1 = 1;
    } else {
        int1 = ngx_atoi(int1_str.data, int1_str.len);
    }

    if (int2_str.len > 0 && int2_str.data[0] == '-') {
        int2 = ngx_atoi(int2_str.data + 1, int2_str.len - 1);
        is_negative2 = 1;
    } else {
        int2 = ngx_atoi(int2_str.data, int2_str.len);
    }

    if (int1 == NGX_ERROR || int2 == NGX_ERROR || int2 == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid integer value or division "
                      "by zero for div operator");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int1 = -int1;
    }

    if (is_negative2 == 1) {
        int2 = -int2;
    }

    result = int1 / int2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for div result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_mod(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    ngx_int_t                  is_negative1 = 0, is_negative2 = 0;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for mod operator");
        return NGX_ERROR;
    }

    if (int1_str.len > 0 && int1_str.data[0] == '-') {
        int1 = ngx_atoi(int1_str.data + 1, int1_str.len - 1);
        is_negative1 = 1;
    } else {
        int1 = ngx_atoi(int1_str.data, int1_str.len);
    }

    if (int2_str.len > 0 && int2_str.data[0] == '-') {
        int2 = ngx_atoi(int2_str.data + 1, int2_str.len - 1);
        is_negative2 = 1;
    } else {
        int2 = ngx_atoi(int2_str.data, int2_str.len);
    }

    if (int1 == NGX_ERROR || int2 == NGX_ERROR || int2 == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid integer value or "
                      "division by zero for mod operator");
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        int1 = -int1;
    }

    if (is_negative2 == 1) {
        int2 = -int2;
    }

    result = int1 % int2;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for mod result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_round(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str, precision_str;
    ngx_int_t                  precision, i, j, decimal_point = -1, len;
    u_char                    *num_data, *result;
    size_t                     num_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &precision_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments for "
                      "round operator");
        return NGX_ERROR;
    }

    precision = ngx_atoi(precision_str.data, precision_str.len);
    if (precision == NGX_ERROR || precision < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid precision value for round operator");
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: input for round operator must be a number");
            return NGX_ERROR;
        }
    }

    /* If there's no decimal point, add one and append zeros */
    if (decimal_point == -1) {
        decimal_point = num_len;
        num_len += precision + 1;
        num_data = ngx_palloc(r->pool, num_len + 1);
        if (num_data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(num_data, num_str.data, num_str.len);
        num_data[decimal_point] = '.';
        for (i = decimal_point + 1; i < (ngx_int_t)num_len; i++) {
            num_data[i] = '0';
        }
        num_data[num_len] = '\0';
        v->data = num_data;
        v->len = num_len;
        return NGX_OK;
    }

    len = decimal_point + precision + 1;
    if (len > (ngx_int_t)num_len) {
        len = num_len;
    }

    result = ngx_palloc(r->pool, len + 1);
    if (result == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(result, num_data, len);
    result[len] = '\0';

    /* Round the number if needed */
    if (len < (ngx_int_t)num_len && num_data[len] >= '5') {
        for (j = len - 1; j >= 0; j--) {
            if (result[j] == '.') {
                continue;
            }

            if (result[j] < '9') {
                result[j]++;
                break;
            } else {
                result[j] = '0';
                if (j == 0) {
                    u_char *new_result = ngx_palloc(r->pool, len + 2);
                    if (new_result == NULL) {
                        return NGX_ERROR;
                    }
                    new_result[0] = '1';
                    ngx_memcpy(new_result + 1, result, len);
                    new_result[len + 1] = '\0';
                    v->data = new_result;
                    v->len = len + 1;
                    return NGX_OK;
                }
            }
        }
    }

    /* Append zeros if necessary */
    if (len < (decimal_point + precision + 1)) {
        for (i = len; i < (decimal_point + precision + 1); i++) {
            result[i] = '0';
        }
        result[decimal_point + precision + 1] = '\0';
        v->len = decimal_point + precision + 1;
    } else {
        v->len = len;
    }

    v->data = result;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_floor(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;
    ngx_int_t                  i, decimal_point = -1;
    u_char                    *num_data, *result;
    size_t                     num_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "floor operator");
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: input for round operator must be a number");
            return NGX_ERROR;
        }
    }

    /* If there's no decimal point, it's already an integer */
    if (decimal_point == -1) {
        v->data = num_str.data;
        v->len = num_str.len;
        return NGX_OK;
    }

    /* Handle negative numbers differently */
    if (num_data[0] == '-') {
        /* Truncate everything after the decimal point */
        result = ngx_palloc(r->pool, decimal_point + 2);
        if (result == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(result, num_data, decimal_point);
        result[decimal_point] = '\0';

        /* Check if we need to round down */
        if (num_data[decimal_point + 1] > '0') {
            for (i = decimal_point - 1; i >= 0; i--) {
                if (result[i] == '-') {
                    continue;
                }

                if (result[i] < '9') {
                    result[i]++;
                    break;
                } else {
                    result[i] = '0';
                    if (i == 1) {
                        result[0] = '-';
                        result[1] = '1';
                        v->data = result;
                        v->len = decimal_point + 1;
                        return NGX_OK;
                    }
                }
            }
        }
    } else {
        /* Truncate everything after the decimal point for positive numbers */
        result = ngx_palloc(r->pool, decimal_point + 1);
        if (result == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(result, num_data, decimal_point);
        result[decimal_point] = '\0';
    }

    v->data = result;
    v->len = decimal_point;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_ceil(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;
    ngx_int_t                  i, decimal_point = -1;
    u_char                    *num_data, *result;
    size_t                     num_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "ceil operator");
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: input for round operator must be a number");
            return NGX_ERROR;
        }
    }

    /* If there's no decimal point, it's already an integer */
    if (decimal_point == -1) {
        v->data = num_str.data;
        v->len = num_str.len;
        return NGX_OK;
    }

    /* Handle negative numbers differently */
    if (num_data[0] == '-') {
        /* Truncate everything after the decimal point for negative numbers */
        result = ngx_palloc(r->pool, decimal_point + 1);
        if (result == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(result, num_data, decimal_point);
        result[decimal_point] = '\0';
    } else {
        /* Truncate everything after the decimal point */
        /* and add 1 if necessary for positive numbers */
        result = ngx_palloc(r->pool, decimal_point + 2);
        if (result == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(result, num_data, decimal_point);
        result[decimal_point] = '\0';

        /* Check if we need to round up */
        if (num_data[decimal_point + 1] > '0') {
            for (i = decimal_point - 1; i >= 0; i--) {
                if (result[i] < '9') {
                    result[i]++;
                    break;
                } else {
                    result[i] = '0';
                    if (i == 0) {
                        u_char *new_result = ngx_palloc(r->pool,
                            decimal_point + 2);
                        if (new_result == NULL) {
                            return NGX_ERROR;
                        }
                        new_result[0] = '1';
                        ngx_memcpy(new_result + 1, result, decimal_point);
                        new_result[decimal_point + 1] = '\0';
                        v->data = new_result;
                        v->len = decimal_point + 1;
                        return NGX_OK;
                    }
                }
            }
        }
    }

    v->data = result;
    v->len = decimal_point;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    /* Generate a random number */
    ngx_uint_t rand_num = ngx_random();

    /* Convert to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", rand_num) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_rand_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  range_str, start_str, end_str;
    ngx_int_t                  start, end, result;
    u_char                    *p;
    u_char                    *dash;

    args = var->args->elts;

    /* Compute the start and end values */
    if (ngx_http_complex_value(r, &args[0], &range_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for \"rand_range\" operator");
        return NGX_ERROR;
    }

    dash = ngx_strlchr(range_str.data, range_str.data + range_str.len, '-');
    if (dash == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to parse range, missing '-'");
        return NGX_ERROR;
    }

    start_str.data = range_str.data;
    start_str.len = dash - range_str.data;

    end_str.data = dash + 1;
    end_str.len = range_str.data + range_str.len - (dash + 1);

    start = ngx_atoi(start_str.data, start_str.len);
    end = ngx_atoi(end_str.data, end_str.len);

    if (start == NGX_ERROR || end == NGX_ERROR || start > end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid start or end value for \"rand_range\"");
        return NGX_ERROR;
    }

    /* Generate a random number between start and end (inclusive) */
    result = start + (ngx_random() % (end - start + 1));

    /* Allocate memory for the result string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for \"rand_range\" result");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, hex_str;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for hex_encode operator");
        return NGX_ERROR;
    }

    hex_str.len = src_str.len << 1;
    hex_str.data = ngx_pnalloc(r->pool, hex_str.len);
    if (hex_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for hex_encode");
        return NGX_ERROR;
    }

    ngx_hex_dump(hex_str.data, src_str.data, src_str.len);

    v->len = hex_str.len;
    v->data = hex_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  hex_str, bin_str;
    u_char                    *p;
    ngx_int_t                  n;
    size_t                     i;

    args = var->args->elts;

    /* Compute argument */
    if (ngx_http_complex_value(r, &args[0], &hex_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for hex_decode operator");
        return NGX_ERROR;
    }

    /* Check if the input string is of even length */
    if (hex_str.len % 2 != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: hex_decode requires even-length string");
        return NGX_ERROR;
    }

    /* Allocate memory for the output binary string */
    bin_str.len = hex_str.len >> 1;
    bin_str.data = ngx_pnalloc(r->pool, bin_str.len);
    if (bin_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for hex_decode");
        return NGX_ERROR;
    }

    /* Convert hex string to binary */
    p = hex_str.data;
    for (i = 0; i < bin_str.len; i++) {
        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid hex character "
                          "in hex_decode at position %d",
                          (int)(p - hex_str.data));
            return NGX_ERROR;
        }

        p += 2;
        bin_str.data[i] = (u_char) n;
    }

    /* Set variable value */
    v->len = bin_str.len;
    v->data = bin_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_dec_to_hex(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  dec_str;
    ngx_int_t                  dec_value;
    u_char                    *p;
    ngx_flag_t                 negative = 0;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &dec_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for dec_to_hex");
        return NGX_ERROR;
    }

    /* Validate if the input is a number */
    if (dec_str.data[0] == '-') {
        negative = 1;
    }

    dec_value = ngx_atoi(dec_str.data + (negative ? 1 : 0),
                           dec_str.len - (negative ? 1 : 0));
    if (dec_value == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid decimal value for dec_to_hex");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for dec_to_hex");
        return NGX_ERROR;
    }

    if (negative) {
        v->len = ngx_sprintf(p, "-%xi", dec_value) - p;
    } else {
        v->len = ngx_sprintf(p, "%xi", dec_value) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_hex_to_dec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  hex_str;
    ngx_int_t                  dec_value = 0;
    u_char                    *p;
    ngx_flag_t                 negative = 0;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &hex_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for hex_to_dec");
        return NGX_ERROR;
    }

    /* Check if the input is negative */
    if (hex_str.data[0] == '-') {
        negative = 1;
    }

    dec_value = ngx_hextoi(hex_str.data + (negative ? 1 : 0),
                           hex_str.len - (negative ? 1 : 0));
    if (dec_value == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid hexadecimal value for hex_to_dec");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for hex_to_dec");
        return NGX_ERROR;
    }

    if (negative) {
        v->len = ngx_sprintf(p, "-%i", dec_value) - p;
    } else {
        v->len = ngx_sprintf(p, "%i", dec_value) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, escaped_str;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for escape_uri operator");
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    src = src_str.data;

    /* Calculate the escaped length */
    escape = 2 * ngx_escape_uri(NULL, src, src_str.len, NGX_ESCAPE_URI);
    len = src_str.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for escape_uri");
        return NGX_ERROR;
    }

    /* Perform the escaping */
    if (escape == 0) {
        ngx_memcpy(dst, src, src_str.len);
    } else {
        ngx_escape_uri(dst, src, src_str.len, NGX_ESCAPE_URI);
    }

    /* Set the escaped string */
    escaped_str.data = dst;
    escaped_str.len = len;

    /* Set the variable value */
    v->len = escaped_str.len;
    v->data = escaped_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, escaped_str;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for escape_args operator");
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    src = src_str.data;

    /* Calculate the escaped length */
    escape = 2 * ngx_escape_uri(NULL, src, src_str.len, NGX_ESCAPE_ARGS);
    len = src_str.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for escape_args");
        return NGX_ERROR;
    }

    /* Perform the escaping */
    if (escape == 0) {
        ngx_memcpy(dst, src, src_str.len);
    } else {
        ngx_escape_uri(dst, src, src_str.len, NGX_ESCAPE_ARGS);
    }

    /* Set the escaped string */
    escaped_str.data = dst;
    escaped_str.len = len;

    /* Set the variable value */
    v->len = escaped_str.len;
    v->data = escaped_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_escape_uri_component(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, escaped_str;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for escape_uri_component operator");
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    src = src_str.data;

    /* Calculate the escaped length */
    escape = 2 * ngx_escape_uri(NULL, src, src_str.len,
                                NGX_ESCAPE_URI_COMPONENT);
    len = src_str.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "escape_uri_component");
        return NGX_ERROR;
    }

    /* Perform the escaping */
    if (escape == 0) {
        ngx_memcpy(dst, src, src_str.len);
    } else {
        ngx_escape_uri(dst, src, src_str.len, NGX_ESCAPE_URI_COMPONENT);
    }

    /* Set the escaped string */
    escaped_str.data = dst;
    escaped_str.len = len;

    /* Set the variable value */
    v->len = escaped_str.len;
    v->data = escaped_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_escape_html(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, escaped_str;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for escape_uri_component operator");
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    src = src_str.data;

    /* Calculate the escaped length */
    escape = 2 * ngx_escape_uri(NULL, src, src_str.len,
                                NGX_ESCAPE_HTML);
    len = src_str.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "escape_html");
        return NGX_ERROR;
    }

    /* Perform the escaping */
    if (escape == 0) {
        ngx_memcpy(dst, src, src_str.len);
    } else {
        ngx_escape_uri(dst, src, src_str.len, NGX_ESCAPE_HTML);
    }

    /* Set the escaped string */
    escaped_str.data = dst;
    escaped_str.len = len;

    /* Set the variable value */
    v->len = escaped_str.len;
    v->data = escaped_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, unescaped_str;
    size_t                     len;
    u_char                    *p, *src, *dst;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "unescape_uri operator");
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    /* Allocate memory for the unescaped string */
    len = src_str.len;
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for unescape_uri");
        return NGX_ERROR;
    }

    /* Perform the unescaping */
    src = src_str.data;
    dst = p;
    ngx_unescape_uri(&dst, &src, src_str.len, 0);

    if (src != src_str.data + src_str.len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: input data not consumed completely "
                      "in unescape_uri");
        return NGX_ERROR;
    }

    /* Set variable value */
    unescaped_str.data = p;
    unescaped_str.len = dst - p;

    v->len = unescaped_str.len;
    v->data = unescaped_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_base64_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, encoded_str;
    size_t                     len;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "base64_encode operator");
        return NGX_ERROR;
    }

    len = ngx_base64_encoded_length(src_str.len);

    encoded_str.data = ngx_pnalloc(r->pool, len);
    if (encoded_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for base64_encode");
        return NGX_ERROR;
    }

    ngx_encode_base64(&encoded_str, &src_str);

    /* Set variable value */
    v->len = encoded_str.len;
    v->data = encoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_base64url_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, encoded_str;
    size_t                     len;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "base64url_encode operator");
        return NGX_ERROR;
    }

    len = ngx_base64_encoded_length(src_str.len);

    encoded_str.data = ngx_pnalloc(r->pool, len);
    if (encoded_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "base64url_encode");
        return NGX_ERROR;
    }

    ngx_encode_base64url(&encoded_str, &src_str);

    /* Set variable value */
    v->len = encoded_str.len;
    v->data = encoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_base64_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, decoded_str;
    size_t                     len;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "base64_decode operator");
        return NGX_ERROR;
    }

    len = ngx_base64_decoded_length(src_str.len);

    decoded_str.data = ngx_pnalloc(r->pool, len);
    if (decoded_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "base64_decode");
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded_str, &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to decode base64 string");
        return NGX_ERROR;
    }

    /* Set variable value */
    v->len = decoded_str.len;
    v->data = decoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_base64url_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, decoded_str;
    size_t                     len;

    args = var->args->elts;

    /* Compute the source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "base64url_decode operator");
        return NGX_ERROR;
    }

    len = ngx_base64_decoded_length(src_str.len);

    decoded_str.data = ngx_pnalloc(r->pool, len);
    if (decoded_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "base64url_decode");
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&decoded_str, &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to decode base64url string");
        return NGX_ERROR;
    }

    /* Set variable value */
    v->len = decoded_str.len;
    v->data = decoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_crc32_short(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    ngx_uint_t                 crc;

    args = var->args->elts;

    /* Evaluate source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "crc32_short source string");
        return NGX_ERROR;
    }

    /* Compute CRC32 */
    crc = ngx_crc32_short(src_str.data, src_str.len);

    /* Allocate buffer for CRC32 result */
    u_char *p;
    p = ngx_pnalloc(r->pool, 9);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for crc32_short");
        return NGX_ERROR;
    }

    /* Convert CRC32 result to string */
    v->len = ngx_sprintf(p, "%08xD", crc) - p;

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_crc32_long(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    ngx_uint_t                 crc;

    args = var->args->elts;

    /* Evaluate source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "crc32_long source string");
        return NGX_ERROR;
    }

    /* Compute CRC32 */
    crc = ngx_crc32_long(src_str.data, src_str.len);

    /* Allocate buffer for CRC32 result */
    u_char *p;
    p = ngx_pnalloc(r->pool, 9);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for crc32_long");
        return NGX_ERROR;
    }

    /* Convert CRC32 result to string */
    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_md5sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    ngx_md5_t                  md5;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "md5sum operator");
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 32);
    if (hash_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for md5sum");
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, src_str.data, src_str.len);
    ngx_md5_final(hash_data, &md5);

    /* Convert the MD5 hash to a hexadecimal string */
    v->data = ngx_pnalloc(r->pool, 32);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash_data, 16);
    v->len = 32;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_sha1sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    ngx_sha1_t                 sha1;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "sha1sum operator");
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 40);
    if (hash_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for sha1sum");
        return NGX_ERROR;
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, src_str.data, src_str.len);
    ngx_sha1_final(hash_data, &sha1);

    /* Convert the SHA1 hash to a hexadecimal string */
    v->data = ngx_pnalloc(r->pool, 40);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash_data, 20);
    v->len = 40;

    return NGX_OK;
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_var_do_sha256sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "sha256sum operator");
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 64);
    if (hash_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for sha256sum");
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        return NGX_ERROR;
    }

    EVP_MD_CTX_destroy(md);

    /* Convert the SHA256 hash to a hexadecimal string */
    v->data = ngx_pnalloc(r->pool, 64);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash_data, 32);
    v->len = 64;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_sha384sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "sha256sum operator");
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 96);
    if (hash_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for sha384sum");
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha384(), NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        return NGX_ERROR;
    }

    EVP_MD_CTX_destroy(md);

    /* Convert the SHA384 hash to a hexadecimal string */
    v->data = ngx_pnalloc(r->pool, 96);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash_data, 48);
    v->len = 96;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_sha512sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "sha512sum operator");
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 128);
    if (hash_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for sha512sum");
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha512(), NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        return NGX_ERROR;
    }

    EVP_MD_CTX_destroy(md);

    /* Convert the SHA384 hash to a hexadecimal string */
    v->data = ngx_pnalloc(r->pool, 128);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash_data, 64);
    v->len = 128;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_hmac_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, secret_str;
    unsigned int               md_len = 0;
    unsigned char              md[EVP_MAX_MD_SIZE];

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "HMAC_SHA1 src_string");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &secret_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "HMAC_SHA1 secret");
        return NGX_ERROR;
    }

    HMAC(EVP_sha1(), secret_str.data, secret_str.len,
        src_str.data, src_str.len, md, &md_len);

    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, md_len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for HMAC_SHA1");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, &md, md_len);
    v->len = md_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_hmac_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, secret_str;
    unsigned int               md_len = 0;
    unsigned char              md[EVP_MAX_MD_SIZE];

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "HMAC_SHA256 src_string");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &secret_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "HMAC_SHA256 secret");
        return NGX_ERROR;
    }

    HMAC(EVP_sha256(), secret_str.data, secret_str.len,
         src_str.data, src_str.len, md, &md_len);

    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, md_len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for HMAC_SHA256");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, &md, md_len);
    v->len = md_len;

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_var_do_if_time_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  param_str;
    ngx_int_t                  year_start = -1, year_end = -1;
    ngx_int_t                  month_start = -1, month_end = -1;
    ngx_int_t                  day_start = -1, day_end = -1;
    ngx_int_t                  wday_start = -1, wday_end = -1;
    ngx_int_t                  hour_start = -1, hour_end = -1;
    ngx_int_t                  min_start = -1, min_end = -1;
    ngx_int_t                  sec_start = -1, sec_end = -1;
    ngx_int_t                  tz_offset = 0;
    ngx_uint_t                 i, j;
    time_t                     raw_time;
    struct tm                  tm_copy;

    args = var->args->elts;

    /* parse time range */
    for (i = 0; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &param_str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncmp(param_str.data, "year=", 5) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &year_start, &year_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid year range value");
                return NGX_ERROR;
            }

            if (year_start < 1970 || year_end < year_start) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid year range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "month=", 6) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 6, param_str.data + 6},
                    &month_start, &month_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid month range value");
                return NGX_ERROR;
            }

            if (month_start < 1 || month_start > 12
                || month_end < month_start || month_end > 12) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid month range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "day=", 4) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &day_start, &day_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid day range value");
                return NGX_ERROR;
            }

            if (day_start < 1 || day_start > 31
                || day_end < day_start || day_end > 31) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid day range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "wday=", 5) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &wday_start, &wday_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid wday range value");
                return NGX_ERROR;
            }

            if (wday_start < 1 || wday_start > 7
                || wday_end < wday_start || wday_end > 7) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid wday range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "hour=", 5) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &hour_start, &hour_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid hour range value");
                return NGX_ERROR;
            }

            if (hour_start < 0 || hour_start > 23
                || hour_end < hour_start || hour_end > 23) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid hour range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "min=", 4) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &min_start, &min_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid minute range value");
                return NGX_ERROR;
            }

            if (min_start < 0 || min_start > 59
                || min_end < min_start || min_end > 59) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid minute range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "sec=", 4) == 0) {
            if (ngx_http_var_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &sec_start, &sec_end) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid second range value");
                return NGX_ERROR;
            }

            if (sec_start < 0 || sec_start > 59
                || sec_end < sec_start || sec_end > 59) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid second range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "timezone=", 9) == 0) {
            if (var->args->nelts == 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: at least one time range "
                    "args must be present");
                return NGX_ERROR;
            }

            if (ngx_strncmp(param_str.data + 9, "gmt", 3) == 0) {
                if (param_str.len == 12) {
                    tz_offset = 0;
                } else if (param_str.len == 17
                    && (param_str.data[12] == '+' 
                        || param_str.data[12] == '-')) {
                    for (j = 13; j < 17; j++) {
                        if (param_str.data[j] < '0'
                            || param_str.data[j] > '9') {
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "http_var: invalid timezone offset value");
                            return NGX_ERROR;
                        }
                    }

                    tz_offset = ((param_str.data[13] - '0') * 10
                                  + (param_str.data[14] - '0')) * 3600;
                    tz_offset += ((param_str.data[15] - '0') * 10
                                   + (param_str.data[16] - '0')) * 60;

                    if (param_str.data[12] == '-') {
                        tz_offset = -tz_offset;
                    }
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "http_var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: invalid timezone format");
                return NGX_ERROR;
            }
        }
    }

    /* get current time */
    if (tz_offset >= 0) {
        raw_time = ngx_time() + (time_t)tz_offset;
    } else {
        raw_time = ngx_time() - (time_t)(-tz_offset);
    }

    ngx_libc_gmtime(raw_time, &tm_copy);

    /* check whether each time parameter meets the requirements */
    if ((year_start != -1
            && (tm_copy.tm_year + 1900 < year_start
                || tm_copy.tm_year + 1900 > year_end))
        || (month_start != -1
            && (tm_copy.tm_mon + 1 < month_start
                || tm_copy.tm_mon + 1 > month_end))
        || (day_start != -1
            && (tm_copy.tm_mday < day_start || tm_copy.tm_mday > day_end))
        || (wday_start != -1
            && ((tm_copy.tm_wday == 0 ? 7 : tm_copy.tm_wday) < wday_start
                || (tm_copy.tm_wday == 0 ? 7 : tm_copy.tm_wday) > wday_end))
        || (hour_start != -1
            && (tm_copy.tm_hour < hour_start || tm_copy.tm_hour > hour_end))
        || (min_start != -1
            && (tm_copy.tm_min < min_start || tm_copy.tm_min > min_end))
        || (sec_start != -1
            && (tm_copy.tm_sec < sec_start || tm_copy.tm_sec > sec_end))) {
        v->len = 1;
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char *) "1";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_gmt_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  ts_str, date_format;
    time_t                     ts;
    u_char                    *p;
    struct tm                  tm;

    args = var->args->elts;

    if (var->args->nelts == 2) {
        /* Two arguments: unix_time and date format */
        if (ngx_http_complex_value(r, &args[0], &ts_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "gmt_time unix_time");
            return NGX_ERROR;
        }

        ts = ngx_atoi(ts_str.data, ts_str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid unix_time value for gmt_time");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "gmt_time date_format");
            return NGX_ERROR;
        }
    } else {
        /* One argument: date format, use current time */
        if (ngx_http_complex_value(r, &args[0], &date_format) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument "
                          "for gmt_time date_format");
            return NGX_ERROR;
        }

        ts = ngx_time();
    }

    if (ngx_strcmp(date_format.data, "http_time") == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: memory allocation failed for gmt_time");
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, ts)- p;
        v->data = p;

        return NGX_OK;
    }
  
    if (ngx_strcmp(date_format.data, "cookie_time") == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Thu, 18-Nov-10 11:27:35 GMT") - 1);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: memory allocation failed for gmt_time");
            return NGX_ERROR;
        }

        v->len = ngx_http_cookie_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }
  
    ngx_libc_gmtime(ts, &tm);

    /* Allocate extra space for formatting */
    p = ngx_palloc(r->pool, 256);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for gmt_time");
        return NGX_ERROR;
    }

    v->len = strftime((char *) p, 256,
                      (char *) date_format.data, &tm);

    if (v->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: strftime failed for gmt_time");
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_local_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  ts_str, date_format;
    time_t                     ts;
    u_char                    *p;
    struct tm                  tm;

    args = var->args->elts;

    if (var->args->nelts == 2) {
        /* Two arguments: unix_time and date format */
        if (ngx_http_complex_value(r, &args[0], &ts_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "gmt_time unix_time");
            return NGX_ERROR;
        }

        ts = ngx_atoi(ts_str.data, ts_str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid unix_time value "
                          "for gmt_time");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "gmt_time date_format");
            return NGX_ERROR;
        }
    } else {
        /* One argument: date format, use current time */
        if (ngx_http_complex_value(r, &args[0], &date_format) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument "
                          "for gmt_time date_format");
            return NGX_ERROR;
        }

        ts = ngx_time();
    }

    ngx_libc_localtime(ts, &tm);

    /* Allocate extra space for formatting */
    p = ngx_palloc(r->pool, 256);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for local_time");
        return NGX_ERROR;
    }

    v->len = strftime((char *) p, 256,
                      (char *) date_format.data, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: strftime failed for local_time");
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_unix_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  date_str, date_format, tz_str;
    ngx_tm_t                   tm;
    time_t                     unix_time;
    int                        tz_offset = 0;
    u_char                    *p;
    ngx_time_t                *tp;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (var->args->nelts == 0) {
        p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        tp = ngx_timeofday();

        v->len = ngx_sprintf(p, "%T", tp->sec) - p;
        v->data = p;

        return NGX_OK;
    }
    
    if (var->args->nelts == 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: illegal number of parameters for unix_time");
        return NGX_ERROR;
    }

    /* Two arguments: http date string, http_time */
    if (ngx_http_complex_value(r, &args[0], &date_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: failed to compute argument for "
                    "unix_time date_string");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_var: failed to compute argument for "
                    "unix_time date_format");
        return NGX_ERROR;
    }

    if (ngx_strcmp(date_format.data, "http_time") == 0) {
        unix_time = ngx_parse_http_time(date_str.data, date_str.len);
        if (unix_time == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to parse http_time for unix_time");
            return NGX_ERROR;
        }
        goto set_unix_time;
    }

    /* Third argument: timezone */
    if (var->args->nelts == 3) {
        if (ngx_http_complex_value(r, &args[2], &tz_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "unix_time timezone");
            return NGX_ERROR;
        }

        if (ngx_strncmp(tz_str.data, "gmt", 3) == 0) {
            if (tz_str.len == 3) {
                tz_offset = 0;
            } else if ((tz_str.len == 8)
                       && (tz_str.data[3] == '+' || tz_str.data[3] == '-')) {
                for (i = 4; i < 8; i++) {
                    if (tz_str.data[i] < '0'
                        || tz_str.data[i] > '9') {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "http_var: invalid timezone offset value");
                        return NGX_ERROR;
                    }
                }

                /* Parse timezone offset, e.g., +0800 or -0200 */
                tz_offset = ((tz_str.data[4] - '0') * 10
                              + (tz_str.data[5] - '0')) * 3600;
                tz_offset += ((tz_str.data[6] - '0') * 10
                               + (tz_str.data[7] - '0')) * 60;
                if (tz_str.data[3] == '-') {
                    tz_offset = -tz_offset;
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "http_var: invalid timezone format for "
                              "\"unix_time\" operator");
                return NGX_ERROR;
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid timezone format for "
                          "\"unix_time\" operator");
            return NGX_ERROR;
        }
    }

    /* Parse the date string */
    ngx_memzero(&tm, sizeof(ngx_tm_t));
    if (strptime((char *) date_str.data,
        (char *) date_format.data, &tm) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "http_var: failed to parse date string for "
                        "\"unix_time\" operator");
        return NGX_ERROR;
    }

    /* Convert to unix_time */
    unix_time = timegm(&tm) - tz_offset;

set_unix_time:

    /* Convert unix_time to string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "\"unix_time\" operator");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", unix_time) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_do_if_ip_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  ip_str, range_str;
    ngx_uint_t                 i;
    ngx_cidr_t                 cidr;
    in_addr_t                  ipv4_addr;

#if (NGX_HAVE_INET6)
    struct in6_addr            ipv6_addr;
    struct sockaddr_in6        addr_in6;
#endif

    args = var->args->elts;

    /* Get the IP address to match */
    if (ngx_http_complex_value(r, &args[0], &ip_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for \"if_ip_range\" operator");
        return NGX_ERROR;
    }

    /* Parse IPv4 address */
    ipv4_addr = ngx_inet_addr(ip_str.data, ip_str.len);
    if (ipv4_addr == INADDR_NONE) {

#if (NGX_HAVE_INET6)
        /* If it's not IPv4, try to parse as IPv6 */
        if (ngx_inet6_addr(ip_str.data, ip_str.len, &ipv6_addr) == NGX_OK) {
            /* IPv6 address */
            addr_in6.sin6_family = AF_INET6;
            ngx_memcpy(&addr_in6.sin6_addr, &ipv6_addr,
                       sizeof(struct in6_addr));

            /* Check if the IPv6 address is an IPv4-mapped address */
            if (IN6_IS_ADDR_V4MAPPED(&ipv6_addr)) {
                /* Extract the IPv4 address from the mapped IPv6 address */
                u_char *p = ipv6_addr.s6_addr;
                ipv4_addr = p[12] << 24;
                ipv4_addr += p[13] << 16;
                ipv4_addr += p[14] << 8;
                ipv4_addr += p[15];
                ipv4_addr = htonl(ipv4_addr);
            }
        }
#endif

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid IP address: \"%V\"", &ip_str);
        return NGX_ERROR;

    }

    /* Iterate over all IP ranges to find a match */
    for (i = 1; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &range_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: failed to compute argument for "
                          "\"if_ip_range\" operator");
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
                ngx_uint_t n;
                for (n = 0; n < 16; n++) {
                    if ((p[n] & cidr.u.in6.mask.s6_addr[n])
                        != cidr.u.in6.addr.s6_addr[n]) {
                        goto next;
                    }
                }

                v->len = 1;
                v->data = (u_char *) "1";
                return NGX_OK;

            next:
                continue;
#endif
            }

        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid IP or CIDR range: \"%V\"",
                          &range_str);
            return NGX_ERROR;
        }
    }

    /* No matching range found */
    v->len = 1;
    v->data = (u_char *) "0";

    return NGX_OK;
}
