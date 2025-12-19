
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
    NGX_HTTP_VAR_OP_HMAC_SHA384,
    NGX_HTTP_VAR_OP_HMAC_SHA512,
#endif

    NGX_HTTP_VAR_OP_IF_TIME_RANGE,

    NGX_HTTP_VAR_OP_GMT_TIME,
    NGX_HTTP_VAR_OP_LOCAL_TIME,
    NGX_HTTP_VAR_OP_UNIX_TIME,

    NGX_HTTP_VAR_OP_IF_IP_RANGE,

    NGX_HTTP_VAR_OP_GET_COOKIE,

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


static ngx_http_var_operator_enum_t ngx_http_var_operators[] = {
    { ngx_string("and"),              NGX_HTTP_VAR_OP_AND,              2, 99 },
    { ngx_string("or"),               NGX_HTTP_VAR_OP_OR,               2, 99 },
    { ngx_string("not"),              NGX_HTTP_VAR_OP_NOT,              1, 1  },

    { ngx_string("if_empty"),         NGX_HTTP_VAR_OP_IF_EMPTY,         1, 1  },
    { ngx_string("if_not_empty"),     NGX_HTTP_VAR_OP_IF_NOT_EMPTY,     1, 1  },
    { ngx_string("if_is_num"),        NGX_HTTP_VAR_OP_IF_IS_NUM,        1, 1  },
    { ngx_string("if_str_eq"),        NGX_HTTP_VAR_OP_IF_STR_EQ,        2, 2  },
    { ngx_string("if_str_ne"),        NGX_HTTP_VAR_OP_IF_STR_NE,        2, 2  },
    { ngx_string("if_starts_with"),   NGX_HTTP_VAR_OP_IF_STARTS_WITH,   2, 2  },
    { ngx_string("if_ends_with"),     NGX_HTTP_VAR_OP_IF_ENDS_WITH,     2, 2  },
    { ngx_string("if_find"),          NGX_HTTP_VAR_OP_IF_FIND,          2, 2  },
    { ngx_string("if_str_in"),        NGX_HTTP_VAR_OP_IF_STR_IN,        3, 99 },

    { ngx_string("copy"),             NGX_HTTP_VAR_OP_COPY,             1, 1  },
    { ngx_string("len"),              NGX_HTTP_VAR_OP_LEN,              1, 1  },
    { ngx_string("upper"),            NGX_HTTP_VAR_OP_UPPER,            1, 1  },
    { ngx_string("lower"),            NGX_HTTP_VAR_OP_LOWER,            1, 1  },
    { ngx_string("trim"),             NGX_HTTP_VAR_OP_TRIM,             1, 1  },
    { ngx_string("ltrim"),            NGX_HTTP_VAR_OP_LTRIM,            1, 1  },
    { ngx_string("rtrim"),            NGX_HTTP_VAR_OP_RTRIM,            1, 1  },
    { ngx_string("reverse"),          NGX_HTTP_VAR_OP_REVERSE,          1, 1  },
    { ngx_string("find"),             NGX_HTTP_VAR_OP_FIND,             2, 2  },
    { ngx_string("repeat"),           NGX_HTTP_VAR_OP_REPEAT,           2, 2  },
    { ngx_string("substr"),           NGX_HTTP_VAR_OP_SUBSTR,           2, 3  },
    { ngx_string("replace"),          NGX_HTTP_VAR_OP_REPLACE,          3, 3  },

#if (NGX_PCRE)
    { ngx_string("if_re_match"),      NGX_HTTP_VAR_OP_IF_RE_MATCH,      2, 2  },

    { ngx_string("re_capture"),       NGX_HTTP_VAR_OP_RE_CAPTURE,       3, 3  },
    { ngx_string("re_sub"),           NGX_HTTP_VAR_OP_RE_SUB,           3, 3  },
    { ngx_string("re_gsub"),          NGX_HTTP_VAR_OP_RE_GSUB,          3, 3  },
#endif

    { ngx_string("if_eq"),            NGX_HTTP_VAR_OP_IF_EQ,            2, 2  },
    { ngx_string("if_ne"),            NGX_HTTP_VAR_OP_IF_NE,            2, 2  },
    { ngx_string("if_lt"),            NGX_HTTP_VAR_OP_IF_LT,            2, 2  },
    { ngx_string("if_le"),            NGX_HTTP_VAR_OP_IF_LE,            2, 2  },
    { ngx_string("if_gt"),            NGX_HTTP_VAR_OP_IF_GT,            2, 2  },
    { ngx_string("if_ge"),            NGX_HTTP_VAR_OP_IF_GE,            2, 2  },
    { ngx_string("if_range"),         NGX_HTTP_VAR_OP_IF_RANGE,         2, 2  },
    { ngx_string("if_in"),            NGX_HTTP_VAR_OP_IF_IN,            3, 99 },

    { ngx_string("abs"),              NGX_HTTP_VAR_OP_ABS,              1, 1  },
    { ngx_string("max"),              NGX_HTTP_VAR_OP_MAX,              2, 2  },
    { ngx_string("min"),              NGX_HTTP_VAR_OP_MIN,              2, 2  },
    { ngx_string("add"),              NGX_HTTP_VAR_OP_ADD,              2, 2  },
    { ngx_string("sub"),              NGX_HTTP_VAR_OP_SUB,              2, 2  },
    { ngx_string("mul"),              NGX_HTTP_VAR_OP_MUL,              2, 2  },
    { ngx_string("div"),              NGX_HTTP_VAR_OP_DIV,              2, 2  },
    { ngx_string("mod"),              NGX_HTTP_VAR_OP_MOD,              2, 2  },
    { ngx_string("round"),            NGX_HTTP_VAR_OP_ROUND,            2, 2  },
    { ngx_string("floor"),            NGX_HTTP_VAR_OP_FLOOR,            1, 1  },
    { ngx_string("ceil"),             NGX_HTTP_VAR_OP_CEIL,             1, 1  },
    { ngx_string("rand"),             NGX_HTTP_VAR_OP_RAND,             0, 0  },
    { ngx_string("rand_range"),       NGX_HTTP_VAR_OP_RAND_RANGE,       1, 1  },

    { ngx_string("hex_encode"),       NGX_HTTP_VAR_OP_HEX_ENCODE,       1, 1  },
    { ngx_string("hex_decode"),       NGX_HTTP_VAR_OP_HEX_DECODE,       1, 1  },
    { ngx_string("dec_to_hex"),       NGX_HTTP_VAR_OP_DEC_TO_HEX,       1, 1  },
    { ngx_string("hex_to_dec"),       NGX_HTTP_VAR_OP_HEX_TO_DEC,       1, 1  },
    { ngx_string("escape_uri"),       NGX_HTTP_VAR_OP_ESCAPE_URI,       1, 1  },
    { ngx_string("escape_args"),      NGX_HTTP_VAR_OP_ESCAPE_ARGS,      1, 1  },
    { ngx_string("escape_uri_component"),
                                NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT,   1, 1  },
    { ngx_string("escape_html"),      NGX_HTTP_VAR_OP_ESCAPE_HTML,      1, 1  },
    { ngx_string("unescape_uri"),     NGX_HTTP_VAR_OP_UNESCAPE_URI,     1, 1  },
    { ngx_string("base64_encode"),    NGX_HTTP_VAR_OP_BASE64_ENCODE,    1, 1  },
    { ngx_string("base64url_encode"), NGX_HTTP_VAR_OP_BASE64URL_ENCODE, 1, 1  },
    { ngx_string("base64_decode"),    NGX_HTTP_VAR_OP_BASE64_DECODE,    1, 1  },
    { ngx_string("base64url_decode"), NGX_HTTP_VAR_OP_BASE64URL_DECODE, 1, 1  },

    { ngx_string("crc32_short"),      NGX_HTTP_VAR_OP_CRC32_SHORT,      1, 1  },
    { ngx_string("crc32_long"),       NGX_HTTP_VAR_OP_CRC32_LONG,       1, 1  },
    { ngx_string("md5sum"),           NGX_HTTP_VAR_OP_MD5SUM,           1, 1  },
    { ngx_string("sha1sum"),          NGX_HTTP_VAR_OP_SHA1SUM,          1, 1  },

#if (NGX_HTTP_SSL)
    { ngx_string("sha256sum"),        NGX_HTTP_VAR_OP_SHA256SUM,        1, 1  },
    { ngx_string("sha384sum"),        NGX_HTTP_VAR_OP_SHA384SUM,        1, 1  },
    { ngx_string("sha512sum"),        NGX_HTTP_VAR_OP_SHA512SUM,        1, 1  },
    { ngx_string("hmac_sha1"),        NGX_HTTP_VAR_OP_HMAC_SHA1,        2, 2  },
    { ngx_string("hmac_sha256"),      NGX_HTTP_VAR_OP_HMAC_SHA256,      2, 2  },
    { ngx_string("hmac_sha384"),      NGX_HTTP_VAR_OP_HMAC_SHA384,      2, 2  },
    { ngx_string("hmac_sha512"),      NGX_HTTP_VAR_OP_HMAC_SHA512,      2, 2  },
#endif

    { ngx_string("if_time_range"),    NGX_HTTP_VAR_OP_IF_TIME_RANGE,    1, 8  },

    { ngx_string("gmt_time"),         NGX_HTTP_VAR_OP_GMT_TIME,         1, 2  },
    { ngx_string("local_time"),       NGX_HTTP_VAR_OP_LOCAL_TIME,       1, 2  },
    { ngx_string("unix_time"),        NGX_HTTP_VAR_OP_UNIX_TIME,        0, 3  },

    { ngx_string("if_ip_range"),      NGX_HTTP_VAR_OP_IF_IP_RANGE,      2, 99 },

    { ngx_string("get_cookie"),       NGX_HTTP_VAR_OP_GET_COOKIE,       1, 1  },

    { ngx_null_string,                NGX_HTTP_VAR_OP_UNKNOWN,          0, 0  }
};


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
    ngx_int_t index, ngx_http_var_conf_t *vconf,
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
static ngx_int_t ngx_http_var_utils_parse_int_range(ngx_str_t str,
    ngx_int_t *start, ngx_int_t *end);
static ngx_int_t ngx_http_var_utils_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    ngx_uint_t type);
static u_char *ngx_http_var_utils_strlstrn(u_char *s1, u_char *last,
    u_char *s2, size_t n);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_var_utils_set_hmac(ngx_http_request_t *r,
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

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_exec_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_exec_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_re_gsub(ngx_http_request_t *r,
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
static ngx_int_t ngx_http_var_exec_rand_range(ngx_http_request_t *r,
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

static ngx_int_t ngx_http_var_exec_crc32_short(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_crc32_long(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_md5sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha1sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_var_exec_sha256sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha384sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_sha512sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_exec_hmac_sha1(ngx_http_request_t *r,
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

static ngx_int_t ngx_http_var_exec_get_cookie(ngx_http_request_t *r,
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

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_var_create_loc_conf,          /* create location configuration */
    ngx_http_var_merge_loc_conf            /* merge location configuration */
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


/* Merge configurations */
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


/* "var" directive handler */
static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_conf_t         *vconf = conf;

    ngx_str_t                   *value;
    ngx_uint_t                   cur, last;
    ngx_str_t                    s;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_uint_t                   i, n;
    ngx_http_var_operator_e      op;
    ngx_uint_t                   ignore_case, min_args, max_args;
    ngx_uint_t                   args_count;
    size_t                       ops_count;
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

    op = NGX_HTTP_VAR_OP_UNKNOWN;
    ignore_case = 0;
    filter = NULL;
    negative = 0;

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: invalid number of arguments "
                           "in \"var\" directive");
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 0 || value[1].data == NULL || value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: invalid variable name \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Remove the leading '$' and convert to lowercase */
    ngx_strlow(value[1].data, value[1].data, value[1].len);
    value[1].len--;
    value[1].data++;

    /* Convert to lowercase */
    ngx_strlow(value[2].data, value[2].data, value[2].len);

    /* Map operator string to enum and get argument counts */
    ops_count = sizeof(ngx_http_var_operators) /
                  sizeof(ngx_http_var_operator_enum_t);

    for (i = 0; i < ops_count; i++) {
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

    if (cf->args->nelts > 3 && (ngx_strncmp(value[last].data, "if=", 3) == 0
                             || ngx_strncmp(value[last].data, "if!=", 4) == 0))
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
        last--;

    } else {
        args_count = cf->args->nelts - 3;
    }

    cur = 3;
    if (cur <= last && value[cur].len == 2
        && value[cur].data[0] == '-' && value[cur].data[1] == 'i')
    {
        ignore_case = 1;
        args_count--;
        cur++;
    }

    if (args_count < min_args || args_count > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http var: invalid number of arguments "
                           "for operator \"%V\"", &value[2]);
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

    var->name = value[1];
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
        if (args_count < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http var: regex operators "
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

        /* Compile regex pattern */
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

        /* Compile assign_value */
        if (op != NGX_HTTP_VAR_OP_IF_RE_MATCH) {
            if (args_count != 2) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http var: regex capture and sub "
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

        /* Initialize args array */
        var->args = ngx_array_create(cf->pool, args_count ? args_count : 1,
                                    sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        /* Compile all arguments */
        for (n = 0; n < args_count; n++) {
            cv = ngx_array_push(var->args);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[cur + n];
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

    v = ngx_http_add_variable(cf, &value[1], flags);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler && v->get_handler != ngx_http_var_variable_handler) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "http var: variable \"%V\" already has a handler",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Save variable index to data */
    var->index = ngx_http_get_variable_index(cf, &value[1]);
    v->data = (uintptr_t) &var->index;

    /* Set variable handler */
    v->get_handler = ngx_http_var_variable_handler;

    return NGX_CONF_OK;
}


static ngx_http_var_ctx_t *
ngx_http_var_get_lock_ctx(ngx_http_request_t *r)
{
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_var_ctx_t  *ctx;

    /* Attempt to get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx != NULL) {
        return ctx;
    }

    /* If the context does not exist, create and attach it to the request */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_var_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    /* Initialize the variable lock array, assuming a maximum number of variables */
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

    /* Get or create the context */
    ctx = ngx_http_var_get_lock_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR; /* Context creation failed */
    }

    /* Check if it is already locked */
    if (ctx->locked_vars[index] == 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http var: circular reference detected "
                      "for variable index %ui", index);
        return NGX_ERROR;
    }

    /* Mark the variable as locked */
    ctx->locked_vars[index] = 1;

    return NGX_OK;
}


static void
ngx_http_variable_release_lock(ngx_http_request_t *r, ngx_int_t index)
{
    ngx_http_var_ctx_t       *ctx;

    /* Get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx == NULL) {
        return;
    }

    /* Clear the lock mark */
    ctx->locked_vars[index] = 0;
}


/* Helper function to find variable */
static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r, ngx_int_t index,
    ngx_http_var_conf_t *vconf, ngx_http_var_variable_t **var)
{
    ngx_http_var_variable_t    *vars;
    ngx_uint_t                  i;
    ngx_str_t                   val;

    vars = vconf->vars->elts;

    /* Linear search */
    for (i = 0; i < vconf->vars->nelts; i++) {
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

            /* Found the variable */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http var: variable \"%V\" definition found",
                           &vars[i].name);

            /* Return the found variable */
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

    /* Acquire lock for variable to avoid loopback exception */
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

    case NGX_HTTP_VAR_OP_RE_GSUB:
        rc = ngx_http_var_exec_re_gsub(r, v, var);
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

    case NGX_HTTP_VAR_OP_RAND_RANGE:
        rc = ngx_http_var_exec_rand_range(r, v, var);
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

    case NGX_HTTP_VAR_OP_CRC32_SHORT:
        rc = ngx_http_var_exec_crc32_short(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_CRC32_LONG:
        rc = ngx_http_var_exec_crc32_long(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MD5SUM:
        rc = ngx_http_var_exec_md5sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA1SUM:
        rc = ngx_http_var_exec_sha1sum(r, v, var);
        break;

#if (NGX_HTTP_SSL)
    case NGX_HTTP_VAR_OP_SHA256SUM:
        rc = ngx_http_var_exec_sha256sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA384SUM:
        rc = ngx_http_var_exec_sha384sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SHA512SUM:
        rc = ngx_http_var_exec_sha512sum(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HMAC_SHA1:
        rc = ngx_http_var_exec_hmac_sha1(r, v, var);
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

    case NGX_HTTP_VAR_OP_GET_COOKIE:
        rc = ngx_http_var_exec_get_cookie(r, v, var);
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http var: unknown operator");
        ngx_http_variable_release_lock(r, var->index);
        v->not_found = 1;
        return NGX_ERROR;
    }

    /* Evaluation is complete, release the lock */
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


/* Variable handler */
static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vconf;
    ngx_http_var_variable_t      *var;
    ngx_int_t                     index;
    ngx_int_t                     rc;

    vconf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);

    if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http var: not variable defined by http var module");
        return NGX_DECLINED;
    }

    index = *(ngx_int_t *) data;

    /* Search */
    rc = ngx_http_var_find_variable(r, index, vconf, &var);
    if (rc == NGX_OK) {
        goto found;

    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Variable not found */
    v->not_found = 1;
    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http var: evaluating the expression of variable \"%V\"",
                   &var->name);

    /* Evaluate the variable expression */
    rc = ngx_http_var_evaluate_variable(r, v, var);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_utils_check_str_is_num(ngx_str_t num_str)
{
    ngx_str_t   num_abs_str;
    ngx_int_t   num;
    ngx_uint_t  decimal_places;
    ngx_uint_t  i;

    num_abs_str = num_str;
    decimal_places = 0;

    if (num_abs_str.len > 0 && num_abs_str.data[0] == '-') {
        num_abs_str.data++;
        num_abs_str.len--;
    }

    for (i = 0; i < num_abs_str.len; i++) {
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
ngx_http_var_utils_auto_atoi(ngx_str_t val, ngx_int_t *int_val)
{
    ngx_int_t  is_negative;

    is_negative = 0;

    if (val.len > 0 && val.data[0] == '-') {
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
    ngx_uint_t  decimal_places1, decimal_places2;
    ngx_int_t   is_negative1, is_negative2;
    ngx_uint_t  max_decimal_places;
    ngx_uint_t  i;

    decimal_places1 = 0;
    decimal_places2 = 0;
    is_negative1 = 0;
    is_negative2 = 0;

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

    max_decimal_places = (decimal_places1 > decimal_places2)
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
    ngx_int_t   is_negative1, is_negative2, is_negative3;
    ngx_uint_t  max_decimal_places;
    ngx_uint_t  i;

    decimal_places1 = 0;
    decimal_places2 = 0;
    decimal_places3 = 0;
    is_negative1 = 0;
    is_negative2 = 0;
    is_negative3 = 0;

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

    if (val3.len > 0 && val3.data[0] == '-') {
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

    max_decimal_places = decimal_places1;

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
ngx_http_var_utils_parse_int_range(ngx_str_t str,
    ngx_int_t *start, ngx_int_t *end)
{
    ngx_uint_t i;
    ngx_int_t temp_start, temp_end, is_range;

    temp_start = 0;
    temp_end = 0;
    is_range = 0;

    i = 0;
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
ngx_http_var_utils_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    ngx_uint_t type)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, escaped_str;
    size_t                     len;
    uintptr_t                  escape;
    u_char                    *src, *dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Handle empty source string */
    if (src_str.len == 0) {
        return NGX_ERROR;
    }

    src = src_str.data;

    /* Calculate the escaped length */
    escape = 2 * ngx_escape_uri(NULL, src, src_str.len, type);
    len = src_str.len + escape;

    dst = ngx_pnalloc(r->pool, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    /* Perform the escaping */
    if (escape == 0) {
        ngx_memcpy(dst, src, src_str.len);
    } else {
        ngx_escape_uri(dst, src, src_str.len, type);
    }

    /* Set the escaped string */
    escaped_str.data = dst;
    escaped_str.len = len;

    /* Set the variable value */
    v->len = escaped_str.len;
    v->data = escaped_str.data;

    return NGX_OK;
}


/*
 * Same as ngx_strlcasestrn(), but case-sensitive.
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
ngx_http_var_utils_set_hmac(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var,
    const EVP_MD *evp_md)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, secret_str;
    unsigned int               md_len;
    unsigned char              md[EVP_MAX_MD_SIZE];

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &secret_str) != NGX_OK) {
        return NGX_ERROR;
    }

    md_len = 0;
    HMAC(evp_md, secret_str.data, secret_str.len,
        src_str.data, src_str.len, md, &md_len);

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
    if (val.len > 0) {
        v->data = (u_char *) "1";
    } else {
        v->data = (u_char *) "0";
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
    ngx_str_t                  str, prefix;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &prefix) != NGX_OK) {
        return NGX_ERROR;
    }

    if (prefix.len == 0) {
        v->len = 1;
        v->data = (u_char *) "1";
        return NGX_OK;
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
ngx_http_var_exec_if_ends_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  str, suffix;
    u_char                    *str_end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &suffix) != NGX_OK) {
        return NGX_ERROR;
    }

    if (suffix.len == 0) {
        v->len = 1;
        v->data = (u_char *) "1";
        return NGX_OK;
    }

    v->len = 1;

    if (suffix.len > str.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    str_end = str.data + str.len - suffix.len;

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
ngx_http_var_exec_if_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  str, sub_str;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &sub_str) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = 1;

    if (str.len == 0) {
        if (sub_str.len == 0) {
            v->data = (u_char *) "1";
        } else {
            v->data = (u_char *) "0";
        }
        return NGX_OK;
    }

    if (sub_str.len == 0 || sub_str.len > str.len) {
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    if (var->ignore_case == 1) {
        p = ngx_strlcasestrn(str.data, str.data + str.len,
                sub_str.data, sub_str.len - 1);
    } else {
        p = ngx_http_var_utils_strlstrn(str.data, str.data + str.len,
                sub_str.data, sub_str.len - 1);
    }

    if (p != NULL) {
        v->data = (u_char *) "1";
    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_str_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_uint_t                 i, nelts;

    args = var->args->elts;
    nelts = var->args->nelts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 1; i < nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &val2) != NGX_OK) {
            return NGX_ERROR;
        }

        if (val1.len != val2.len) {
            continue;
        }

        if (var->ignore_case == 1) {
            if (ngx_strncasecmp(val1.data, val2.data, val1.len) == 0) {
                v->data = (u_char *) "1";
                v->len = 1;
                return NGX_OK;
            }

        } else {
            if (ngx_strncmp(val1.data, val2.data, val1.len) == 0) {
                v->data = (u_char *) "1";
                v->len = 1;
                return NGX_OK;
            }
        }
    }

    v->data = (u_char *) "0";
    v->len = 1;
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
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val.data, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *p;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
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
ngx_http_var_exec_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  value_str;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &value_str) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, value_str.data, v->len);

    /* Convert to uppercase */
    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_toupper(v->data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  value_str;
    ngx_uint_t                 i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &value_str) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, value_str.data, v->len);

    /* Convert to lowercase */
    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_tolower(v->data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
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
ngx_http_var_exec_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
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
ngx_http_var_exec_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, trimmed_str;
    u_char                    *start, *end;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
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
ngx_http_var_exec_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, reversed_str;
    u_char                    *p, *q;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    reversed_str.len = src_str.len;
    reversed_str.data = ngx_pnalloc(r->pool, reversed_str.len);
    if (reversed_str.data == NULL) {
        return NGX_ERROR;
    }

    p = reversed_str.data;
    q = src_str.data + src_str.len - 1;

    for ( /* void */ ; q >= src_str.data; q--) {
        *p++ = *q;
    }

    /* Set variable value */
    v->len = reversed_str.len;
    v->data = reversed_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, sub_str;
    u_char                    *p;
    ngx_int_t                  pos;
    u_char                    *buf;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &sub_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (sub_str.len == 0 || src_str.len == 0) {
        /* If sub_str is empty or src_str is empty, return 0 */
        pos = 0;
    } else {
        if (var->ignore_case == 1) {
            p = ngx_strlcasestrn(src_str.data, src_str.data + src_str.len,
                                 sub_str.data, sub_str.len - 1);
        } else {
            p = ngx_http_var_utils_strlstrn(src_str.data,
                    src_str.data + src_str.len, sub_str.data, sub_str.len - 1);
        }

        if (p) {
            /* Position starts from 1 */
            pos = (ngx_int_t)(p - src_str.data) + 1;
        } else {
            pos = 0;
        }
    }

    /* Convert pos to string */
    buf = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(buf, "%i", pos) - buf;
    v->data = buf;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_repeat(ngx_http_request_t *r,
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
        || ngx_http_complex_value(r, &args[1], &repeat_times_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Parse repeat times */
    times = ngx_atoi(repeat_times_str.data, repeat_times_str.len);
    if (times == NGX_ERROR || times < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid repeat times");
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
ngx_http_var_exec_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, start_str, len_str;
    ngx_int_t                  start, len;
    ngx_uint_t                 src_len;

    args = var->args->elts;

    /* Compute arguments */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &start_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Parse start value */
    start = ngx_atoi(start_str.data, start_str.len);
    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid start in substr");
        return NGX_ERROR;
    }

    src_len = src_str.len;

    /* Handle the case where start is beyond the string length */
    if ((ngx_uint_t)start >= src_len) {
        return NGX_ERROR;
    }

    /* Check if len is provided */
    if (var->args->nelts == 3
        && ngx_http_complex_value(r, &args[2], &len_str) == NGX_OK)
    {
        len = ngx_atoi(len_str.data, len_str.len);
        if (len == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid length in substr");
            return NGX_ERROR;
        }

        /* Adjust len if it exceeds the string length */
        if ((ngx_uint_t)(start + len) > src_len) {
            len = src_len - start;
        }
    } else {
        /* Default len to the remaining string length */
        len = src_len - start;
    }

    /* Allocate memory for the substring */
    v->len = len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(v->data, src_str.data + start, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, search_str, replace_str, result_str;
    u_char                    *p, *q;
    size_t                     count, new_len;
    ngx_uint_t                 i;
    ngx_int_t                  rc;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &search_str) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &replace_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (search_str.len == 0) {
        /* Prevent infinite loop */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: search string is empty in replace");
        return NGX_ERROR;
    }

    /* Count occurrences */
    count = 0;
    p = src_str.data;
    for (i = 0; i <= src_str.len - search_str.len; /* void */ ) {
        if (var->ignore_case) {
            rc = ngx_strncasecmp(p + i, search_str.data, search_str.len);
        } else {
            rc = ngx_strncmp(p + i, search_str.data, search_str.len);
        }

        if (rc == 0) {
            count++;
            i += search_str.len;
        } else {
            i++;
        }
    }

    /* No replacements needed */
    if (count == 0) {
        v->len = src_str.len;
        v->data = src_str.data;
        return NGX_OK;
    }

    /* Calculate new length */
    new_len = src_str.len + count * (replace_str.len - search_str.len);

    if (new_len > NGX_MAX_SIZE_T_VALUE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: replacement result too large");
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
        if (i <= src_str.len - search_str.len) {
            if (var->ignore_case) {
                rc = ngx_strncasecmp(p + i, search_str.data, search_str.len);
            } else {
                rc = ngx_strncmp((const char *)(p + i),
                                 (const char *)search_str.data,
                                 search_str.len);
            }

            if (rc == 0) {
                ngx_memcpy(q, replace_str.data, replace_str.len);
                q += replace_str.len;
                i += search_str.len;
                continue;
            }
        }

        *q++ = p[i++];
    }

    result_str.len = q - result_str.data;

    /* Set variable value */
    v->len = result_str.len;
    v->data = result_str.data;

    return NGX_OK;
}


#if (NGX_PCRE)
static ngx_int_t
ngx_http_var_exec_if_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    subject;
    ngx_int_t                    rc;

    args = var->args->elts;

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
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex match failed");
        return NGX_ERROR;
    }

    v->data = (u_char *) "1";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_re_capture(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    subject, assign_value;
    ngx_int_t                    rc;

    args = var->args->elts;

    /* Calculate the value of src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Perform regex match */
    rc = ngx_http_regex_exec(r, var->regex, &subject);
    if (rc == NGX_DECLINED) {
        return NGX_ERROR;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex match failed");
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
ngx_http_var_exec_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    subject, replacement, result;
    ngx_int_t                    rc;
    u_char                      *p;
    ngx_uint_t                   start, end, len;

    args = var->args->elts;

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
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: regex substitution failed");
        return NGX_ERROR;
    }

    /* Ensure captures are available */
    if (r->ncaptures < 2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: insufficient captures");
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
ngx_http_var_exec_re_gsub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject, replacement, result;
    ngx_http_complex_value_t    *args;
    ngx_uint_t                   offset;
    u_char                      *p;
    ngx_int_t                    rc;
    int                         *captures;
    ngx_uint_t                   allocated;
    ngx_uint_t                   required;
    ngx_str_t                    sub;
    u_char                      *new_data;
    int                          match_start, match_end;
    ngx_str_t                    replaced;

    args = var->args->elts;

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

    offset = 0;
    while (offset < subject.len) {
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
                new_data = ngx_pnalloc(r->pool, allocated);
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
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: regex substitution failed");
            return NGX_ERROR;
        }

        /* Retrieve capture group information */
        captures = r->captures;

        /* captures is an array of ints, representing the start and end positions of the capture groups */
        match_start = captures[0];
        match_end = captures[1];

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
    ngx_str_t                  val, range_val;
    ngx_int_t                  src_val, start_val, end_val;
    ngx_str_t                  start_str, end_str;
    u_char                    *dash;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &range_val) != NGX_OK)
    {
        return NGX_ERROR;
    }

    dash = ngx_strlchr(range_val.data, range_val.data + range_val.len, '-');
    if (dash == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_range\" failed to "
                      "parse range, missing '-'");
        return NGX_ERROR;
    }

    start_str.data = range_val.data;
    start_str.len = dash - range_val.data;

    end_str.data = dash + 1;
    end_str.len = range_val.data + range_val.len - (dash + 1);

    if (ngx_http_var_utils_auto_atofp3(val, start_str, end_str,
        &src_val, &start_val, &end_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"if_range\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    v->len = 1;
    if (src_val >= start_val && src_val <= end_val) {
        v->data = (u_char *) "1";
    } else {
        v->data = (u_char *) "0";
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_if_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val1, val2;
    ngx_int_t                  int_val1, int_val2;
    ngx_uint_t                 i, nelts;

    args = var->args->elts;
    nelts = var->args->nelts;

    if (ngx_http_complex_value(r, &args[0], &val1) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 1; i < nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &val2) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: \"if_in\" failed to convert "
                          "values to fixed point");
            /* continue to check the next number */
            continue;
        }

        if (int_val1 == int_val2) {
            v->data = (u_char *) "1";
            v->len = 1;
            return NGX_OK;
        }
    }

    v->data = (u_char *) "0";
    v->len = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_abs(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;

    args = var->args->elts;

    /* Evaluate argument */
    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check if is number */
    if (ngx_http_var_utils_check_str_is_num(num_str) != NGX_OK) {
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
ngx_http_var_exec_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str, val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        return NGX_ERROR;
    }

    val1 = int1_str;
    val2 = int2_str;

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"max\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
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
ngx_http_var_exec_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str, val1, val2;
    ngx_int_t                  int_val1, int_val2;

    args = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK) {
        return NGX_ERROR;
    }

    val1 = int1_str;
    val2 = int2_str;

    if (ngx_http_var_utils_auto_atofp(val1, val2, &int_val1, &int_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: \"min\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
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
ngx_http_var_exec_add(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(int1_str, &int1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(int2_str, &int2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"add\" operator");
        return NGX_ERROR;
    }

    result = int1 + int2;

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
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(int1_str, &int1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(int2_str, &int2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"sub\" operator");
        return NGX_ERROR;
    }

    result = int1 - int2;

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
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(int1_str, &int1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(int2_str, &int2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"mul\" operator");
        return NGX_ERROR;
    }

    result = int1 * int2;

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
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(int1_str, &int1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(int2_str, &int2) != NGX_OK
        || int2 == 0)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"div\" operator");
        return NGX_ERROR;
    }

    result = int1 / int2;

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
    ngx_str_t                  int1_str, int2_str;
    ngx_int_t                  int1, int2, result;
    u_char                    *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &int1_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &int2_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_utils_auto_atoi(int1_str, &int1) != NGX_OK
        || ngx_http_var_utils_auto_atoi(int2_str, &int2) != NGX_OK
        || int2 == 0)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid integer value for \"mod\" operator");
        return NGX_ERROR;
    }

    result = int1 % int2;

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
    ngx_str_t                  num_str, precision_str;
    ngx_int_t                  precision, i, j, decimal_point, len;
    u_char                    *num_data, *result;
    size_t                     num_len;
    u_char                    *new_result;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &precision_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    precision = ngx_atoi(precision_str.data, precision_str.len);
    if (precision == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid precision value for "
                      "\"round\" operator");
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    decimal_point = -1;
    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: input for \"round\" operator must be "
                      "a number");
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
                    new_result = ngx_palloc(r->pool, len + 2);
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
ngx_http_var_exec_floor(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;
    ngx_int_t                  i, decimal_point;
    u_char                    *num_data, *result;
    size_t                     num_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    decimal_point = -1;
    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: input for \"round\" operator must be "
                      "a number");
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
ngx_http_var_exec_ceil(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  num_str;
    ngx_int_t                  i, decimal_point;
    u_char                    *num_data, *result;
    size_t                     num_len;
    u_char                    *new_result;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &num_str) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = num_str.data;
    num_len = num_str.len;

    /* Check if it is a number and find the decimal point */
    if (num_data[0] == '.' || (num_data[0] == '-' && num_data[1] == '.')) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: decimal point cannot "
                      "appear at the beginning");
        return NGX_ERROR;
    }

    decimal_point = -1;
    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (i == 0 && num_data[i] == '-') {
            continue;
        }

        if (num_data[i] == '.') {
            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: illegal decimal point found");
                return NGX_ERROR;
            }
            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: input for \"round\" operator must be "
                      "a number");
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
                        new_result = ngx_palloc(r->pool, decimal_point + 2);
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
ngx_http_var_exec_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    u_char  *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", ngx_random()) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_rand_range(ngx_http_request_t *r,
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
        return NGX_ERROR;
    }

    dash = ngx_strlchr(range_str.data, range_str.data + range_str.len, '-');
    if (dash == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to parse range, missing '-'");
        return NGX_ERROR;
    }

    start_str.data = range_str.data;
    start_str.len = dash - range_str.data;

    end_str.data = dash + 1;
    end_str.len = range_str.data + range_str.len - (dash + 1);

    start = ngx_atoi(start_str.data, start_str.len);
    end = ngx_atoi(end_str.data, end_str.len);

    if (start == NGX_ERROR || end == NGX_ERROR || start > end) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid start or end value for \"rand_range\"");
        return NGX_ERROR;
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
ngx_http_var_exec_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, hex_str;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hex_str.len = src_str.len << 1;
    hex_str.data = ngx_pnalloc(r->pool, hex_str.len);
    if (hex_str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(hex_str.data, src_str.data, src_str.len);

    v->len = hex_str.len;
    v->data = hex_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_hex_decode(ngx_http_request_t *r,
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
        return NGX_ERROR;
    }

    /* Check if the input string is of even length */
    if (hex_str.len % 2 != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: hex_decode requires even-length string");
        return NGX_ERROR;
    }

    /* Allocate memory for the output binary string */
    bin_str.len = hex_str.len >> 1;
    bin_str.data = ngx_pnalloc(r->pool, bin_str.len);
    if (bin_str.data == NULL) {
        return NGX_ERROR;
    }

    /* Convert hex string to binary */
    p = hex_str.data;
    for (i = 0; i < bin_str.len; i++) {
        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid hex character "
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
ngx_http_var_exec_dec_to_hex(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  dec_str;
    ngx_int_t                  dec_value;
    u_char                    *p;
    ngx_flag_t                 negative;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &dec_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Validate if the input is a number */
    if (dec_str.data[0] == '-') {
        negative = 1;
    } else {
        negative = 0;
    }

    dec_value = ngx_atoi(dec_str.data + (negative ? 1 : 0),
                           dec_str.len - (negative ? 1 : 0));
    if (dec_value == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid decimal value for dec_to_hex");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
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
ngx_http_var_exec_hex_to_dec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  hex_str;
    ngx_int_t                  dec_value;
    u_char                    *p;
    ngx_flag_t                 negative;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &hex_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check if the input is negative */
    if (hex_str.data[0] == '-') {
        negative = 1;
    } else {
        negative = 0;
    }

    dec_value = ngx_hextoi(hex_str.data + (negative ? 1 : 0),
                           hex_str.len - (negative ? 1 : 0));
    if (dec_value == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: invalid hexadecimal value for hex_to_dec");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
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
    ngx_str_t                  src_str, unescaped_str;
    size_t                     len;
    u_char                    *p, *src, *dst;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
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
        return NGX_ERROR;
    }

    /* Perform the unescaping */
    src = src_str.data;
    dst = p;
    ngx_unescape_uri(&dst, &src, src_str.len, 0);

    if (src != src_str.data + src_str.len) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: input data not consumed completely "
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
ngx_http_var_exec_base64_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, encoded_str;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    len = ngx_base64_encoded_length(src_str.len);

    encoded_str.data = ngx_pnalloc(r->pool, len);
    if (encoded_str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&encoded_str, &src_str);

    /* Set variable value */
    v->len = encoded_str.len;
    v->data = encoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64url_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, encoded_str;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    len = ngx_base64_encoded_length(src_str.len);

    encoded_str.data = ngx_pnalloc(r->pool, len);
    if (encoded_str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64url(&encoded_str, &src_str);

    /* Set variable value */
    v->len = encoded_str.len;
    v->data = encoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, decoded_str;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    len = ngx_base64_decoded_length(src_str.len);

    decoded_str.data = ngx_pnalloc(r->pool, len);
    if (decoded_str.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded_str, &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to decode base64 string");
        return NGX_ERROR;
    }

    /* Set variable value */
    v->len = decoded_str.len;
    v->data = decoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_base64url_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str, decoded_str;
    size_t                     len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    len = ngx_base64_decoded_length(src_str.len);

    decoded_str.data = ngx_pnalloc(r->pool, len);
    if (decoded_str.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&decoded_str, &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: failed to decode base64url string");
        return NGX_ERROR;
    }

    /* Set variable value */
    v->len = decoded_str.len;
    v->data = decoded_str.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_crc32_short(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    ngx_uint_t                 crc;
    u_char                    *p;

    args = var->args->elts;

    /* Evaluate source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Compute CRC32 */
    crc = ngx_crc32_short(src_str.data, src_str.len);

    /* Allocate buffer for CRC32 result */
    p = ngx_pnalloc(r->pool, 9);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /* Convert CRC32 result to string */
    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_crc32_long(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    ngx_uint_t                 crc;
    u_char                    *p;

    args = var->args->elts;

    /* Evaluate source string */
    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Compute CRC32 */
    crc = ngx_crc32_long(src_str.data, src_str.len);

    /* Allocate buffer for CRC32 result */
    p = ngx_pnalloc(r->pool, 9);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /* Convert CRC32 result to string */
    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_md5sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    ngx_md5_t                  md5;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 32);
    if (hash_data == NULL) {
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
ngx_http_var_exec_sha1sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    ngx_sha1_t                 sha1;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 40);
    if (hash_data == NULL) {
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
ngx_http_var_exec_sha256sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 64);
    if (hash_data == NULL) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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
ngx_http_var_exec_sha384sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 96);
    if (hash_data == NULL) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha384(), NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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
ngx_http_var_exec_sha512sum(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  src_str;
    u_char                    *hash_data;
    EVP_MD_CTX                *md;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        return NGX_ERROR;
    }

    hash_data = ngx_pnalloc(r->pool, 128);
    if (hash_data == NULL) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha512(), NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestUpdate(md, src_str.data, src_str.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DigestFinal_ex(md, hash_data, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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
ngx_http_var_exec_hmac_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_set_hmac(r, v, var, EVP_sha1());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha256(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_set_hmac(r, v, var, EVP_sha256());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha384(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_set_hmac(r, v, var, EVP_sha384());
}


static ngx_int_t
ngx_http_var_exec_hmac_sha512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    return ngx_http_var_utils_set_hmac(r, v, var, EVP_sha512());
}
#endif


static ngx_int_t
ngx_http_var_exec_if_time_range(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  param_str;
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
    struct tm                  tm_copy;

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

    /* parse time range */
    for (i = 0; i < var->args->nelts; i++) {
        if (ngx_http_complex_value(r, &args[i], &param_str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncmp(param_str.data, "year=", 5) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &year_start, &year_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "month=", 6) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 6, param_str.data + 6},
                    &month_start, &month_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "day=", 4) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &day_start, &day_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "wday=", 5) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &wday_start, &wday_end) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "http var: invalid wday range value");
                return NGX_ERROR;
            }

            if (wday_start < 1 || wday_start > 7
                || wday_end < wday_start || wday_end > 7)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "http var: invalid wday range value");
                return NGX_ERROR;
            }

        } else if (ngx_strncmp(param_str.data, "hour=", 5) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 5, param_str.data + 5},
                    &hour_start, &hour_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "min=", 4) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &min_start, &min_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "sec=", 4) == 0) {
            if (ngx_http_var_utils_parse_int_range(
                    (ngx_str_t){param_str.len - 4, param_str.data + 4},
                    &sec_start, &sec_end) != NGX_OK)
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

        } else if (ngx_strncmp(param_str.data, "timezone=", 9) == 0) {
            if (var->args->nelts == 1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "http var: at least one time range "
                    "args must be present");
                return NGX_ERROR;
            }

            if (ngx_strncmp(param_str.data + 9, "gmt", 3) == 0) {
                if (param_str.len == 12) {
                    tz_offset = 0;
                } else if (param_str.len == 17
                    && (param_str.data[12] == '+' 
                        || param_str.data[12] == '-'))
                {
                    for (j = 13; j < 17; j++) {
                        if (param_str.data[j] < '0'
                            || param_str.data[j] > '9')
                        {
                            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                "http var: invalid timezone offset value");
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
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            } else {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "http var: invalid timezone format");
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
            && (tm_copy.tm_sec < sec_start || tm_copy.tm_sec > sec_end)))
    {
        v->len = 1;
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char *) "1";

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_gmt_time(ngx_http_request_t *r,
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
            return NGX_ERROR;
        }

        ts = ngx_atoi(ts_str.data, ts_str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid unix_time value for "
                          "\"gmt_time\"");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        /* One argument: date format, use current time */
        if (ngx_http_complex_value(r, &args[0], &date_format) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();
    }

    if (ngx_strcmp(date_format.data, "http_time") == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, ts)- p;
        v->data = p;

        return NGX_OK;
    }
  
    if (ngx_strcmp(date_format.data, "cookie_time") == 0) {
        p = ngx_pnalloc(r->pool, sizeof("Thu, 18-Nov-10 11:27:35 GMT") - 1);
        if (p == NULL) {
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
        return NGX_ERROR;
    }

    v->len = strftime((char *) p, 256,
                      (char *) date_format.data, &tm);

    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: strftime failed for \"gmt_time\"");
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_local_time(ngx_http_request_t *r,
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
            return NGX_ERROR;
        }

        ts = ngx_atoi(ts_str.data, ts_str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid unix_time value "
                          "for \"local_time\" operator");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        /* One argument: date format, use current time */
        if (ngx_http_complex_value(r, &args[0], &date_format) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();
    }

    ngx_libc_localtime(ts, &tm);

    /* Allocate extra space for formatting */
    p = ngx_palloc(r->pool, 256);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = strftime((char *) p, 256,
                      (char *) date_format.data, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: strftime failed for "
                      "\"local_time\" operator");
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_exec_unix_time(ngx_http_request_t *r,
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
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http var: illegal number of parameters for "
                      "\"unix_time\"");
        return NGX_ERROR;
    }

    /* Two arguments: http date string, http_time */
    if (ngx_http_complex_value(r, &args[0], &date_str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &date_format) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_strcmp(date_format.data, "http_time") == 0) {
        unix_time = ngx_parse_http_time(date_str.data, date_str.len);
        if (unix_time == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: failed to parse http_time for "
                          "\"unix_time\"");
            return NGX_ERROR;
        }
        goto set_unix_time;
    }

    /* Third argument: timezone */
    if (var->args->nelts == 3) {
        if (ngx_http_complex_value(r, &args[2], &tz_str) != NGX_OK) {
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
                        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "http var: invalid timezone offset value");
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
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "http var: invalid timezone format for "
                              "\"unix_time\" operator");
                return NGX_ERROR;
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "http var: invalid timezone format for "
                          "\"unix_time\" operator");
            return NGX_ERROR;
        }
    }

    /* Parse the date string */
    ngx_memzero(&tm, sizeof(ngx_tm_t));
    if (strptime((char *) date_str.data,
        (char *) date_format.data, &tm) == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http var: failed to parse date string for "
                        "\"unix_time\" operator");
        return NGX_ERROR;
    }

    /* Convert to unix_time */
    unix_time = timegm(&tm) - tz_offset;

set_unix_time:

    /* Convert unix_time to string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", unix_time) - p;
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


static ngx_int_t
ngx_http_var_exec_get_cookie(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  cookie_name, cookie_value;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &cookie_name) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                          &cookie_name, &cookie_value)
        == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = cookie_value.len;
    v->data = cookie_value.data;
}