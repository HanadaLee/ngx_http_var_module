
/*
 * Copyright (c) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef enum {
    NGX_HTTP_VAR_OP_COPY,
    NGX_HTTP_VAR_OP_UPPER,
    NGX_HTTP_VAR_OP_LOWER,
    NGX_HTTP_VAR_OP_MAX,
    NGX_HTTP_VAR_OP_MIN,
    NGX_HTTP_VAR_OP_LEN,
    NGX_HTTP_VAR_OP_TRIM,
    NGX_HTTP_VAR_OP_LTRIM,
    NGX_HTTP_VAR_OP_RTRIM,
    NGX_HTTP_VAR_OP_REVERSE,
    NGX_HTTP_VAR_OP_POSITION,
    NGX_HTTP_VAR_OP_REPEAT,
    NGX_HTTP_VAR_OP_SUBSTR,
    NGX_HTTP_VAR_OP_REPLACE,
    NGX_HTTP_VAR_OP_HEX_ENCODE,
    NGX_HTTP_VAR_OP_HEX_DECODE,
    NGX_HTTP_VAR_OP_ESCAPE_URI,
    NGX_HTTP_VAR_OP_ESCAPE_ARGS,
    NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT,
    NGX_HTTP_VAR_OP_UNESCAPE_URI,

#if (NGX_PCRE)
    NGX_HTTP_VAR_OP_RE_MATCH,
    NGX_HTTP_VAR_OP_RE_SUB,
    NGX_HTTP_VAR_OP_RE_GSUB,
#endif

    NGX_HTTP_VAR_OP_RAND,

    NGX_HTTP_VAR_OP_UNKNOWN
} ngx_http_var_operator_e;


typedef struct {
    ngx_array_t                *vars;        /* array of ngx_http_var_variable_t */
} ngx_http_var_conf_t;


typedef struct {
    ngx_str_t                   name;        /* variable name */
    ngx_http_var_operator_e     operator;    /* operator type */
    ngx_array_t                *args;        /* array of ngx_http_complex_value_t */

#if (NGX_PCRE)
    ngx_http_regex_t           *regex;       /* compiled regex */
    void                       *value;       /* regex value */
#endif
} ngx_http_var_variable_t;


typedef struct {
    ngx_str_t                   name;        /* operator string */
    ngx_http_var_operator_e     op;          /* operator enum */
    ngx_uint_t                  ignore_case; /* ignore case for regex */
    ngx_uint_t                  min_args;    /* minimum number of arguments */
    ngx_uint_t                  max_args;    /* maximum number of arguments */
} ngx_http_var_operator_mapping_t;


static ngx_http_var_operator_mapping_t ngx_http_var_operators[] = {
    { ngx_string("copy"),         NGX_HTTP_VAR_OP_COPY,         0, 1, 1 },
    { ngx_string("upper"),        NGX_HTTP_VAR_OP_UPPER,        0, 1, 1 },
    { ngx_string("lower"),        NGX_HTTP_VAR_OP_LOWER,        0, 1, 1 },
    { ngx_string("max"),          NGX_HTTP_VAR_OP_MAX,          0, 2, 2 },
    { ngx_string("min"),          NGX_HTTP_VAR_OP_MIN,          0, 2, 2 },
    { ngx_string("len"),          NGX_HTTP_VAR_OP_LEN,          0, 1, 1 },
    { ngx_string("trim"),         NGX_HTTP_VAR_OP_TRIM,         0, 1, 1 },
    { ngx_string("ltrim"),        NGX_HTTP_VAR_OP_LTRIM,        0, 1, 1 },
    { ngx_string("rtrim"),        NGX_HTTP_VAR_OP_RTRIM,        0, 1, 1 },
    { ngx_string("reverse"),      NGX_HTTP_VAR_OP_REVERSE,      0, 1, 1 },
    { ngx_string("position"),     NGX_HTTP_VAR_OP_POSITION,     0, 2, 2 },
    { ngx_string("repeat"),       NGX_HTTP_VAR_OP_REPEAT,       0, 2, 2 },
    { ngx_string("substr"),       NGX_HTTP_VAR_OP_SUBSTR,       0, 3, 3 },
    { ngx_string("replace"),       NGX_HTTP_VAR_OP_REPLACE,     0, 3, 3 },
    { ngx_string("hex_encode"),   NGX_HTTP_VAR_OP_HEX_ENCODE,   0, 1, 1 },
    { ngx_string("hex_decode"),   NGX_HTTP_VAR_OP_HEX_DECODE,   0, 1, 1 },
    { ngx_string("escape_uri"),   NGX_HTTP_VAR_OP_ESCAPE_URI,   0, 1, 1 },
    { ngx_string("escape_args"),  NGX_HTTP_VAR_OP_ESCAPE_ARGS,  0, 1, 1 },
    { ngx_string("escape_uri_component"),
                          NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT, 0, 1, 1 },
    { ngx_string("unescape_uri"), NGX_HTTP_VAR_OP_UNESCAPE_URI, 0, 1, 1 },

#if (NGX_PCRE)
    { ngx_string("re_match"),     NGX_HTTP_VAR_OP_RE_MATCH,     0, 3, 3 },
    { ngx_string("re_match_i"),   NGX_HTTP_VAR_OP_RE_MATCH,     1, 3, 3 },
    { ngx_string("re_sub"),       NGX_HTTP_VAR_OP_RE_SUB,       0, 3, 3 },
    { ngx_string("re_sub_i"),     NGX_HTTP_VAR_OP_RE_SUB,       1, 3, 3 },
    { ngx_string("re_gsub"),      NGX_HTTP_VAR_OP_RE_GSUB,      0, 3, 3 },
    { ngx_string("re_gsub_i"),    NGX_HTTP_VAR_OP_RE_GSUB,      1, 3, 3 },
#endif

    { ngx_string("rand"),         NGX_HTTP_VAR_OP_RAND,       0, 0, 0 }
};


static void *ngx_http_var_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_var_create_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_find_variable(ngx_http_request_t *r,
    ngx_str_t *var_name, ngx_http_var_conf_t *vconf,
    ngx_log_t *log, const char *conf_level,
    ngx_http_var_variable_t **found_var);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_var_variable_expr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

static ngx_int_t ngx_http_var_operate_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_position(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_escape_uri_component(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_operate_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_re_gsub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

static ngx_int_t ngx_http_var_operate_rand(ngx_http_request_t *r,
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

    ngx_http_var_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_var_create_srv_conf,          /* create server configuration */
    ngx_http_var_merge_conf,               /* merge server configuration */

    ngx_http_var_create_loc_conf,          /* create location configuration */
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


/* Create main configuration */
static void *
ngx_http_var_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


/* Create server configuration */
static void *
ngx_http_var_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


/* Create location configuration */
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
    ngx_str_t                    var_name, operator_str, regex_pattern;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_uint_t                   i, n;
    ngx_http_var_operator_e      op = NGX_HTTP_VAR_OP_UNKNOWN;
    ngx_uint_t                   ignore_case = 0, min_args = 0, max_args = 0;
    ngx_uint_t                   args_count;
    size_t                       operators_count;

    value = cf->args->elts;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments in \"var\" directive");
        return NGX_CONF_ERROR;
    }

    var_name = value[1];
    operator_str = value[2];

    if (var_name.len == 0 || var_name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &var_name);
        return NGX_CONF_ERROR;
    }

    /* Remove the leading '$' from variable name */
    var_name.len--;
    var_name.data++;

    /* Map operator string to enum and get argument counts */
    operators_count = sizeof(ngx_http_var_operators) / 
                  sizeof(ngx_http_var_operator_mapping_t);
    for (i = 0; i < operators_count; i++) {
        if (operator_str.len == ngx_http_var_operators[i].name.len &&
            ngx_strncmp(operator_str.data,
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
                           "unsupported operator \"%V\"", &operator_str);
        return NGX_CONF_ERROR;
    }

    args_count = cf->args->nelts - 3;

    if (args_count < min_args || args_count > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments for operator \"%V\"",
                           &operator_str);
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

#if (NGX_PCRE)
    if (op == NGX_HTTP_VAR_OP_RE_MATCH
        || op == NGX_HTTP_VAR_OP_RE_SUB
        || op == NGX_HTTP_VAR_OP_RE_GSUB)
    {
        /* Regex operators requires 3 parameters：src_string, regex_pattern, assign_value */
        if (args_count != 3) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "re_match operator requires 3 arguments");
            return NGX_CONF_ERROR;
        }

        /* Compile src_string (complex variable) */
        var->args = ngx_array_create(cf->pool, 1,
            sizeof(ngx_http_complex_value_t));
        if (var->args == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_http_complex_value_t *cv_src;
        ngx_http_compile_complex_value_t ccv;

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

        /* Get regex pattern */
        regex_pattern = value[4];

        /* Compile assign_value */
        var->value = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (var->value == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[5];
        ccv.complex_value = var->value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Compile regex pattern */
        ngx_regex_compile_t        rc;
        u_char                     errstr[NGX_MAX_CONF_ERRSTR];

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

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
            ngx_http_compile_complex_value_t   ccv;

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
                           "variable \"%V\" already has a handler",
                           &var_name);
    }

    return NGX_CONF_OK;
}


/* Helper function to find variable */
static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r, ngx_str_t *var_name,
    ngx_http_var_conf_t *vconf, ngx_log_t *log, const char *conf_level,
    ngx_http_var_variable_t **found_var)
{
    ngx_http_var_variable_t      *vars;
    ngx_uint_t                    n;
    ngx_int_t                     i;

    if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http_var: searching in %s conf", conf_level);

    vars = vconf->vars->elts;
    n = vconf->vars->nelts;

    /* Linear search */
    for (i = 0; i < (ngx_int_t) n; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http_var: checking variable \"%V\" in %s conf",
                       &vars[i].name, conf_level);

        if (vars[i].name.len == var_name->len &&
            ngx_strncmp(vars[i].name.data, var_name->data, var_name->len) == 0)
        {
            /* Found the variable */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http_var: variable found in %s conf", conf_level);

            /* Return the found variable */
            *found_var = &vars[i];

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* Variable handler */
static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vconf;
    ngx_str_t                     var_name;
    ngx_log_t                    *log = r->connection->log;
    ngx_str_t                    *var_name_ptr;
    ngx_int_t                     rc;
    ngx_http_var_variable_t      *found_var = NULL;

    /* Get variable name from data */
    var_name_ptr = (ngx_str_t *) data;
    var_name.len = var_name_ptr->len;
    var_name.data = var_name_ptr->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http_var: handling variable \"$%V\"", &var_name);

    /* Search in location conf */
    vconf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log,
        "location", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in server conf */
    vconf = ngx_http_get_module_srv_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log,
        "server", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in main conf */
    vconf = ngx_http_get_module_main_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log,
        "main", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Variable not found */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http_var: variable \"$%V\" not found", &var_name);

    v->not_found = 1;
    return NGX_OK;

found:

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    /* Evaluate the variable expression */
    rc = ngx_http_var_variable_expr(r, v, found_var);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Expression evaluation function */
static ngx_int_t
ngx_http_var_variable_expr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_int_t rc;

    switch (var->operator) {
    case NGX_HTTP_VAR_OP_COPY:
        rc = ngx_http_var_operate_copy(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_UPPER:
        rc = ngx_http_var_operate_upper(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LOWER:
        rc = ngx_http_var_operate_lower(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MAX:
        rc = ngx_http_var_operate_max(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_MIN:
        rc = ngx_http_var_operate_min(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LEN:
        rc = ngx_http_var_operate_len(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_TRIM:
        rc = ngx_http_var_operate_trim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_LTRIM:
        rc = ngx_http_var_operate_ltrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RTRIM:
        rc = ngx_http_var_operate_rtrim(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REVERSE:
        rc = ngx_http_var_operate_reverse(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_POSITION:
        rc = ngx_http_var_operate_position(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPEAT:
        rc = ngx_http_var_operate_repeat(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_SUBSTR:
        rc = ngx_http_var_operate_substr(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_REPLACE:
        rc = ngx_http_var_operate_replace(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_HEX_ENCODE:
        rc = ngx_http_var_operate_hex_encode(r, v, var);
        break;
    
    case NGX_HTTP_VAR_OP_HEX_DECODE:
        rc = ngx_http_var_operate_hex_decode(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI:
        rc = ngx_http_var_operate_escape_uri(r, v, var);
        break;
    
    case NGX_HTTP_VAR_OP_ESCAPE_ARGS:
        rc = ngx_http_var_operate_escape_args(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_ESCAPE_URI_COMPONENT:
        rc = ngx_http_var_operate_escape_uri_component(r, v, var);
        break;
    
    case NGX_HTTP_VAR_OP_UNESCAPE_URI:
        rc = ngx_http_var_operate_unescape_uri(r, v, var);
        break;

#if (NGX_PCRE)
    case NGX_HTTP_VAR_OP_RE_MATCH:
        rc = ngx_http_var_operate_re_match(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_SUB:
        rc = ngx_http_var_operate_re_sub(r, v, var);
        break;

    case NGX_HTTP_VAR_OP_RE_GSUB:
        rc = ngx_http_var_operate_re_gsub(r, v, var);
        break;
#endif

    case NGX_HTTP_VAR_OP_RAND:
        rc = ngx_http_var_operate_rand(r, v, var);
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: unknown operator");
        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_var_operate_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;
    ngx_http_complex_value_t *cv;

    cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute variable value");
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

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;
    ngx_http_complex_value_t *cv;

    cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
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
ngx_http_var_operate_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;
    ngx_http_complex_value_t *cv;

    cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
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
ngx_http_var_operate_max(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t *cvp;
    ngx_str_t                 arg_str1, arg_str2;
    ngx_int_t                 num1, num2, max;

    cvp = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &cvp[0], &arg_str1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &cvp[1], &arg_str2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute second argument");
        return NGX_ERROR;
    }

    /* Convert arguments to integers */
    num1 = ngx_atoi(arg_str1.data, arg_str1.len);
    if (num1 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid number \"%V\"", &arg_str1);
        return NGX_ERROR;
    }

    num2 = ngx_atoi(arg_str2.data, arg_str2.len);
    if (num2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid number \"%V\"", &arg_str2);
        return NGX_ERROR;
    }

    /* Compute max */
    max = (num1 > num2) ? num1 : num2;

    /* Convert result to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", max) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_min(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_http_complex_value_t *cvp;
    ngx_str_t                 arg_str1, arg_str2;
    ngx_int_t                 num1, num2, min;

    cvp = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &cvp[0], &arg_str1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &cvp[1], &arg_str2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute second argument");
        return NGX_ERROR;
    }

    /* Convert arguments to integers */
    num1 = ngx_atoi(arg_str1.data, arg_str1.len);
    if (num1 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid number \"%V\"", &arg_str1);
        return NGX_ERROR;
    }

    num2 = ngx_atoi(arg_str2.data, arg_str2.len);
    if (num2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid number \"%V\"", &arg_str2);
        return NGX_ERROR;
    }

    /* Compute min */
    min = (num1 < num2) ? num1 : num2;

    /* Convert result to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", min) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str;
    ngx_http_complex_value_t  *args;
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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_trim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, trimmed_str;
    ngx_http_complex_value_t *args;
    u_char                   *start, *end;

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
    while (start <= end && ngx_isspace(*start)) {
        start++;
    }

    /* Trim right */
    while (end >= start && ngx_isspace(*end)) {
        end--;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_ltrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, trimmed_str;
    ngx_http_complex_value_t *args;
    u_char                   *start, *end;

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
    while (start <= end && ngx_isspace(*start)) {
        start++;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_rtrim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, trimmed_str;
    ngx_http_complex_value_t *args;
    u_char                   *start, *end;

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
    while (end >= start && ngx_isspace(*end)) {
        end--;
    }

    trimmed_str.data = start;
    trimmed_str.len = end >= start ? (size_t)(end - start + 1) : 0;

    /* Set variable value */
    v->len = trimmed_str.len;
    v->data = trimmed_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_reverse(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, reversed_str;
    ngx_http_complex_value_t *args;
    u_char                   *p, *q;

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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_position(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, sub_str;
    ngx_http_complex_value_t *args;
    u_char                   *p;
    ngx_int_t                 pos = 0;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[1], &sub_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for position operator");
        return NGX_ERROR;
    }

    if (sub_str.len == 0 || src_str.len == 0) {
        /* If sub_str is empty or src_str is empty, return 0 */
        pos = 0;
    } else {
        p = ngx_strnstr(src_str.data, (char *)sub_str.data, src_str.len);
        if (p) {
            pos = (ngx_int_t)(p - src_str.data) + 1; /* Position starts from 1 */
        } else {
            pos = 0;
        }
    }

    /* Convert position to string */
    u_char *buf = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(buf, "%i", pos) - buf;
    v->data = buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_repeat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str;
    ngx_http_complex_value_t *args;
    ngx_int_t                 times;
    size_t                    total_len;
    u_char                   *p;
    ngx_uint_t                i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[1], &v[1]) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for repeat operator");
        return NGX_ERROR;
    }

    times = ngx_atoi(v[1].data, v[1].len);
    if (times == NGX_ERROR || times < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid repeat times");
        return NGX_ERROR;
    }

    total_len = src_str.len * times;
    p = ngx_pnalloc(r->pool, total_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_uint_t)times; i++) {
        ngx_memcpy(p + i * src_str.len, src_str.data, src_str.len);
    }

    /* Set variable value */
    v->len = total_len;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_substr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str;
    ngx_http_complex_value_t *args;
    ngx_int_t                 start, len;
    ngx_uint_t                src_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[1], &v[1]) != NGX_OK ||
        ngx_http_complex_value(r, &args[2], &v[2]) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute arguments "
                      "for substr operator");
        return NGX_ERROR;
    }

    start = ngx_atoi(v[1].data, v[1].len);
    len = ngx_atoi(v[2].data, v[2].len);

    if (start == NGX_ERROR || len == NGX_ERROR || start < 0 || len < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid start or length in substr");
        return NGX_ERROR;
    }

    src_len = src_str.len;

    if ((ngx_uint_t)start >= src_len) {
        /* Start is beyond the string length */
        v->len = 0;
        v->data = (u_char *)"";
    } else {
        if ((ngx_uint_t)(start + len) > src_len) {
            len = src_len - start;
        }
        v->len = len;
        v->data = src_str.data + start;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_replace(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                 src_str, search_str, replace_str, result_str;
    ngx_http_complex_value_t *args;
    u_char                   *p, *q;
    size_t                    count = 0, new_len;
    ngx_uint_t                i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[1], &search_str) != NGX_OK ||
        ngx_http_complex_value(r, &args[2], &replace_str) != NGX_OK) {
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
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
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
        if (i <= src_str.len - search_str.len &&
            ngx_strncmp(p + i, search_str.data, search_str.len) == 0) {
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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_hex_encode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str, hex_str;
    ngx_http_complex_value_t  *args;

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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_hex_decode(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  hex_str, bin_str;
    ngx_http_complex_value_t  *args;
    u_char                     c1, c2, *p;
    size_t                     i;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &hex_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for hex_decode operator");
        return NGX_ERROR;
    }

    if (hex_str.len % 2 != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: hex_decode requires even-length string");
        return NGX_ERROR;
    }

    bin_str.len = hex_str.len >> 1;
    bin_str.data = ngx_pnalloc(r->pool, bin_str.len);
    if (bin_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for hex_decode");
        return NGX_ERROR;
    }

    p = hex_str.data;
    for (i = 0; i < bin_str.len; i++) {
        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_var: invalid hex character in hex_decode");
            return NGX_ERROR;
        }

        p += 2;
        bin_str.data[i] = (u_char) n;
    }

    v->len = bin_str.len;
    v->data = bin_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_escape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str, escaped_str;
    ngx_http_complex_value_t  *args;
    size_t                     escaped_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument "
                      "for escape_uri operator");
        return NGX_ERROR;
    }

    escaped_len = ngx_escape_uri(NULL, src_str.data, src_str.len,
                                 NGX_ESCAPE_URI);

    escaped_str.len = escaped_len;
    escaped_str.data = ngx_pnalloc(r->pool, escaped_str.len);
    if (escaped_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for escape_uri");
        return NGX_ERROR;
    }

    ngx_escape_uri(escaped_str.data, src_str.data, src_str.len,
                   NGX_ESCAPE_URI);

    v->len = escaped_str.len;
    v->data = escaped_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_escape_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str, escaped_str;
    ngx_http_complex_value_t  *args;
    size_t                     escaped_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "escape_args operator");
        return NGX_ERROR;
    }

    escaped_len = ngx_escape_uri(NULL, src_str.data, src_str.len,
                                 NGX_ESCAPE_ARGS);

    escaped_str.len = escaped_len;
    escaped_str.data = ngx_pnalloc(r->pool, escaped_str.len);
    if (escaped_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for escape_args");
        return NGX_ERROR;
    }

    ngx_escape_uri(escaped_str.data, src_str.data, src_str.len,
                   NGX_ESCAPE_ARGS);

    v->len = escaped_str.len;
    v->data = escaped_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_escape_uri_component(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str, escaped_str;
    ngx_http_complex_value_t  *args;
    size_t                     escaped_len;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "escape_uri_component operator");
        return NGX_ERROR;
    }

    escaped_len = ngx_escape_uri(NULL, src_str.data, src_str.len,
                                 NGX_ESCAPE_URI_COMPONENT);

    escaped_str.len = escaped_len;
    escaped_str.data = ngx_pnalloc(r->pool, escaped_str.len);
    if (escaped_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for "
                      "escape_uri_component");
        return NGX_ERROR;
    }

    ngx_escape_uri(escaped_str.data, src_str.data, src_str.len,
                   NGX_ESCAPE_URI_COMPONENT);

    v->len = escaped_str.len;
    v->data = escaped_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_unescape_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                  src_str, unescaped_str;
    ngx_http_complex_value_t  *args;
    size_t                     unescaped_len;
    u_char                     *p;

    args = var->args->elts;

    if (ngx_http_complex_value(r, &args[0], &src_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: failed to compute argument for "
                      "unescape_uri operator");
        return NGX_ERROR;
    }

    unescaped_len = ngx_unescape_uri(NULL, src_str.data, src_str.len, 0);

    if (unescaped_len == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid URI encoding in unescape_uri");
        return NGX_ERROR;
    }

    unescaped_str.len = unescaped_len;
    unescaped_str.data = ngx_pnalloc(r->pool, unescaped_str.len);
    if (unescaped_str.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: memory allocation failed for unescape_uri");
        return NGX_ERROR;
    }

    p = ngx_unescape_uri(unescaped_str.data, src_str.data, src_str.len, 0);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: invalid URI encoding in unescape_uri");
        return NGX_ERROR;
    }

    v->len = unescaped_str.len;
    v->data = unescaped_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


#if (NGX_PCRE)
static ngx_int_t
ngx_http_var_operate_re_match(ngx_http_request_t *r,
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
        v->not_found = 1;
        return NGX_OK;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_var: regex match failed");
        return NGX_ERROR;
    }

    /* Calculate the value of assign_value */
    if (ngx_http_complex_value(r, var->value, &assign_value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Set the variable value */
    v->len = assign_value.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, assign_value.data, v->len);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_re_sub(ngx_http_request_t *r,
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
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
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
    if (ngx_http_complex_value(r, var->value, &replacement) != NGX_OK) {
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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_operate_re_gsub(ngx_http_request_t *r,
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
    if (ngx_http_complex_value(r, var->value, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Initialize the result string, initially allocate 2 times the original length */
    allocated = subject.len * 2;
    if (allocated < 256) {  /* Set a smaller initial buffer limit to avoid excessive allocation for very small strings */
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
        if (ngx_http_complex_value(r, var->value, &replaced) != NGX_OK) {
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
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_var_operate_rand(ngx_http_request_t *r,
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
