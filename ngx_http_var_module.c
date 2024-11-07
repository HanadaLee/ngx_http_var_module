#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef enum {
    NGX_HTTP_VAR_OP_COPY,
    NGX_HTTP_VAR_OP_UPPER,
    NGX_HTTP_VAR_OP_LOWER,
    NGX_HTTP_VAR_OP_MAX,
    NGX_HTTP_VAR_OP_MIN,
    NGX_HTTP_VAR_OP_RAND,
    NGX_HTTP_VAR_OP_RE_MATCH,
    NGX_HTTP_VAR_OP_RE_SUB,
    NGX_HTTP_VAR_OP_RE_GSUB,
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
    { ngx_string("copy"),       NGX_HTTP_VAR_OP_COPY,     0, 1, 1 },
    { ngx_string("upper"),      NGX_HTTP_VAR_OP_UPPER,    0, 1, 1 },
    { ngx_string("lower"),      NGX_HTTP_VAR_OP_LOWER,    0, 1, 1 },
    { ngx_string("max"),        NGX_HTTP_VAR_OP_MAX,      0, 2, 2 },
    { ngx_string("min"),        NGX_HTTP_VAR_OP_MIN,      0, 2, 2 },

#if (NGX_PCRE)
    { ngx_string("re_match"),   NGX_HTTP_VAR_OP_RE_MATCH, 0, 3, 3 },
    { ngx_string("re_match_i"), NGX_HTTP_VAR_OP_RE_MATCH, 1, 3, 3 },
    { ngx_string("re_sub"),     NGX_HTTP_VAR_OP_RE_SUB,   0, 3, 3 },
    { ngx_string("re_sub_i"),   NGX_HTTP_VAR_OP_RE_SUB,   1, 3, 3 },
    { ngx_string("re_gsub"),    NGX_HTTP_VAR_OP_RE_GSUB,  0, 3, 3 },
    { ngx_string("re_gsub_i"),  NGX_HTTP_VAR_OP_RE_GSUB,  1, 3, 3 },
#endif

    { ngx_string("rand"),       NGX_HTTP_VAR_OP_RAND,     0, 0, 0 }
};

static void *ngx_http_var_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_find_variable(ngx_http_request_t *r, ngx_str_t *var_name,
                           ngx_http_var_conf_t *vconf,
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
static ngx_int_t ngx_http_var_operate_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_operate_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_re_sub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
static ngx_int_t ngx_http_var_operate_re_gsub(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var);
#endif

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
    NULL,                     /* postconfiguration */

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

        ngx_memcpy(var, prev->vars->elts, prev->vars->nelts * sizeof(ngx_http_var_variable_t));
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
    for (i = 0; i < sizeof(ngx_http_var_operators) / sizeof(ngx_http_var_operator_mapping_t); i++) {
        if (operator_str.len == ngx_http_var_operators[i].name.len &&
            ngx_strncmp(operator_str.data, ngx_http_var_operators[i].name.data, operator_str.len) == 0)
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
                           "invalid number of arguments for operator \"%V\"", &operator_str);
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
    if (op == NGX_HTTP_VAR_OP_RE_MATCH || op == NGX_HTTP_VAR_OP_RE_SUB || op == NGX_HTTP_VAR_OP_RE_GSUB) {
        /* re_match 操作符需要 3 个参数：src_string, regex_pattern, assign_value */
        if (args_count != 3) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "re_match operator requires 3 arguments");
            return NGX_CONF_ERROR;
        }

        /* 编译 src_string（复杂变量） */
        var->args = ngx_array_create(cf->pool, 1, sizeof(ngx_http_complex_value_t));
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

        /* 获取正则表达式 */
        regex_pattern = value[4];

        /* 编译目标值（assign_value） */
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

        /* 编译正则表达式 */
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

    if (v->get_handler == NULL || v->get_handler == ngx_http_var_variable_handler) {
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
                           "variable \"%V\" already has a handler", &var_name);
    }

    return NGX_CONF_OK;
}

/* Helper function to find variable */
static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r, ngx_str_t *var_name,
                           ngx_http_var_conf_t *vconf,
                           ngx_log_t *log, const char *conf_level,
                           ngx_http_var_variable_t **found_var)
{
    ngx_http_var_variable_t      *vars;
    ngx_uint_t                    n;
    ngx_int_t                     i;

    if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ngx_http_var_module: searching in %s conf", conf_level);

    vars = vconf->vars->elts;
    n = vconf->vars->nelts;

    /* Linear search */
    for (i = 0; i < (ngx_int_t) n; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "ngx_http_var_module: checking variable \"%V\" in %s conf",
                       &vars[i].name, conf_level);

        if (vars[i].name.len == var_name->len &&
            ngx_strncmp(vars[i].name.data, var_name->data, var_name->len) == 0)
        {
            /* Found the variable */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "ngx_http_var_module: variable found in %s conf", conf_level);

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
                   "ngx_http_var_module: handling variable \"$%V\"", &var_name);

    /* Search in location conf */
    vconf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log, "location", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in server conf */
    vconf = ngx_http_get_module_srv_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log, "server", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in main conf */
    vconf = ngx_http_get_module_main_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, log, "main", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Variable not found */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ngx_http_var_module: variable \"$%V\" not found", &var_name);

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

    case NGX_HTTP_VAR_OP_RAND:
        rc = ngx_http_var_operate_rand(r, v, var);
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

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: unknown operator");
        return NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_http_var_operate_copy(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;

    if (var->args->nelts != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: invalid number of arguments for copy operator");
        return NGX_ERROR;
    }

    ngx_http_complex_value_t *cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute variable value");
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, value_str.data, v->len);

    return NGX_OK;
}

/* Uppercase operation */
static ngx_int_t
ngx_http_var_operate_upper(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;
    ngx_http_complex_value_t *cv;

    if (var->args->nelts != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: upper operator requires exactly one argument");
        return NGX_ERROR;
    }

    cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute argument for upper operator");
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
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

/* Lowercase operation */
static ngx_int_t
ngx_http_var_operate_lower(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t value_str;
    ngx_http_complex_value_t *cv;

    if (var->args->nelts != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: lower operator requires exactly one argument");
        return NGX_ERROR;
    }

    cv = (ngx_http_complex_value_t *) var->args->elts;

    if (ngx_http_complex_value(r, &cv[0], &value_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute argument for lower operator");
        return NGX_ERROR;
    }

    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
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

    if (var->args->nelts != 2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: max operator requires exactly two arguments");
        return NGX_ERROR;
    }

    cvp = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &cvp[0], &arg_str1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &cvp[1], &arg_str2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute second argument");
        return NGX_ERROR;
    }

    /* Convert arguments to integers */
    num1 = ngx_atoi(arg_str1.data, arg_str1.len);
    if (num1 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: invalid number \"%V\"", &arg_str1);
        return NGX_ERROR;
    }

    num2 = ngx_atoi(arg_str2.data, arg_str2.len);
    if (num2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: invalid number \"%V\"", &arg_str2);
        return NGX_ERROR;
    }

    /* Compute max */
    max = (num1 > num2) ? num1 : num2;

    /* Convert result to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
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

    if (var->args->nelts != 2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: min operator requires exactly two arguments");
        return NGX_ERROR;
    }

    cvp = var->args->elts;

    /* Evaluate first argument */
    if (ngx_http_complex_value(r, &cvp[0], &arg_str1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute first argument");
        return NGX_ERROR;
    }

    /* Evaluate second argument */
    if (ngx_http_complex_value(r, &cvp[1], &arg_str2) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: failed to compute second argument");
        return NGX_ERROR;
    }

    /* Convert arguments to integers */
    num1 = ngx_atoi(arg_str1.data, arg_str1.len);
    if (num1 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: invalid number \"%V\"", &arg_str1);
        return NGX_ERROR;
    }

    num2 = ngx_atoi(arg_str2.data, arg_str2.len);
    if (num2 == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: invalid number \"%V\"", &arg_str2);
        return NGX_ERROR;
    }

    /* Compute min */
    min = (num1 < num2) ? num1 : num2;

    /* Convert result to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", min) - p;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_http_var_operate_rand(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    if (var->args->nelts != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: rand operator does not accept arguments");
        return NGX_ERROR;
    }

    /* Generate a random number */
    ngx_uint_t rand_num = ngx_random();

    /* Convert to string */
    u_char *p;
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: memory allocation failed");
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", rand_num) - p;
    v->data = p;

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

    /* 计算 src_string 的值 */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 执行正则匹配 */
    rc = ngx_http_regex_exec(r, var->regex, &subject);
    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    } else if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: regex match failed");
        return NGX_ERROR;
    }

    /* 计算 assign_value 的值 */
    if (ngx_http_complex_value(r, var->value, &assign_value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 设置变量值 */
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
                      "ngx_http_var_module: regex substitution failed");
        return NGX_ERROR;
    }

    /* Ensure captures are available */
    if (r->ncaptures < 2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: insufficient captures");
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
#if (NGX_PCRE)
    ngx_str_t                    subject, replacement, result;
    ngx_http_complex_value_t    *args = var->args->elts;
    ngx_uint_t                   offset = 0;
    u_char                      *p;
    ngx_int_t                    rc;
    int                         *captures;
    ngx_uint_t                   allocated;
    ngx_uint_t                   required;

    /* 计算 src_string 的值 */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 计算替换字符串模板 */
    if (ngx_http_complex_value(r, var->value, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 初始化结果字符串，初始分配10倍原始长度，最小1KB */
    allocated = subject.len * 10;
    if (allocated < 1024) {
        allocated = 1024;
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

        /* 执行正则匹配 */
        rc = ngx_http_regex_exec(r, var->regex, &sub);

        if (rc == NGX_DECLINED) {
            /* 没有更多匹配，复制剩余的部分 */
            required = (ngx_uint_t)(p - result.data) + sub.len;
            if (required > allocated) {
                /* 需要扩展缓冲区 */
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
                          "ngx_http_var_module: regex substitution failed");
            return NGX_ERROR;
        }

        /* 获取捕获组信息 */
        captures = r->captures;
        /* captures是一个int数组，捕获组的起始和结束位置 */
        int match_start = captures[0];
        int match_end = captures[1];

        /* 复制匹配前的部分 */
        if (match_start > 0) {
            required = (ngx_uint_t)(p - result.data) + match_start;
            if (required > allocated) {
                /* 需要扩展缓冲区 */
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

        /* 计算替换字符串，处理其中的 $n */
        ngx_str_t replaced;
        if (ngx_http_complex_value(r, var->value, &replaced) != NGX_OK) {
            return NGX_ERROR;
        }

        /* 确保替换后的字符串有足够的空间 */
        required = (ngx_uint_t)(p - result.data) + replaced.len + (subject.len - offset - match_end);
        if (required > allocated) {
            /* 扩展缓冲区到足够大小 */
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

        /* 复制替换字符串 */
        ngx_memcpy(p, replaced.data, replaced.len);
        p += replaced.len;
        result.len += replaced.len;

        /* 更新偏移量到匹配结束位置 */
        offset += match_end;

        /* 防止无限循环 */
        if (match_end == match_start) {
            offset++;
            if (offset > subject.len) {
                break;
            }
        }
    }

    /* 设置变量值 */
    v->len = p - result.data;
    v->data = result.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
#endif