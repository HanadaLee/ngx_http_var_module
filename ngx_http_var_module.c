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
    NGX_HTTP_VAR_OP_UNKNOWN
} ngx_http_var_operator_e;

typedef struct {
    ngx_array_t                *vars;      /* array of ngx_http_var_variable_t */
} ngx_http_var_conf_t;

typedef struct {
    ngx_str_t                   name;           /* variable name */
    ngx_http_var_operator_e     operator;       /* operator type */
    ngx_array_t                *args;           /* array of ngx_http_complex_value_t */
    ngx_uint_t                  flags;          /* general flags, e.g., NGX_REGEX_CASELESS */
    unsigned                    global:1;       /* whether to perform global matching */
    /* 以下字段用于 re_match 操作符 */
    ngx_regex_t                *regex;          /* compiled regular expression */
    ngx_uint_t                  ncaptures;      /* number of captures */
} ngx_http_var_variable_t;

typedef struct {
    ngx_str_t                   name;       /* operator string */
    ngx_http_var_operator_e     op;         /* operator enum */
    ngx_uint_t                  min_args;   /* minimum number of arguments */
    ngx_uint_t                  max_args;   /* maximum number of arguments */
} ngx_http_var_operator_mapping_t;

static ngx_http_var_operator_mapping_t ngx_http_var_operators[] = {
    { ngx_string("copy"),    NGX_HTTP_VAR_OP_COPY,      1, 1 },
    { ngx_string("upper"),   NGX_HTTP_VAR_OP_UPPER,     1, 1 },
    { ngx_string("lower"),   NGX_HTTP_VAR_OP_LOWER,     1, 1 },
    { ngx_string("max"),     NGX_HTTP_VAR_OP_MAX,       2, 2 },
    { ngx_string("min"),     NGX_HTTP_VAR_OP_MIN,       2, 2 },
    { ngx_string("rand"),    NGX_HTTP_VAR_OP_RAND,      0, 0 },
    { ngx_string("re_match"), NGX_HTTP_VAR_OP_RE_MATCH, 3, 3 }
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
static ngx_int_t ngx_http_var_operate_re_match(ngx_http_request_t *r,
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
/* "var" directive handler */
static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_conf_t         *vconf = conf;
    ngx_str_t                   *value;
    ngx_str_t                    var_name, operator_str;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_uint_t                   i, n;
    ngx_http_var_operator_e      op = NGX_HTTP_VAR_OP_UNKNOWN;
    ngx_uint_t                   min_args = 0, max_args = 0;
    ngx_uint_t                   args_count;
    ngx_uint_t                   arg_index;

    value = cf->args->elts;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments in \"var\" directive");
        return NGX_CONF_ERROR;
    }

    var_name = value[1];

    if (var_name.len == 0 || var_name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &var_name);
        return NGX_CONF_ERROR;
    }

    /* Remove the leading '$' from variable name */
    var_name.len--;
    var_name.data++;

    /* Initialize variable definition */
    var = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_variable_t));
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->name.len = var_name.len;
    var->name.data = ngx_pstrdup(cf->pool, &var_name);
    if (var->name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Initialize general flags */
    var->flags = 0;
    var->global = 0;

    /* Start parsing from the third argument */
    arg_index = 2;

    /* Parse general options */
    while (arg_index < cf->args->nelts) {
        ngx_str_t *arg = &value[arg_index];
        if (arg->len >= 2 && arg->data[0] == '-') {
            u_char *flag = arg->data + 1;
            for (; *flag; flag++) {
                switch (*flag) {
                case 'i':
                    var->flags |= NGX_REGEX_CASELESS;
                    break;
                case 'g':
                    var->global = 1;
                    break;
                default:
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid flag \"%c\"", *flag);
                    return NGX_CONF_ERROR;
                }
            }
            arg_index++;
        } else {
            break;
        }
    }

    /* Check if there are enough arguments left for the operator */
    if (cf->args->nelts - arg_index < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing operator in \"var\" directive");
        return NGX_CONF_ERROR;
    }

    /* Get the operator */
    operator_str = value[arg_index++];

    /* Map operator string to enum and get argument counts */
    for (i = 0; i < sizeof(ngx_http_var_operators) / sizeof(ngx_http_var_operator_mapping_t); i++) {
        if (operator_str.len == ngx_http_var_operators[i].name.len &&
            ngx_strncmp(operator_str.data, ngx_http_var_operators[i].name.data, operator_str.len) == 0)
        {
            op = ngx_http_var_operators[i].op;
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

    var->operator = op;

    /* Calculate the number of remaining arguments */
    args_count = cf->args->nelts - arg_index;

    if (args_count < min_args || args_count > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments for operator \"%V\"", &operator_str);
        return NGX_CONF_ERROR;
    }

    /* Initialize args array */
    var->args = ngx_array_create(cf->pool, args_count ? args_count : 1,
                                 sizeof(ngx_http_complex_value_t));
    if (var->args == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Compile all arguments */
    for (n = 0; n < args_count; n++) {
        ngx_http_complex_value_t            *cv;
        ngx_http_compile_complex_value_t     ccv;

        cv = ngx_array_push(var->args);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[arg_index + n];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /* For re_match operator, compile the regex */
    if (op == NGX_HTTP_VAR_OP_RE_MATCH) {
        /* The regex is the second argument (args[1]) */
        ngx_http_complex_value_t *regex_cv = ((ngx_http_complex_value_t *)var->args->elts) + 1;

        if (regex_cv->value.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "regex pattern cannot be empty");
            return NGX_CONF_ERROR;
        }

        if (regex_cv->lengths != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "regex pattern cannot contain variables");
            return NGX_CONF_ERROR;
        }

        ngx_str_t regex_str = regex_cv->value;

        ngx_regex_compile_t   rc;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = regex_str;
        rc.pool = cf->pool;
        rc.options = var->flags;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = ngx_pnalloc(cf->pool, NGX_MAX_CONF_ERRSTR);
        if (rc.err.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "failed to compile regex \"%V\": %V", &regex_str, &rc.err);
            return NGX_CONF_ERROR;
        }

        var->regex = rc.regex;
        var->ncaptures = rc.captures;
    }

    /* Add variable definition to the configuration */
    if (vconf->vars == NULL) {
        vconf->vars = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_var_variable_t *));
        if (vconf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_http_var_variable_t **varp = ngx_array_push(vconf->vars);
    if (varp == NULL) {
        return NGX_CONF_ERROR;
    }

    *varp = var;

    /* Register the variable */
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

    case NGX_HTTP_VAR_OP_RE_MATCH:
        rc = ngx_http_var_operate_re_match(r, v, var);
        break;

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

static ngx_int_t
ngx_http_var_operate_re_match(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_variable_t *var)
{
    ngx_str_t                    subject, assign_value;
    ngx_int_t                    rc;
    int                         *captures;
    ngx_uint_t                   ncaptures;

    ngx_http_complex_value_t    *args = var->args->elts;

    /* Evaluate src_string */
    if (ngx_http_complex_value(r, &args[0], &subject) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Execute regex matching */
    ncaptures = (var->ncaptures + 1) * 3;
    captures = ngx_palloc(r->pool, ncaptures * sizeof(int));
    if (captures == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_regex_exec(var->regex, &subject, captures, ncaptures);
    if (rc == NGX_REGEX_NO_MATCHED) {
        v->not_found = 1;
        return NGX_OK;
    } else if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_var_module: regex match failed");
        return NGX_ERROR;
    }

    /* Save captures in the request */
    r->captures = captures;
    r->captures_data = subject.data;
    r->ncaptures = ncaptures;

    /* Evaluate assign_value */
    if (ngx_http_complex_value(r, &args[2], &assign_value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Set variable value */
    v->len = assign_value.len;
    v->data = assign_value.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    /* Clean up captures */
    r->captures = NULL;
    r->captures_data = NULL;
    r->ncaptures = 0;

    return NGX_OK;
}