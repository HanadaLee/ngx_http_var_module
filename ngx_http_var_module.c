#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef enum {
    NGX_HTTP_VAR_OP_COPY,
    NGX_HTTP_VAR_OP_UPPER,
    NGX_HTTP_VAR_OP_LOWER,
    NGX_HTTP_VAR_OP_UNKNOWN
} ngx_http_var_operator_e;

typedef struct {
    ngx_array_t                    *vars;      /* array of ngx_http_var_variable_t */
} ngx_http_var_conf_t;

typedef struct {
    ngx_str_t                   name;       /* variable name */
    ngx_http_complex_value_t    value;      /* complex value */
    ngx_http_var_operator_e     operator;   /* operator type */
} ngx_http_var_variable_t;

typedef struct {
    ngx_str_t                   name;       /* operator string */
    ngx_http_var_operator_e     op;         /* operator enum */
} ngx_http_var_operator_mapping_t;

static ngx_http_var_operator_mapping_t ngx_http_var_operators[] = {
    { ngx_string("copy"),  NGX_HTTP_VAR_OP_COPY },
    { ngx_string("upper"), NGX_HTTP_VAR_OP_UPPER },
    { ngx_string("lower"), NGX_HTTP_VAR_OP_LOWER }
};

/* Function prototypes */
static void *ngx_http_var_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_find_variable(ngx_http_request_t *r, ngx_str_t *var_name,
                           ngx_http_var_conf_t *vconf, ngx_str_t *value_str,
                           ngx_log_t *log, const char *conf_level,
                           ngx_http_var_variable_t **found_var);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_var_operate_copy(u_char *data, size_t len, ngx_str_t *value_str);
static ngx_int_t ngx_http_var_operate_upper(u_char *data, size_t len, ngx_str_t *value_str);
static ngx_int_t ngx_http_var_operate_lower(u_char *data, size_t len, ngx_str_t *value_str);

static ngx_command_t ngx_http_var_commands[] = {

    { ngx_string("var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
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
    ngx_str_t                    var_name, operator_str;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_uint_t                   i;
    ngx_http_var_operator_e      op = NGX_HTTP_VAR_OP_UNKNOWN;

    value = cf->args->elts;

    var_name = value[1];
    operator_str = value[2];

    if (var_name.len == 0 || var_name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &var_name);
        return NGX_CONF_ERROR;
    }

    /* 移除变量名前的 '$' */
    var_name.len--;
    var_name.data++;

    /* 通过映射获取操作符的枚举值 */
    for (i = 0; i < sizeof(ngx_http_var_operators) / sizeof(ngx_http_var_operator_mapping_t); i++) {
        if (operator_str.len == ngx_http_var_operators[i].name.len &&
            ngx_strncmp(operator_str.data, ngx_http_var_operators[i].name.data, operator_str.len) == 0)
        {
            op = ngx_http_var_operators[i].op;
            break;
        }
    }

    if (op == NGX_HTTP_VAR_OP_UNKNOWN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unsupported operator \"%V\"", &operator_str);
        return NGX_CONF_ERROR;
    }

    /* 初始化变量数组 */
    if (vconf->vars == NULL) {
        vconf->vars = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_var_variable_t));
        if (vconf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* 添加变量定义 */
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

    /* 编译复杂值 */
    ngx_http_compile_complex_value_t   ccv;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &var->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* 注册变量 */
    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    v = ngx_http_add_variable(cf, &var_name, flags);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL || v->get_handler == ngx_http_var_variable_handler) {
        v->get_handler = ngx_http_var_variable_handler;

        /* 存储变量名 */
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

/* Helper function to find and compute variable */
static ngx_int_t
ngx_http_var_find_variable(ngx_http_request_t *r, ngx_str_t *var_name,
                           ngx_http_var_conf_t *vconf, ngx_str_t *value_str,
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

            if (ngx_http_complex_value(r, &vars[i].value, value_str) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ngx_http_var_module: failed to compute variable value");
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "ngx_http_var_module: variable value computed \"%V\"",
                           value_str);

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
    ngx_str_t                     value_str;
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
    rc = ngx_http_var_find_variable(r, &var_name, vconf, &value_str, log, "location", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in server conf */
    vconf = ngx_http_get_module_srv_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, &value_str, log, "server", &found_var);
    if (rc == NGX_OK) {
        goto found;
    } else if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* Search in main conf */
    vconf = ngx_http_get_module_main_conf(r, ngx_http_var_module);
    rc = ngx_http_var_find_variable(r, &var_name, vconf, &value_str, log, "main", &found_var);
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

    /* 分配内存 */
    v->len = value_str.len;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ngx_http_var_module: memory allocation failed");
        return NGX_ERROR;
    }

    /* 调用对应的操作处理函数 */
    switch (found_var->operator) {
    case NGX_HTTP_VAR_OP_COPY:
        rc = ngx_http_var_operate_copy(v->data, v->len, &value_str);
        break;

    case NGX_HTTP_VAR_OP_UPPER:
        rc = ngx_http_var_operate_upper(v->data, v->len, &value_str);
        break;

    case NGX_HTTP_VAR_OP_LOWER:
        rc = ngx_http_var_operate_lower(v->data, v->len, &value_str);
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ngx_http_var_module: unknown operator");
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_var_operate_copy(u_char *data, size_t len, ngx_str_t *value_str)
{
    ngx_memcpy(data, value_str->data, len);
    return NGX_OK;
}

static ngx_int_t
ngx_http_var_operate_upper(u_char *data, size_t len, ngx_str_t *value_str)
{
    size_t i;

    ngx_memcpy(data, value_str->data, len);

    for (i = 0; i < len; i++) {
        data[i] = ngx_toupper(data[i]);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_var_operate_lower(u_char *data, size_t len, ngx_str_t *value_str)
{
    size_t i;

    ngx_memcpy(data, value_str->data, len);

    for (i = 0; i < len; i++) {
        data[i] = ngx_tolower(data[i]);
    }

    return NGX_OK;
}