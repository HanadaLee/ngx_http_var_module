#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_array_t                    *vars;      /* array of ngx_http_var_variable_t */
} ngx_http_var_conf_t;

typedef struct {
    ngx_str_t                   name;       /* variable name */
    ngx_http_complex_value_t    value;      /* complex value */
} ngx_http_var_variable_t;

/* Function prototypes */
static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_var_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_var_init(ngx_conf_t *cf);

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
    ngx_http_var_init,                     /* postconfiguration */

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
    ngx_str_t                    var_name, operator;
    ngx_http_variable_t         *v;
    ngx_http_var_variable_t     *var;
    ngx_uint_t                   flags;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    var_name = value[1];
    operator = value[2];

    if (var_name.len == 0 || var_name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &var_name);
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(operator.data, "copy") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unsupported operator \"%V\"", &operator);
        return NGX_CONF_ERROR;
    }

    /* Remove the leading '$' from variable name */
    var_name.len--;
    var_name.data++;

    /* Initialize vars array if necessary */
    if (vconf->vars == NULL) {
        vconf->vars = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_var_variable_t));
        if (vconf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Add variable to configuration */
    var = ngx_array_push(vconf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->name.len = var_name.len;
    var->name.data = ngx_pstrdup(cf->pool, &var_name);
    if (var->name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &var->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* Add variable to Nginx */
    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    v = ngx_http_add_variable(cf, &var_name, flags);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL || v->get_handler == ngx_http_var_variable_handler) {
        v->get_handler = ngx_http_var_variable_handler;
        /* Store variable name in data */
        v->data = (uintptr_t) var->name.data;
    } else {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "variable \"%V\" already has a handler", &var_name);
    }

    return NGX_CONF_OK;
}

/* Variable handler */
static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vconf;
    ngx_http_var_variable_t      *vars;
    ngx_uint_t                    n;
    ngx_str_t                     var_name;
    ngx_str_t                     value_str;
    ngx_int_t                     i;

    /* Get variable name from data */
    var_name.len = ngx_strlen((u_char *) data);
    var_name.data = (u_char *) data;

    /* Get module configuration */
    vconf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);
    if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
        /* No variables defined in location, check server level */
        vconf = ngx_http_get_module_srv_conf(r, ngx_http_var_module);
        if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
            /* No variables defined in server, check main level */
            vconf = ngx_http_get_module_main_conf(r, ngx_http_var_module);
            if (vconf == NULL || vconf->vars == NULL || vconf->vars->nelts == 0) {
                /* Variable not found */
                v->not_found = 1;
                return NGX_OK;
            }
        }
    }

    vars = vconf->vars->elts;
    n = vconf->vars->nelts;

    /* Linear search */
    for (i = 0; i < (ngx_int_t) n; i++) {
        if (vars[i].name.len == var_name.len &&
            ngx_strncmp(vars[i].name.data, var_name.data, var_name.len) == 0)
        {
            /* Found the variable */
            if (ngx_http_complex_value(r, &vars[i].value, &value_str) != NGX_OK) {
                return NGX_ERROR;
            }

            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
            v->len = value_str.len;

            /* Allocate memory for the variable value */
            v->data = ngx_pnalloc(r->pool, value_str.len);
            if (v->data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(v->data, value_str.data, value_str.len);

            return NGX_OK;
        }
    }

    /* Variable not found */
    v->not_found = 1;
    return NGX_OK;
}

/* Module postconfiguration */
static ngx_int_t
ngx_http_var_init(ngx_conf_t *cf)
{
    /* No additional initialization required */
    return NGX_OK;
}
