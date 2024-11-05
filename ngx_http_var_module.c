#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_array_t                *vars;      /* array of ngx_http_var_variable_t */
} ngx_http_var_loc_conf_t;

typedef struct {
    ngx_str_t                   name;       /* variable name */
    ngx_http_complex_value_t    value;      /* complex value */
} ngx_http_var_variable_t;

/* Function prototypes */
static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_var_init(ngx_conf_t *cf);
static int ngx_libc_cdecl ngx_http_var_cmp_variables(const void *one, const void *two);

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

/* Create location configuration */
static void *
ngx_http_var_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_var_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}

/* Merge location configurations */
static char *
ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_var_loc_conf_t *prev = parent;
    ngx_http_var_loc_conf_t *conf = child;

    if (conf->vars == NULL && prev->vars != NULL) {
        conf->vars = ngx_array_create(cf->pool, prev->vars->nelts,
                                      sizeof(ngx_http_var_variable_t));
        if (conf->vars == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_http_var_variable_t *prev_vars = prev->vars->elts;
        for (ngx_uint_t i = 0; i < prev->vars->nelts; i++) {
            ngx_http_var_variable_t *var = ngx_array_push(conf->vars);
            if (var == NULL) {
                return NGX_CONF_ERROR;
            }
            *var = prev_vars[i];
        }
    }

    return NGX_CONF_OK;
}

/* "var" directive handler */
static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_loc_conf_t   *vlcf = conf;
    ngx_str_t                 *value;
    ngx_str_t                  var_name, operator;
    ngx_http_variable_t       *v;
    ngx_http_var_variable_t   *var;
    ngx_uint_t                 flags;
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
    if (vlcf->vars == NULL) {
        vlcf->vars = ngx_array_create(cf->pool, 4,
                                      sizeof(ngx_http_var_variable_t));
        if (vlcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Add variable to configuration */
    var = ngx_array_push(vlcf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->name = var_name;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &var->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* Add variable to Nginx */
    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    /* Reconstruct variable name with leading '$' */
    ngx_str_t full_var_name = value[1];

    v = ngx_http_add_variable(cf, &full_var_name, flags);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL || v->get_handler == ngx_http_var_variable_handler) {
        v->get_handler = ngx_http_var_variable_handler;
        v->data = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "variable \"%V\" already has a handler", &full_var_name);
    }

    return NGX_CONF_OK;
}

/* Variable handler */
static ngx_int_t
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_loc_conf_t      *vlcf;
    ngx_http_var_variable_t      *vars;
    ngx_uint_t                    i;
    ngx_str_t                     var_name;
    ngx_str_t                     value_str;

    /* Get variable name without leading '$' */
    var_name.len = v->name.len - 1;
    var_name.data = v->name.data + 1;

    /* Configuration hierarchy: location -> server -> main */
    ngx_http_var_loc_conf_t *conf_list[] = {
        ngx_http_get_module_loc_conf(r, ngx_http_var_module),
        ngx_http_get_module_srv_conf(r, ngx_http_var_module),
        ngx_http_get_module_main_conf(r, ngx_http_var_module)
    };

    for (i = 0; i < 3; i++) {
        vlcf = conf_list[i];
        if (vlcf == NULL || vlcf->vars == NULL || vlcf->vars->nelts == 0) {
            continue;
        }

        vars = vlcf->vars->elts;
        ngx_uint_t n = vlcf->vars->nelts;

        /* Binary search */
        ngx_int_t low = 0;
        ngx_int_t high = n - 1;
        ngx_int_t mid;
        int cmp;

        while (low <= high) {
            mid = (low + high) / 2;
            cmp = ngx_strcmp(var_name.data, vars[mid].name.data);

            if (cmp == 0) {
                /* Found the variable */
                if (ngx_http_complex_value(r, &vars[mid].value, &value_str) != NGX_OK) {
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
            } else if (cmp < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
    }

    /* Variable not found */
    v->not_found = 1;
    return NGX_OK;
}

/* Compare function for qsort */
static int ngx_libc_cdecl
ngx_http_var_cmp_variables(const void *one, const void *two)
{
    ngx_http_var_variable_t *first = (ngx_http_var_variable_t *) one;
    ngx_http_var_variable_t *second = (ngx_http_var_variable_t *) two;

    return ngx_strcmp(first->name.data, second->name.data);
}

/* Module postconfiguration */
static ngx_int_t
ngx_http_var_init(ngx_conf_t *cf)
{
    ngx_http_var_loc_conf_t      *vlcf;

    /* Configuration hierarchy: main, server, location */
    ngx_http_conf_ctx_t *ctx = cf->ctx;

    /* Sort variables in main conf */
    vlcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_var_module);
    if (vlcf && vlcf->vars && vlcf->vars->nelts > 0) {
        ngx_qsort(vlcf->vars->elts, vlcf->vars->nelts,
                  sizeof(ngx_http_var_variable_t), ngx_http_var_cmp_variables);
    }

    /* Sort variables in server conf */
    if (ctx->srv_conf) {
        vlcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_var_module);
        if (vlcf && vlcf->vars && vlcf->vars->nelts > 0) {
            ngx_qsort(vlcf->vars->elts, vlcf->vars->nelts,
                      sizeof(ngx_http_var_variable_t), ngx_http_var_cmp_variables);
        }
    }

    /* Sort variables in location conf */
    vlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_var_module);
    if (vlcf && vlcf->vars && vlcf->vars->nelts > 0) {
        ngx_qsort(vlcf->vars->elts, vlcf->vars->nelts,
                  sizeof(ngx_http_var_variable_t), ngx_http_var_cmp_variables);
    }

    return NGX_OK;
}
