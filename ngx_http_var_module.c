#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_VAR_LEVELS 3

typedef enum {
    NGX_HTTP_VAR_LEVEL_HTTP = 0,
    NGX_HTTP_VAR_LEVEL_SERVER,
    NGX_HTTP_VAR_LEVEL_LOCATION
} ngx_http_var_level_e;

typedef struct {
    ngx_http_complex_value_t    *values[NGX_HTTP_VAR_LEVELS]; /* definitions at different levels */
} ngx_http_var_variable_value_t;

typedef struct {
    ngx_str_t                   name;       /* variable name without '$' */
    ngx_http_var_variable_value_t *var_data;
} ngx_http_var_variable_t;

typedef struct {
    ngx_array_t *variables; /* array of ngx_http_var_variable_t */
} ngx_http_var_main_conf_t;

/* Function prototypes */
static char *ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_var_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_var_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_command_t ngx_http_var_commands[] = {

    { ngx_string("var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_var_create_variable,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_var_create_main_conf,         /* create main configuration */
    ngx_http_var_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
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
    ngx_http_var_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->variables = ngx_array_create(cf->pool, 4, sizeof(ngx_http_var_variable_t));
    if (conf->variables == NULL) {
        return NULL;
    }

    return conf;
}

/* Initialize main configuration */
static char *
ngx_http_var_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

/* "var" directive handler */
static char *
ngx_http_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_main_conf_t   *vmcf = conf;
    ngx_str_t                 *value;
    ngx_str_t                  var_name, operator;
    ngx_http_variable_t       *v;
    ngx_http_var_variable_t   *var;
    ngx_http_complex_value_t  *cv;
    ngx_uint_t                 i;
    ngx_uint_t                 level;
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

    /* Determine configuration level */
    if (cf->cmd_type == NGX_HTTP_MAIN_CONF) {
        level = NGX_HTTP_VAR_LEVEL_HTTP;
    } else if (cf->cmd_type == NGX_HTTP_SRV_CONF) {
        level = NGX_HTTP_VAR_LEVEL_SERVER;
    } else {
        level = NGX_HTTP_VAR_LEVEL_LOCATION;
    }

    /* Search for existing variable */
    ngx_http_var_variable_t *variables = vmcf->variables->elts;
    for (i = 0; i < vmcf->variables->nelts; i++) {
        if (variables[i].name.len == var_name.len &&
            ngx_strncmp(variables[i].name.data, var_name.data, var_name.len) == 0)
        {
            var = &variables[i];
            break;
        }
    }

    if (i == vmcf->variables->nelts) {
        /* Variable not found, create new one */
        var = ngx_array_push(vmcf->variables);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->name.len = var_name.len;
        var->name.data = ngx_pnalloc(cf->pool, var_name.len);
        if (var->name.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(var->name.data, var_name.data, var_name.len);

        var->var_data = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_variable_value_t));
        if (var->var_data == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Compile complex value */
    cv = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* Assign complex value to the appropriate level */
    var->var_data->values[level] = cv;

    /* Add variable to Nginx */
    ngx_str_t full_var_name = value[1]; /* Original variable name with '$' */

    /* Check if variable already exists in Nginx */
    v = ngx_http_add_variable(cf, &full_var_name, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_var_variable_handler;
        v->data = (uintptr_t) var->var_data;
    } else if (v->get_handler == ngx_http_var_variable_handler) {
        /* Variable already added by this module, do nothing */
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
    ngx_http_var_variable_value_t *var_data = (ngx_http_var_variable_value_t *) data;
    ngx_http_complex_value_t      *cv;
    ngx_str_t                      value_str;

    /* Determine configuration level */
    ngx_uint_t level;

    if (r->loc_conf) {
        level = NGX_HTTP_VAR_LEVEL_LOCATION;
    } else if (r->srv_conf) {
        level = NGX_HTTP_VAR_LEVEL_SERVER;
    } else {
        level = NGX_HTTP_VAR_LEVEL_HTTP;
    }

    /* Find the first available definition from the innermost level */
    for (; level < NGX_HTTP_VAR_LEVELS; level--) {
        cv = var_data->values[level];
        if (cv != NULL) {
            if (ngx_http_complex_value(r, cv, &value_str) != NGX_OK) {
                return NGX_ERROR;
            }

            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
            v->len = value_str.len;

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
