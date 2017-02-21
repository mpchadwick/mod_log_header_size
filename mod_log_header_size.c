#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "mod_log_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"

module AP_MODULE_DECLARE_DATA log_header_size_module;

typedef struct log_header_size_config_t {
    apr_off_t bytes_in_header;
    apr_off_t bytes_out_header;
} log_header_size_config_t;

static int gather_header_size(void *b_, const char *key, const char *value)
{
    int *b = b_;
    (*b) += strlen(key);
    (*b) += strlen(value);

    return 1;
}

static const char *log_bytes_in_header(request_rec *r, char *a)
{
    log_header_size_config_t *cf = ap_get_module_config(r->connection->conn_config, &log_header_size_module);

    return apr_off_t_toa(r->pool, cf->bytes_in_header);
}

static const char *log_bytes_out_header(request_rec *r, char *a)
{
    log_header_size_config_t *cf = ap_get_module_config(r->connection->conn_config, &log_header_size_module);
    apr_table_do(gather_header_size, &cf->bytes_out_header, r->headers_out, NULL);

    return apr_off_t_toa(r->pool, cf->bytes_out_header);
}

static int log_header_size_pre_connection(conn_rec *c, void *csd)
{
    log_header_size_config_t *cf = apr_palloc(c->pool, sizeof(*cf));

    ap_set_module_config(c->conn_config, &log_header_size_module, cf);

    return OK;
}

static int log_header_size_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "^IH", log_bytes_in_header, 0);
        log_pfn_register(p, "^OH", log_bytes_out_header, 0);
    }

    return OK;
}

static int log_header_size_post_read_request(request_rec *r)
{
    log_header_size_config_t *cf = ap_get_module_config(r->connection->conn_config, &log_header_size_module);
    apr_table_do(gather_header_size, &cf->bytes_in_header, r->headers_in, NULL);

    return OK;
}

static int log_header_size_log_transaction(request_rec *r)
{
    log_header_size_config_t *cf = ap_get_module_config(r->connection->conn_config, &log_header_size_module);
    cf->bytes_in_header = cf->bytes_out_header = 0;

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_connection(log_header_size_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(log_header_size_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_post_read_request(log_header_size_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(log_header_size_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(log_header_size) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};
