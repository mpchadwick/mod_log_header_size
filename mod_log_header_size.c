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

static const char *log_bytes_in_header(request_rec *r, char *a)
{
    return "Hello";
}

static int log_header_size_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "^IH", log_bytes_in_header, 0);
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(log_header_size_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
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
