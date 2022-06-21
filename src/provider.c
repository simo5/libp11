/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

struct st_provider_ctx {
    pthread_mutex_t lock;

    /* Provider handles */
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;

    /* Configuration */
    BUF_MEM pin;
    const char *module;
    const char *init_args;

    /* Current operations */
    PKCS11_CTX *pkcs11_ctx;
    PKCS11_SLOT *slot_list;
    unsigned int slot_count;
};

static void provider_ctx_free(PROVIDER_CTX *ctx)
{
    OSSL_LIB_CTX_free(ctx->libctx);
    pthread_mutex_destroy(&ctx->lock);
    OPENSSL_free(ctx);
}

static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static void p11prov_teardown(void *ctx)
{
    provider_ctx_free((PROVIDER_CTX *)ctx);
}

/* Parameters we provide to the core */
static const OSSL_PARAM p11prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_gettable_params(void *provctx)
{
    return p11prov_param_types;
}

static int p11prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL) {
        ret = OSSL_PARAM_set_utf8_ptr(p, "PKCS#11 Provider");
        if (ret == 0) return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
        if (ret == 0) return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR);
        if (ret == 0) return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL) {
        /* return 1 for now,
         * return 0 in future if there are module issues? */
        ret = OSSL_PARAM_set_int(p, 1);
        if (ret == 0) return 0;
    }
    return 1;
}

/* TODO: this needs to be made dynamic,
 * based on what the pkcs11 module supports */
static const OSSL_ALGORITHM p11prov_keymgmt[] = {
    { P11PROV_NAMES_RSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsa_keymgmt_functions, P11PROV_DESCS_RSA, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *p11prov_query_operation(void *provctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return p11prov_keymgmt;
    }
    return NULL;
}

static int p11prov_get_capabilities(void *provctx, const char *capability,
                                    OSSL_CALLBACK *cb, void *arg)
{
    /* TODO: deal with TLS-GROUP */

    return 0;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH p11prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,
      (void (*)(void))p11prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))p11prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))p11prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))p11prov_query_operation },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))p11prov_get_capabilities },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const OSSL_DISPATCH *iter_in;
    OSSL_PARAM core_params[3] = { 0 };
    PROVIDER_CTX *ctx;
    int ret;

    *provctx = NULL;

    for (iter_in = in; iter_in->function_id != 0; iter_in++) {
        switch (iter_in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(iter_in);
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    ctx = OPENSSL_zalloc(sizeof(PROVIDER_CTX));
    if (ctx == NULL) {
        return 0;
    }
    ctx->handle = handle;

    ctx->libctx = OSSL_LIB_CTX_new();
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    pthread_mutex_init(&ctx->lock, 0);

    /* get module path */
    core_params[0] = OSSL_PARAM_construct_utf8_ptr(
                        P11PROV_PKCS11_MODULE_PATH,
                        (char **)&ctx->module,
                        sizeof(ctx->module));
    core_params[1] = OSSL_PARAM_construct_utf8_ptr(
                        P11PROV_PKCS11_MODULE_INIT_ARGS,
                        (char **)&ctx->init_args,
                        sizeof(ctx->init_args));
    core_params[2] = OSSL_PARAM_construct_end();
    ret = c_get_params(handle, core_params);
    if (ret == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        provider_ctx_free(ctx);
        return 0;
    }

    *out = p11prov_dispatch_table;
    *provctx = ctx;
    return 1;
}

