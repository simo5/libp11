/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

static OSSL_FUNC_keymgmt_new_fn rsa_new;
static OSSL_FUNC_keymgmt_gen_init_fn rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_fn rsa_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn rsa_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn rsa_load;
static OSSL_FUNC_keymgmt_free_fn rsa_free;
static OSSL_FUNC_keymgmt_has_fn rsa_has;
static OSSL_FUNC_keymgmt_import_fn rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn rsa_export_types;

const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))rsa_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))rsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))rsa_export_types },
    { 0, NULL }
};

static void *rsa_new(void *provctx)
{
    fprintf(stderr, "new\n");
    fflush(stderr);
    return (void *)0xdeadbeaf;
}

static void *rsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    fprintf(stderr, "gen_init\n");
    fflush(stderr);
    return (void *)0xdeadbeaf;
}

static void *rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    fprintf(stderr, "gen %p %p %p\n", genctx, osslcb, cbarg);
    fflush(stderr);
    return (void *)0xdeadbeaf;
}
static void rsa_gen_cleanup(void *genctx)
{
    fprintf(stderr, "gen_cleanup %p\n", genctx);
    fflush(stderr);
}

static void rsa_free(void *key)
{
    fprintf(stderr, "free %p\n", key);
    fflush(stderr);
    if (key == NULL) return;
    if (key != (void *)0xdeadbeaf) abort();
}

static void *rsa_load(const void *reference, size_t reference_sz)
{
    fprintf(stderr, "load %p, %ld\n", reference, reference_sz);
    fflush(stderr);
    return NULL;
}

static int rsa_has(const void *keydata, int selection)
{
    int ok = 1;

    fprintf(stderr, "has %p %d\n", keydata, selection);
    fflush(stderr);

    if (keydata == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) == 0)
        return 1; /* the selection is not missing */

    /* OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty */
    /*
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    */
    return 0;
}

static int rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    fprintf(stderr, "import %p\n", keydata);
    fflush(stderr);
    return 0;
}

static int rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    fprintf(stderr, "export %p\n", keydata);
    fflush(stderr);
    return 0;
}

static const OSSL_PARAM rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_import_types(int selection)
{
    fprintf(stderr, "import types\n");
    fflush(stderr);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return rsa_key_types;
}

static const OSSL_PARAM *rsa_export_types(int selection)
{
    fprintf(stderr, "export types\n");
    fflush(stderr);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return rsa_key_types;
}
