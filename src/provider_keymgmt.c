/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

static OSSL_FUNC_keymgmt_new_fn p11prov_rsa_new;
static OSSL_FUNC_keymgmt_gen_init_fn p11prov_rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_fn p11prov_rsa_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn p11prov_rsa_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn p11prov_rsa_load;
static OSSL_FUNC_keymgmt_free_fn p11prov_rsa_free;
static OSSL_FUNC_keymgmt_has_fn p11prov_rsa_has;
static OSSL_FUNC_keymgmt_import_fn p11prov_rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn p11prov_rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn p11prov_rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn p11prov_rsa_export_types;

static void *p11prov_rsa_new(void *provctx)
{
    p11prov_debug("new\n");
    return NULL;
}

static void *p11prov_rsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    p11prov_debug("gen_init\n");
    return NULL;
}

static void *p11prov_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    p11prov_debug("gen %p %p %p\n", genctx, osslcb, cbarg);
    return NULL;
}
static void p11prov_rsa_gen_cleanup(void *genctx)
{
    p11prov_debug("gen_cleanup %p\n", genctx);
}

static void p11prov_rsa_free(void *key)
{
    p11prov_debug("free %p\n", key);
    p11prov_object_free((P11PROV_OBJECT *)key);
}

static void *p11prov_rsa_load(const void *reference, size_t reference_sz)
{
    P11PROV_OBJECT *obj = NULL;

    p11prov_debug("load %p, %ld\n", reference, reference_sz);

    if (!reference || reference_sz != sizeof(obj))
        return NULL;

    /* the contents of the reference is the address to our object */
    obj = *(P11PROV_OBJECT **)reference;
    /* we grabbed it, so we detach it */
    *(P11PROV_OBJECT **)reference = NULL;

    return obj;
}

static int p11prov_rsa_has(const void *keydata, int selection)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)keydata;

    p11prov_debug("has %p %d\n", obj, selection);

    if (obj == NULL) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (p11prov_object_key(obj, true) == NULL) return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (p11prov_object_key(obj, false) == NULL) return 0;
    }

    return 1;
}

static int p11prov_rsa_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    p11prov_debug("import %p\n", keydata);
    return 0;
}

static int p11prov_rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)keydata;

    p11prov_debug("export %p\n", keydata);

    if (obj == NULL) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_object_export_public_rsa_key(
                    p11prov_object_key(obj, false), param_callback, cbarg);
    }

    return 0;
}

static const OSSL_PARAM p11prov_rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_rsa_import_types(int selection)
{
    p11prov_debug("import types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *p11prov_rsa_export_types(int selection)
{
    p11prov_debug("export types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsa_key_types;
    return NULL;
}

const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_rsa_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p11prov_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p11prov_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p11prov_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_rsa_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_rsa_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_rsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11prov_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p11prov_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p11prov_rsa_export_types },
    { 0, NULL }
};
