/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

static OSSL_FUNC_keymgmt_new_fn rsa_new;
static OSSL_FUNC_keymgmt_load_fn rsa_load;
static OSSL_FUNC_keymgmt_free_fn rsa_free;

const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_new },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))rsa_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_free },
    { 0, NULL }
};

static void *rsa_new(void *provctx)
{
    return 0xdeadbeaf;
}

static void rsa_free(void *key)
{
    if (key != 0xdeadbeaf) abort();
}

static void *rsa_load(const void *reference, size_t reference_sz)
{
    return NULL;
}
