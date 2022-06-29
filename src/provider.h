/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#ifndef _PROVIDER_H
#define _PROVIDER_H

#ifndef _WIN32
#include "config.h"
#endif

#include "libp11.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

#define UNUSED  __attribute__((unused))

#define P11PROV_PKCS11_MODULE_PATH "pkcs11-module-path"
#define P11PROV_PKCS11_MODULE_INIT_ARGS "pkcs11-module-init-args"

#define P11PROV_DEFAULT_PROPERTIES "provider=pkcs11"
#define P11PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define P11PROV_DESCS_RSA "PKCS11 RSA Implementation"
#define P11PROV_DESCS_URI "PKCS11 URI Store"

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
typedef struct st_provider_ctx PROVIDER_CTX;

/* Key Management */
extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];

/* Object Stores */
typedef struct p11prov_object P11PROV_OBJECT;

void p11prov_object_free(P11PROV_OBJECT *obj);

extern const OSSL_DISPATCH p11prov_object_store_functions[];

#endif /* _PROVIDER_H */

/* vim: set noexpandtab: */
