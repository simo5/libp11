/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <stdbool.h>

struct p11prov_uri {
    char *model;
    char *manufacturer;
    char *token;
    char *serial;
    char *object;
    unsigned char *id;
    size_t id_len;
    char *pin;
    enum {
        P11PROV_URI_UNDEFINED,
        P11PROV_URI_CERTIFICATE,
        P11PROV_URI_PUBLIC_KEY,
        P11PROV_URI_PRIVATE_KEY,
    } type;
};

struct p11prov_object {
    PROVIDER_CTX *provctx;
    struct p11prov_uri *parsed_uri;
    int loaded;
    PKCS11_CERT *cert;
    PKCS11_KEY *key;
    int ref;
};

static void p11prov_uri_free(struct p11prov_uri *parsed_uri)
{
    if (parsed_uri == NULL) return;

    OPENSSL_free(parsed_uri->model);
    OPENSSL_free(parsed_uri->manufacturer);
    OPENSSL_free(parsed_uri->token);
    OPENSSL_free(parsed_uri->serial);
    OPENSSL_free(parsed_uri->object);
    OPENSSL_free(parsed_uri->id);
    if (parsed_uri->pin) {
        OPENSSL_clear_free(parsed_uri->pin, strlen(parsed_uri->pin));
    }
    OPENSSL_clear_free(parsed_uri, sizeof(struct p11prov_uri));
}

void p11prov_object_free(P11PROV_OBJECT *obj)
{
    fprintf(stderr, "object free (%p)\n", obj);
    fflush(stderr);

    if (obj == NULL) return;

    if (obj->ref) {
        obj->ref--;
        return;
    }

    p11prov_uri_free(obj->parsed_uri);
    OPENSSL_clear_free(obj, sizeof(P11PROV_OBJECT));
}

PKCS11_KEY *p11prov_object_key(P11PROV_OBJECT *obj)
{
    return obj->key;
}

static OSSL_FUNC_store_open_fn p11prov_object_open;
static OSSL_FUNC_store_attach_fn p11prov_object_attach;
static OSSL_FUNC_store_load_fn p11prov_object_load;
static OSSL_FUNC_store_eof_fn p11prov_object_eof;
static OSSL_FUNC_store_close_fn p11prov_object_close;
static OSSL_FUNC_store_export_object_fn p11prov_object_export;

static int hex_to_byte(const char *in, unsigned char *byte)
{
    char c[2], s;
    int i = 0;

    for (i = 0; i < 2; i++) {
        s = in[i];
        if ('0' <= s && s <= '9') {
            c[i] = s - '0';
        } else if ('a' <= s && s <= 'f') {
            c[i] = s - 'a' + 10;
        } else if ('A' <= s && s <= 'F') {
            c[i] = s - 'A' + 10;
        } else {
            return EINVAL;
        }
    }
    *byte = (c[0] << 4) | c[1];
    return 0;
}

static int parse_attr(const char *str, size_t len,
                      unsigned char **output, size_t *outlen)
{
    unsigned char *out;
    size_t index = 0;
    int ret;

    out = OPENSSL_malloc(len + 1);
    if (out == NULL) {
        return ENOMEM;
    }

    while (*str && len > 0) {
        if (*str == '%') {
            char hex[3] = { 0 };
            if (len < 3) {
                ret = EINVAL;
                goto done;
            }
            hex[0] = str[1];
            hex[1] = str[2];
            ret = hex_to_byte(hex, &out[index]);
            if (ret != 0) goto done;

            index++;
            str += 3;
            len -= 3;
        } else {
            out[index] = *str;
            index++;
            str++;
            len--;
        }
    }

    out[index] = '\0';
    ret = 0;

done:
    if (ret != 0) {
        OPENSSL_free(out);
    } else {
        *output = out;
        *outlen = index;
    }
    return ret;
}

#define MAX_PIN_LENGTH 32
static int get_pin(const char *str, size_t len,
                   char **output, size_t *outlen)
{
    char pin[MAX_PIN_LENGTH+1];
    char *pinfile;
    char *filename;
    BIO *fp;
    int ret;

    ret = parse_attr(str, len, (unsigned char **)&pinfile, outlen);
    if (ret != 0) return ret;

    if (strncmp((const char *)pinfile, "file:", 5) == 0) {
        filename = pinfile + 5;
    } else if (*pinfile == '|') {
        ret = EINVAL;
        goto done;
    } else {
        /* missing 'file:' is accepted */
        filename = pinfile;
    }

    fp = BIO_new_file(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to get pin from %s\n", filename);
        fflush(stderr);
        ret = ENOENT;
        goto done;
    }
    ret = BIO_gets(fp, pin, MAX_PIN_LENGTH);
    if (ret <= 0) {
        fprintf(stderr, "Failed to get pin from %s (%d)\n", filename, ret);
        fflush(stderr);
        ret = EINVAL;
        BIO_free(fp);
        goto done;
    }
    BIO_free(fp);

    *output = OPENSSL_strdup(pin);
    if (*output == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;
done:
    OPENSSL_free(pinfile);
    return ret;
}

static int parse_uri(struct p11prov_uri *u, const char *uri)
{
    const char *p, *end;
    int ret;

    if (strncmp(uri, "pkcs11:", 7) != 0) {
        return EINVAL;
    }

    p = uri + 7;
    while (p) {
        size_t outlen;
        unsigned char **ptr;
        size_t *ptrlen;
        size_t len;

        end = strpbrk(p, ";?&");
        if (end) {
            len = end - p;
        } else {
            len = strlen(p);
        }

        ptr = NULL;
        ptrlen = &outlen;

        if (strncmp(p, "model=", 6) == 0) {
            p += 6;
            len -= 6;
            ptr = (unsigned char **)&u->model;
        } else if (strncmp(p, "manufacturer=", 13) == 0) {
            p += 13;
            len -= 13;
            ptr = (unsigned char **)&u->manufacturer;
        } else if (strncmp(p, "token=", 6) == 0) {
            p += 6;
            len -= 6;
            ptr = (unsigned char **)&u->token;
        } else if (strncmp(p, "serial=", 7) == 0) {
            p += 7;
            len -= 7;
            ptr = (unsigned char **)&u->object;
        } else if (strncmp(p, "id=", 3) == 0) {
            p += 3;
            len -= 3;
            ptr = &u->id;
            ptrlen = &u->id_len;
        } else if (strncmp(p, "pin-value=", 10) == 0) {
            p += 10;
            len -= 10;
            ptr = (unsigned char **)&u->pin;
        } else if (strncmp(p, "pin-source=", 11) == 0) {
            p += 11;
            len -= 11;
            ret = get_pin(p, len, &u->pin, ptrlen);
            if (ret != 0) goto done;
        } else if (strncmp(p, "type=", 5) == 0 ||
                   strncmp(p, "object-type=", 12) == 0) {
            p += 4;
            if (*p == '=') {
                p++;
                len -= 5;
            } else {
                p += 8;
                len -= 12;
            }
            if (len == 4 && strncmp(p, "cert", 4) == 0) {
                u->type = P11PROV_URI_CERTIFICATE;
            } else if (len == 6 && strncmp(p, "public", 6) == 0) {
                u->type = P11PROV_URI_PUBLIC_KEY;
            } else if (len == 7 && strncmp(p, "private", 7) == 0) {
                u->type = P11PROV_URI_PRIVATE_KEY;
            } else {
                fprintf(stderr, "Unknown object type\n");
                fflush(stderr);
                ret = EINVAL;
                goto done;
            }
        } else {
            fprintf(stderr, "Ignoring unkown pkcs11 URI attribute\n");
            fflush(stderr);
        }

        if (ptr) {
            ret = parse_attr(p, len, ptr, ptrlen);
            if (ret != 0) goto done;
        }

        if (end) {
            p = end + 1;
        } else {
            p = NULL;
        }
    }

    ret = 0;
done:
    return ret;
}

static void *p11prov_object_open(void *provctx, const char *uri)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;
    P11PROV_OBJECT *obj;
    int ret;

    fprintf(stderr, "object open (%p, %s)\n", ctx, uri);
    fflush(stderr);

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJECT));
    if (obj == NULL) return NULL;

    obj->parsed_uri = OPENSSL_zalloc(sizeof(struct p11prov_uri));
    if (obj->parsed_uri == NULL) {
        p11prov_object_free(obj);
        return NULL;
    }

    ret = parse_uri(obj->parsed_uri, uri);
    if (ret != 0) {
        p11prov_object_free(obj);
        return NULL;
    }

    obj->provctx = ctx;

    return obj;
}

static void *p11prov_object_attach(void *provctx, OSSL_CORE_BIO *in)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;

    fprintf(stderr, "object attach (%p, %p)\n", ctx, in);
    fflush(stderr);

    return NULL;
}

static PKCS11_CERT *cert_cmp(PKCS11_CERT *a, PKCS11_CERT *b)
{
    const ASN1_TIME *a_time, *b_time;
    int pday, psec;

    if (!a || !a->x509) {
	return b;
    }
    if (!b || !b->x509) {
	return a;
    }

    a_time = X509_get0_notAfter(a->x509);
    b_time = X509_get0_notAfter(b->x509);

    /* the best certificate expires last */
    if (ASN1_TIME_diff(&pday, &psec, a_time, b_time)) {
        if (pday < 0 || psec < 0) {
            return a;
        } else {
            return b;
        }
    }

    /* deterministic tie break */
    if (X509_cmp(a->x509, b->x509) < 1) {
        return b;
    }

    return a;
}

static PKCS11_CERT *find_cert(PKCS11_SLOT *slot, PKCS11_CERT *prev,
                              const unsigned char *id, size_t id_len,
                              const char *label)
{
    PKCS11_CERT *match = NULL;
    PKCS11_CERT *certs;
    /* only the slot is used to find certs */
    PKCS11_TOKEN tmp = { .slot = slot };
    unsigned int n;
    int ret;

    ret = PKCS11_enumerate_certs(&tmp, &certs, &n);
    if (ret != 0) {
        fprintf(stderr, "Failed to enumerate certs\n");
        fflush(stderr);
        return prev;
    }
    /* no certs on slot */
    if (n == 0) return prev;

    if (!label && !id) {
        /* default to the first in case nothing matches */
        match = &certs[0];
    }

    /* see if we can match one */
    for (unsigned int i = 0; i < n; i++) {
        PKCS11_CERT *c = &certs[i];
        PKCS11_CERT *eval = NULL;
        if (!label && !id) {
            /* pick the first that has a valid id */
            if (c->id && *c->id) {
                match = c;
                break;
            }
            continue;
        }

        if (label) {
            if (c->label) {
                if (strcmp(label, c->label) == 0) {
                    eval = c;
                } else {
                    /* label exists and does not match */
                    continue;
                }
            }
        }
        if (id) {
            if (c->id_len != 0) {
                if (id_len == c->id_len && memcmp(id, c->id, c->id_len)) {
                    eval = c;
                } else {
                    /* id exists and does not match */
                    continue;
                }
            }
        }

        if (eval) {
            match = cert_cmp(match, eval);
        }
    }

    return cert_cmp(match, prev);
}

static PKCS11_KEY *find_key(PKCS11_SLOT *slot, bool private,
                              const unsigned char *id, size_t id_len,
                              const char *label)
{
    PKCS11_KEY *match = NULL;
    PKCS11_KEY *keys;
    /* only the slot is used to find certs */
    PKCS11_TOKEN tmp = { .slot = slot };
    unsigned int n;
    int ret;

    if (private) {
        ret = PKCS11_enumerate_keys(&tmp, &keys, &n);
    } else {
        ret = PKCS11_enumerate_public_keys(&tmp, &keys, &n);
    }

    if (ret != 0) {
        fprintf(stderr, "Failed to enumerate keys\n");
        fflush(stderr);
        return NULL;
    }
    /* no keys on slot */
    if (n == 0) return NULL;

    if (!label && !id) {
        /* default to the first in case nothing matches */
        match = &keys[0];
    }

    /* see if we can match one */
    for (unsigned int i = 0; i < n; i++) {
        PKCS11_KEY *k = &keys[i];
        PKCS11_KEY *eval = NULL;
        if (!label && !id) {
            /* pick the first that has a valid id */
            if (k->id && *k->id) {
                match = k;
                break;
            }
            continue;
        }

        if (label) {
            if (k->label) {
                if (strcmp(label, k->label) == 0) {
                    eval = k;
                } else {
                    /* label exists and does not match */
                    continue;
                }
            }
        }
        if (id) {
            if (k->id_len != 0) {
                if (id_len == k->id_len && memcmp(id, k->id, k->id_len)) {
                    eval = k;
                } else {
                    /* id exists and does not match */
                    continue;
                }
            }
        }

        /* return first match */
        if (eval) {
            return eval;
        }
    }

    return match;
}

static int p11prov_object_load(void *ctx,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;

    fprintf(stderr, "object load (%p)\n", obj);
    fflush(stderr);

    for (int i = 0; i < obj->provctx->slot_count; i++) {
	PKCS11_SLOT *slot = &obj->provctx->slot_list[i];

        /* ignore slots that are not initialized */
        if (slot->token == NULL) continue;
        if (!slot->token->initialized) continue;

        /* skip slots that do not match */
        if (obj->parsed_uri->model &&
            strcmp(obj->parsed_uri->model,
                   slot->token->model) != 0)
            continue;
        if (obj->parsed_uri->manufacturer &&
            strcmp(obj->parsed_uri->manufacturer,
                   slot->token->manufacturer) != 0)
            continue;
        if (obj->parsed_uri->token &&
            strcmp(obj->parsed_uri->token,
                   slot->token->label) != 0)
            continue;
        if (obj->parsed_uri->serial &&
            strcmp(obj->parsed_uri->serial,
                   slot->token->serialnr) != 0)
            continue;

        /* FIXME: handle login required */

        /* match type */
        if (obj->parsed_uri->type == P11PROV_URI_CERTIFICATE) {
            obj->cert = find_cert(slot, obj->cert,
                                  obj->parsed_uri->id,
                                  obj->parsed_uri->id_len,
                                  obj->parsed_uri->object);
        } else if (obj->parsed_uri->type == P11PROV_URI_PUBLIC_KEY) {
            obj->key = find_key(slot, false,
                                obj->parsed_uri->id,
                                obj->parsed_uri->id_len,
                                obj->parsed_uri->object);
        } else if (obj->parsed_uri->type == P11PROV_URI_PRIVATE_KEY) {
            obj->key = find_key(slot, true,
                                obj->parsed_uri->id,
                                obj->parsed_uri->id_len,
                                obj->parsed_uri->object);
        }
        /* for keys return on first match */
        if (obj->key) break;
    }

    obj->loaded = 1;

    if (obj->cert) {
        /* FIXME: return error for now */
        return 0;
    }
    if (obj->key) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;
        int key_type = PKCS11_get_key_type(obj->key);
        char *type;

        params[0] = OSSL_PARAM_construct_int(
                        OSSL_OBJECT_PARAM_TYPE, &object_type);

        /* we only support RSA so far */
        switch (key_type) {
        case EVP_PKEY_RSA:
            /* we have to handle private keys as our own type,
             * while we can let openssl import public keys and
             * deal with them in the default provider */
            if (obj->key->isPrivate) type = P11PROV_NAMES_RSA;
            else type = "RSA";
            break;
        default:
            return 0;
        }
        params[1] = OSSL_PARAM_construct_utf8_string(
                        OSSL_OBJECT_PARAM_DATA_TYPE, type, 0);

        /* giving away the object by reference */
        obj->ref++;
        params[2] = OSSL_PARAM_construct_octet_string(
                        OSSL_OBJECT_PARAM_REFERENCE, &obj, sizeof(obj));
        params[3] = OSSL_PARAM_construct_end();

        return object_cb(params, object_cbarg);
    }
    return 0;
}

static int p11prov_object_eof(void *ctx)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;

    fprintf(stderr, "object eof (%p)\n", obj);
    fflush(stderr);

    return obj->loaded?1:0;
}

static int p11prov_object_close(void *ctx)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;

    fprintf(stderr, "object close (%p)\n", obj);
    fflush(stderr);

    if (obj == NULL) return 0;

    p11prov_object_free(obj);
    return 1;
}

static int p11prov_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    fprintf(stderr, "set ctx params (%p, %p)\n", loaderctx, params);
    fflush(stderr);

    return 1;
}

int p11prov_object_export_public(P11PROV_OBJECT *obj,
                                 OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    /* ugly libp11 stuff that goes through a legacy EVP_PKEY,
     * forcing 4 alloc/free for each parameter passing... */
    OSSL_PARAM params[3];
    EVP_PKEY *pkey;
    BIGNUM *n = NULL, *e = NULL;
    unsigned char n_data[2048], e_data[2048];
    size_t n_size, e_size;
    int ret = 0;

    pkey = PKCS11_get_public_key(obj->key);
    if (pkey == NULL) return 0;

    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
    if (ret == 0) goto done;
    n_size = (size_t)BN_num_bytes(n);
    ret = BN_bn2nativepad(n, n_data, n_size);
    if (ret < 0) {
        ret = 0;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
    if (ret == 0) goto done;
    e_size = (size_t)BN_num_bytes(e);
    ret = BN_bn2nativepad(e, e_data, e_size);
    if (ret < 0) {
        ret = 0;
        goto done;
    }

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        n_data, n_size);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                        e_data, e_size);
    params[2] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    BN_free(n);
    BN_free(e);

    return ret;
}

static int p11prov_object_export(void *loaderctx, const void *reference,
                                 size_t reference_sz, OSSL_CALLBACK *cb_fn,
                                 void *cb_arg)
{
    P11PROV_OBJECT *obj = NULL;

    fprintf(stderr, "object export %p, %ld\n", reference, reference_sz);
    fflush(stderr);

    if (!reference || reference_sz != sizeof(obj))
        return 0;

    /* the contents of the reference is the address to our object */
    obj = *(P11PROV_OBJECT **)reference;
    /* we grabbed it, so we detach it */
    *(P11PROV_OBJECT **)reference = NULL;

    /* we can only export public bits, so that's all we do */
    return p11prov_object_export_public(obj, cb_fn, cb_arg);
}

const OSSL_DISPATCH p11prov_object_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))p11prov_object_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))p11prov_object_attach },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))p11prov_object_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))p11prov_object_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))p11prov_object_close },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))p11prov_set_ctx_params },
    { OSSL_FUNC_STORE_EXPORT_OBJECT, (void(*)(void))p11prov_object_export },
    { 0, NULL }
};

