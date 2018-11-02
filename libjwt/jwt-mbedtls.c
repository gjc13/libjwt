#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <jwt.h>

#include "config.h"
#include "jwt-private.h"

#define SHA256_OUT_SIZE (32)
#define SHA384_OUT_SIZE (48)
#define SHA512_OUT_SIZE (64)

#define RSA_HASH_BUF_SIZE (256)

int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len, const char *str)
{
    int                  out_size;
    mbedtls_md_type_t    md_type;

    switch (jwt->alg)
    {
    /* HMAC */
    case JWT_ALG_HS256:
        out_size = SHA256_OUT_SIZE;
        md_type  = MBEDTLS_MD_SHA256;
        break;
    case JWT_ALG_HS384:
        out_size = SHA384_OUT_SIZE;
        md_type  = MBEDTLS_MD_SHA384;
        break;
    case JWT_ALG_HS512:
        out_size = SHA512_OUT_SIZE;
        md_type  = MBEDTLS_MD_SHA512;
        break;
    default:
        return EINVAL;
    }

    *out = malloc(out_size);
    if (*out == NULL)
        return ENOMEM;

    mbedtls_md_hmac(mbedtls_md_info_from_type(md_type), jwt->key, jwt->key_len,
            (const unsigned char*)str, strlen(str), (unsigned char*)*out);
    *len = out_size;

    return 0;
}

int jwt_verify_sha_hmac(jwt_t *jwt, const char *head, const char *sig)
{
    char *       sig_check, *buf = NULL;
    unsigned int len;
    int          ret = EINVAL;

    if (!jwt_sign_sha_hmac(jwt, &sig_check, &len, head))
    {
        size_t buf_len = len * 2;
        size_t base64_len;
        buf = alloca(len * 2);
        mbedtls_base64_encode((unsigned char *)buf, base64_len, &base64_len, (unsigned char *)sig_check, len);
        jwt_base64uri_encode(buf);

        if (!strcmp(sig, buf))
            ret = 0;

        free(sig_check);
    }

    return ret;
}

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len, const char *str)
{
    int                      ret;
    mbedtls_pk_context       pk;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_type_t        pk_type;
    mbedtls_md_type_t        md_type;
    unsigned char            hash[RSA_HASH_BUF_SIZE];
    unsigned char            out_buf[MBEDTLS_MPI_MAX_SIZE];
    size_t                   out_size;
    const unsigned char* pers = (const unsigned char *)"jwt";
    size_t pers_len = 3;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    switch (jwt->alg)
    {
    /* RSA */
    case JWT_ALG_RS256:
        md_type   = MBEDTLS_MD_SHA256;
        pk_type   = MBEDTLS_PK_RSA;
        break;
    case JWT_ALG_RS384:
        md_type   = MBEDTLS_MD_SHA384;
        pk_type   = MBEDTLS_PK_RSA;
        break;
    case JWT_ALG_RS512:
        md_type   = MBEDTLS_MD_SHA512;
        pk_type   = MBEDTLS_PK_RSA;
        break;

    /* ECC */
    case JWT_ALG_ES256:
    case JWT_ALG_ES384:
    case JWT_ALG_ES512:
    default:
        ret = EINVAL;
        goto exit;
    }

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, pers_len) != 0)
    {
        goto exit;
    }

    if (mbedtls_pk_parse_key(&pk, jwt->key, strlen(jwt->key) + 1, NULL, 0) != 0)
    {
        ret = EINVAL;
        goto exit;
    }

    if (pk_type != mbedtls_pk_get_type(&pk))
    {
        ret = EINVAL;
        goto exit;
    }

    if (mbedtls_md(mbedtls_md_info_from_type(md_type), (const unsigned char *)str, strlen(str), hash) != 0)
    {
        ret = EINVAL;
        goto exit;
    }

    if (mbedtls_pk_sign(&pk, md_type, hash, 0, out_buf, &out_size, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ret = EINVAL;
        goto exit;
    }

    *out = malloc(out_size);
    memcpy(*out, out_buf, out_size);
    *len = out_size;
    ret = 0;
exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_free(&pk);
    return ret;
}

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64)
{
    int                ret;
    unsigned char *    sig = NULL;
    int                sig_len;
    mbedtls_pk_context pk;
    mbedtls_pk_type_t  pk_type;
    mbedtls_md_type_t  md_type;
    unsigned char      hash[RSA_HASH_BUF_SIZE];

    mbedtls_pk_init(&pk);

    switch (jwt->alg)
    {
    /* RSA */
    case JWT_ALG_RS256:
        md_type   = MBEDTLS_MD_SHA256;
        pk_type   = MBEDTLS_PK_RSA;
        break;
    case JWT_ALG_RS384:
        md_type   = MBEDTLS_MD_SHA384;
        pk_type   = MBEDTLS_PK_RSA;
        break;
    case JWT_ALG_RS512:
        md_type   = MBEDTLS_MD_SHA512;
        pk_type   = MBEDTLS_PK_RSA;
        break;

    /* ECC */
    case JWT_ALG_ES256:
    case JWT_ALG_ES384:
    case JWT_ALG_ES512:
    default:
        ret = EINVAL;
        goto exit;
    }

    sig = (unsigned char *)jwt_b64_decode(sig_b64, &sig_len);

    if (sig == NULL)
    {
        ret = EINVAL;
        goto exit;
    }

    if (mbedtls_pk_parse_public_key(&pk, jwt->key, strlen(jwt->key) + 1) != 0)
    {
        ret = EINVAL;
        goto exit;
    }

    if (pk_type != mbedtls_pk_get_type(&pk))
    {
        ret = EINVAL;
        goto exit_freesig;
    }

    if (mbedtls_md(mbedtls_md_info_from_type(md_type), (const unsigned char *)head, strlen(head), hash) != 0)
    {
        ret = EINVAL;
        goto exit_freesig;
    }

    if (mbedtls_pk_verify(&pk, md_type, hash, 0, sig, sig_len) != 0)
    {
        ret = EINVAL;
        goto exit_freesig;
    }

    ret = 0;
exit_freesig:
    free(sig);
exit:
    return ret;
}
