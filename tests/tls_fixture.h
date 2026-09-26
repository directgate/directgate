/*
 * A throwaway TLS identity on disk, for tests that stand up an HTTPS or WSS
 * endpoint the agent (or dgcli) has to trust.
 *
 * One P-256 certificate for 127.0.0.1 and localhost that is its own CA: point
 * SSL_CERT_FILE at sCert and the agent's normal verification accepts it, so
 * the test exercises the real TLS path rather than a disabled one. P-256
 * because RSA generation would dominate the runtime.
 */

#ifndef DIRECTGATE_TESTS_TLS_FIXTURE_H
#define DIRECTGATE_TESTS_TLS_FIXTURE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef struct {
    char sRoot[64];
    char sCert[128];
    char sKey[128];
    int bCreated;
} tls_fixture_t;

static int tls_fixture_add_ext(X509 *pCert, int nNid, const char *pValue)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, pCert, pCert, NULL, NULL, 0);

    X509_EXTENSION *pExt = X509V3_EXT_conf_nid(NULL, &ctx, nNid, pValue);
    if (pExt == NULL) return 0;

    int nOk = X509_add_ext(pCert, pExt, -1) == 1;
    X509_EXTENSION_free(pExt);
    return nOk;
}

/* Returns 1 with the certificate and key written, 0 on any failure. */
static int tls_fixture_begin(tls_fixture_t *pFix)
{
    memset(pFix, 0, sizeof(*pFix));
    snprintf(pFix->sRoot, sizeof(pFix->sRoot), "/tmp/directgate_tls.XXXXXX");
    if (mkdtemp(pFix->sRoot) == NULL) return 0;
    pFix->bCreated = 1;

    snprintf(pFix->sCert, sizeof(pFix->sCert), "%s/cert.pem", pFix->sRoot);
    snprintf(pFix->sKey, sizeof(pFix->sKey), "%s/key.pem", pFix->sRoot);

    EVP_PKEY *pKey = NULL;
    EVP_PKEY_CTX *pKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pKeyCtx == NULL) return 0;

    if (EVP_PKEY_keygen_init(pKeyCtx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pKeyCtx, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(pKeyCtx, &pKey) != 1)
    {
        EVP_PKEY_CTX_free(pKeyCtx);
        return 0;
    }

    EVP_PKEY_CTX_free(pKeyCtx);
    X509 *pCert = X509_new();
    int nOk = pCert != NULL;

    if (nOk)
    {
        X509_set_version(pCert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(pCert), 1);
        X509_gmtime_adj(X509_getm_notBefore(pCert), -3600);
        X509_gmtime_adj(X509_getm_notAfter(pCert), 24 * 3600);
        X509_set_pubkey(pCert, pKey);

        X509_NAME *pName = X509_get_subject_name(pCert);
        X509_NAME_add_entry_by_txt(pName, "CN", MBSTRING_ASC, (const unsigned char*)"127.0.0.1", -1, -1, 0);
        X509_set_issuer_name(pCert, pName);

        /* Trusted as a CA through SSL_CERT_FILE, matched as a server by its SAN. */
        nOk = tls_fixture_add_ext(pCert, NID_basic_constraints, "critical,CA:TRUE") &&
              tls_fixture_add_ext(pCert, NID_key_usage, "critical,digitalSignature,keyCertSign") &&
              tls_fixture_add_ext(pCert, NID_subject_key_identifier, "hash") &&
              tls_fixture_add_ext(pCert, NID_subject_alt_name, "IP:127.0.0.1,DNS:localhost") &&
              X509_sign(pCert, pKey, EVP_sha256()) > 0;
    }

    if (nOk)
    {
        FILE *pFile = fopen(pFix->sCert, "wb");
        nOk = pFile != NULL && PEM_write_X509(pFile, pCert) == 1;
        if (pFile != NULL) fclose(pFile);
    }

    if (nOk)
    {
        FILE *pFile = fopen(pFix->sKey, "wb");
        nOk = pFile != NULL && PEM_write_PrivateKey(pFile, pKey, NULL, NULL, 0, NULL, NULL) == 1;
        if (pFile != NULL) fclose(pFile);
    }

    X509_free(pCert);
    EVP_PKEY_free(pKey);
    return nOk;
}

static void tls_fixture_end(tls_fixture_t *pFix)
{
    if (!pFix->bCreated) return;
    unlink(pFix->sCert);
    unlink(pFix->sKey);
    rmdir(pFix->sRoot);
    pFix->bCreated = 0;
}

#endif /* DIRECTGATE_TESTS_TLS_FIXTURE_H */
