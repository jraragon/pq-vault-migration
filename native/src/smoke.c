/*
 * P15 -- smoke test (F2, step 1). NOT a benchmark.
 *
 * Checks, with the local OpenSSL:
 *   1. RSA-3072 OAEP (SHA-256, MGF1-SHA-256, empty label) wraps and unwraps a
 *      32-byte key; ML-KEM-768 and ML-KEM-1024 encapsulate and decapsulate to
 *      the same 32-byte shared secret.
 *   2. Sizes of public keys (raw and SPKI DER), stored private keys (seed,
 *      expanded, PKCS#8 DER as encoded by default) and ciphertexts match the
 *      table of the pre-registration (FIPS 203, RFC 9935).
 *   3. An ML-KEM key re-created from its 64-byte seed alone gives the same
 *      public key and decapsulates the same ciphertext (seed storage works).
 * Prints indicative timings (single runs, no controls) only as a sanity check.
 * Exit code 0 only if every check passes.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; printf("  FAIL: " __VA_ARGS__); printf("\n"); } \
                              else { printf("  ok:   " __VA_ARGS__); printf("\n"); } } while (0)

static double now_us(void) {
    struct timespec ts; timespec_get(&ts, TIME_UTC);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void die(const char *what) {
    fprintf(stderr, "OpenSSL error in %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(2);
}

static int spki_len(EVP_PKEY *k) { return i2d_PUBKEY(k, NULL); }
static int pkcs8_len(EVP_PKEY *k) {
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(k);
    if (!p8) die("EVP_PKEY2PKCS8");
    int n = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return n;
}

/* ------------------------------------------------------------------ ML-KEM */
static void test_mlkem(const char *alg, size_t exp_pk, size_t exp_sk, size_t exp_ct) {
    printf("\n[%s]\n", alg);
    double t0, t1;
    EVP_PKEY *key = NULL;
    t0 = now_us();
    key = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    t1 = now_us();
    if (!key) die("keygen");
    printf("  keygen: %.1f us (indicative)\n", t1 - t0);

    unsigned char pk[2048], sk[4096], seed[64];
    size_t pklen = 0, sklen = 0, seedlen = 0;
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pk, sizeof pk, &pklen)) die("get pub");
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, sk, sizeof sk, &sklen)) die("get priv");
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof seed, &seedlen)) die("get seed");
    CHECK(pklen == exp_pk, "public key raw = %zu bytes (expected %zu)", pklen, exp_pk);
    CHECK(sklen == exp_sk, "private key expanded = %zu bytes (expected %zu)", sklen, exp_sk);
    CHECK(seedlen == 64, "private key seed = %zu bytes (expected 64)", seedlen);
    printf("  SPKI DER = %d bytes; PKCS#8 DER (library default encoding) = %d bytes\n",
           spki_len(key), pkcs8_len(key));

    /* encapsulate */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    unsigned char ct[2048], ss1[64], ss2[64];
    size_t ctlen = sizeof ct, ss1len = sizeof ss1, ss2len = sizeof ss2;
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) die("encap init");
    t0 = now_us();
    if (EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss1, &ss1len) <= 0) die("encap");
    t1 = now_us();
    printf("  encapsulate: %.1f us (indicative)\n", t1 - t0);
    CHECK(ctlen == exp_ct, "ciphertext = %zu bytes (expected %zu)", ctlen, exp_ct);
    CHECK(ss1len == 32, "shared secret = %zu bytes (expected 32)", ss1len);
    EVP_PKEY_CTX_free(ctx);

    /* decapsulate with the original key */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) die("decap init");
    t0 = now_us();
    if (EVP_PKEY_decapsulate(ctx, ss2, &ss2len, ct, ctlen) <= 0) die("decap");
    t1 = now_us();
    printf("  decapsulate: %.1f us (indicative)\n", t1 - t0);
    CHECK(ss2len == ss1len && memcmp(ss1, ss2, ss1len) == 0, "decapsulated secret matches");
    EVP_PKEY_CTX_free(ctx);

    /* re-create the key from the seed only (seed storage path) */
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, seedlen),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY *k2 = NULL;
    EVP_PKEY_CTX *fctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    t0 = now_us();
    if (!fctx || EVP_PKEY_fromdata_init(fctx) <= 0 ||
        EVP_PKEY_fromdata(fctx, &k2, EVP_PKEY_KEYPAIR, params) <= 0) die("fromdata(seed)");
    t1 = now_us();
    printf("  load from seed (expansion): %.1f us (indicative)\n", t1 - t0);
    EVP_PKEY_CTX_free(fctx);
    unsigned char pk2[2048]; size_t pk2len = 0;
    if (!EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PUB_KEY, pk2, sizeof pk2, &pk2len)) die("get pub2");
    CHECK(pk2len == pklen && memcmp(pk, pk2, pklen) == 0, "public key re-derived from seed matches");
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, k2, NULL);
    ss2len = sizeof ss2;
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(ctx, ss2, &ss2len, ct, ctlen) <= 0) die("decap(seed key)");
    CHECK(ss2len == ss1len && memcmp(ss1, ss2, ss1len) == 0, "seed-derived key decapsulates the same secret");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(key);
}

/* ------------------------------------------------------------------ RSA */
static void test_rsa3072(void) {
    printf("\n[RSA-3072 OAEP-SHA-256]\n");
    double t0, t1;
    t0 = now_us();
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072);
    t1 = now_us();
    if (!key) die("rsa keygen");
    printf("  keygen: %.1f us (indicative)\n", t1 - t0);
    unsigned char *der = NULL;
    int publen = i2d_PublicKey(key, NULL);        /* RSAPublicKey */
    int privlen = i2d_PrivateKey(key, NULL);      /* RSAPrivateKey */
    CHECK(publen == 398, "RSAPublicKey DER = %d bytes (expected 398)", publen);
    CHECK(privlen >= 1764 && privlen <= 1770, "RSAPrivateKey DER = %d bytes (expected 1764-1770)", privlen);
    CHECK(spki_len(key) == 422, "SPKI DER = %d bytes (expected 422)", spki_len(key));
    printf("  PKCS#8 DER = %d bytes\n", pkcs8_len(key));
    (void)der;

    unsigned char k32[32], ct[512], out[512];
    size_t ctlen = sizeof ct, outlen = sizeof out;
    for (int i = 0; i < 32; i++) k32[i] = (unsigned char)i;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) die("oaep enc init");
    t0 = now_us();
    if (EVP_PKEY_encrypt(ctx, ct, &ctlen, k32, sizeof k32) <= 0) die("oaep enc");
    t1 = now_us();
    printf("  encrypt (wrap 32 B): %.1f us (indicative)\n", t1 - t0);
    CHECK(ctlen == 384, "ciphertext = %zu bytes (expected 384)", ctlen);
    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) die("oaep dec init");
    t0 = now_us();
    if (EVP_PKEY_decrypt(ctx, out, &outlen, ct, ctlen) <= 0) die("oaep dec");
    t1 = now_us();
    printf("  decrypt (unwrap): %.1f us (indicative)\n", t1 - t0);
    CHECK(outlen == 32 && memcmp(out, k32, 32) == 0, "unwrapped key matches");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

int main(void) {
    printf("P15 smoke test\n");
    printf("OpenSSL headers: %s\n", OPENSSL_VERSION_TEXT);
    printf("OpenSSL library: %s\n", OpenSSL_version(OPENSSL_VERSION));
    test_rsa3072();
    test_mlkem("ML-KEM-768", 1184, 2400, 1088);
    test_mlkem("ML-KEM-1024", 1568, 3168, 1568);
    printf("\n%s (%d failure%s)\n", failures ? "SMOKE TEST FAILED" : "SMOKE TEST PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
