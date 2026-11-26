/*
 * P15 -- native reference implementation and benchmark for architecture A1
 * (asymmetric boundary at the account root; JCP construction).
 *
 * Suites (pre-registration, Section 4):
 *   rsa3072   RSA-3072 OAEP (SHA-256, MGF1-SHA-256, empty label) wrapping a
 *             random 32-byte secret (RSA used as a KEM by key transport)
 *   mlkem768  ML-KEM-768 (FIPS 203)
 *   mlkem1024 ML-KEM-1024 (FIPS 203)
 *   hybrid    id-MLKEM1024-RSA3072-SHA3-256 (draft-ietf-lamps-pq-composite-kem):
 *             ct = ct_ML || ct_RSA,
 *             ss = SHA3-256(ss_ML || ss_RSA || ct_RSA || pk_RSA || Label)
 *
 * Stored private-key format (factor): seed | expanded (RFC 9935 OneAsymmetricKey;
 * the hybrid stores seed||RSAPrivateKey as in the composite draft, or
 * expanded||RSAPrivateKey as the experimental "expanded" level).
 *
 * Access package (one per holder):
 *   version(1) || suite_id(1) || kem_ct || AES-256-KW(KEK, root_key)  (40 bytes)
 *   KEK = HKDF-SHA256(ikm = ss, salt = empty,
 *                     info = "P15/A1/package/v1" || suite_id || holder_id(4, BE))
 *   The suite identifier is authenticated through the KDF: a package opened
 *   under the wrong suite yields the wrong KEK and AES-KW integrity fails.
 * Hierarchy: the root key wraps its n_f children with AES-256-KW (40 bytes each).
 *
 * Modes:
 *   p15_a1 selftest                         correctness checks (exit 0 = pass)
 *   p15_a1 sizes                            E1 artefact sizes, CSV on stdout
 *   p15_a1 bench --suite S --format F --op O [--iters N] [--warmup W]
 *                [--nf K] [--cpu C] [--out FILE]
 *       ops: open (E2: cold credential -> decapsulate -> unwrap root -> unwrap
 *            n_f children), keygen, encap, decap, load (credential parse,
 *            including seed expansion where applicable)
 * One invocation = one run (the experimental unit). Randomisation of runs
 * into blocks is done by the driver script, not here.
 */
#ifndef _WIN32
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0A00
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <sched.h>
#  include <unistd.h>
#endif

/* ================================================================ utilities */
static void die(const char *what) {
    fprintf(stderr, "fatal: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(2);
}

#ifdef _WIN32
static double tick_ns;  /* nanoseconds per QPC tick */
static void clock_init(void) {
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); tick_ns = 1e9 / (double)f.QuadPart;
}
static inline uint64_t now_ticks(void) { LARGE_INTEGER c; QueryPerformanceCounter(&c); return (uint64_t)c.QuadPart; }
#else
static double tick_ns = 1.0;
static void clock_init(void) {}
static inline uint64_t now_ticks(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif

/* Pin the calling thread to one logical CPU and report its efficiency class. */
static int pin_cpu(int cpu, char *info, size_t infolen) {
    if (cpu < 0) { snprintf(info, infolen, "not pinned"); return 0; }
#ifdef _WIN32
    if (!SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << cpu)) return -1;
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    /* Efficiency class of the chosen logical processor (higher = faster core). */
    ULONG len = 0; int eff = -1;
    GetSystemCpuSetInformation(NULL, 0, &len, GetCurrentProcess(), 0);
    if (len) {
        unsigned char *buf = malloc(len);
        if (buf && GetSystemCpuSetInformation((PSYSTEM_CPU_SET_INFORMATION)buf, len, &len, GetCurrentProcess(), 0)) {
            for (ULONG off = 0; off < len;) {
                PSYSTEM_CPU_SET_INFORMATION s = (PSYSTEM_CPU_SET_INFORMATION)(buf + off);
                if (s->Type == CpuSetInformation && s->CpuSet.LogicalProcessorIndex == (BYTE)cpu)
                    eff = s->CpuSet.EfficiencyClass;
                off += s->Size;
            }
        }
        free(buf);
    }
    snprintf(info, infolen, "logical CPU %d, efficiency class %d, high priority", cpu, eff);
#else
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) return -1;
    snprintf(info, infolen, "logical CPU %d", cpu);
#endif
    return 0;
}

/* List logical CPUs with their efficiency class (Windows) to choose a P-core. */
static void list_cpus(void) {
#ifdef _WIN32
    ULONG len = 0;
    GetSystemCpuSetInformation(NULL, 0, &len, GetCurrentProcess(), 0);
    unsigned char *buf = malloc(len);
    if (!buf || !GetSystemCpuSetInformation((PSYSTEM_CPU_SET_INFORMATION)buf, len, &len, GetCurrentProcess(), 0)) die("cpu sets");
    printf("logical_cpu,core_index,efficiency_class\n");
    for (ULONG off = 0; off < len;) {
        PSYSTEM_CPU_SET_INFORMATION s = (PSYSTEM_CPU_SET_INFORMATION)(buf + off);
        if (s->Type == CpuSetInformation)
            printf("%u,%u,%u\n", s->CpuSet.LogicalProcessorIndex, s->CpuSet.CoreIndex, s->CpuSet.EfficiencyClass);
        off += s->Size;
    }
    printf("# higher efficiency class = performance core (P-core)\n");
    free(buf);
#else
    printf("cpus: only implemented on Windows (%ld online CPUs)\n", sysconf(_SC_NPROCESSORS_ONLN));
#endif
}

/* ---------------------------------------------------------------- DER helpers */
typedef struct { unsigned char *p; size_t n, cap; } buf_t;
static void b_put(buf_t *b, const void *d, size_t n) {
    if (b->n + n > b->cap) { b->cap = (b->n + n) * 2 + 64; b->p = realloc(b->p, b->cap); if (!b->p) die("oom"); }
    memcpy(b->p + b->n, d, n); b->n += n;
}
static void b_byte(buf_t *b, unsigned char c) { b_put(b, &c, 1); }
static void der_len(buf_t *b, size_t n) {
    if (n < 0x80) b_byte(b, (unsigned char)n);
    else if (n < 0x100) { b_byte(b, 0x81); b_byte(b, (unsigned char)n); }
    else { b_byte(b, 0x82); b_byte(b, (unsigned char)(n >> 8)); b_byte(b, (unsigned char)n); }
}
static void der_tlv(buf_t *b, unsigned char tag, const void *v, size_t n) { b_byte(b, tag); der_len(b, n); b_put(b, v, n); }

/* OneAsymmetricKey v1 with absent parameters and the given privateKey content. */
static buf_t pkcs8_wrap(const unsigned char *oid_der, size_t oidlen, const unsigned char *pk, size_t pklen) {
    buf_t alg = {0}, octet = {0}, body = {0}, out = {0};
    der_tlv(&alg, 0x30, oid_der, oidlen);
    static const unsigned char ver[] = {0x02, 0x01, 0x00};
    b_put(&body, ver, 3);
    b_put(&body, alg.p, alg.n);
    der_tlv(&octet, 0x04, pk, pklen);
    b_put(&body, octet.p, octet.n);
    der_tlv(&out, 0x30, body.p, body.n);
    free(alg.p); free(octet.p); free(body.p);
    return out;
}

/* OIDs (DER, tag+len+value) */
static const unsigned char OID_MLKEM768[]  = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x02};
static const unsigned char OID_MLKEM1024[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x03};
/* id-MLKEM1024-RSA3072-SHA3-256 = 1.3.6.1.5.5.7.6.62 */
static const unsigned char OID_HYBRID[]    = {0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x06,0x3e};
static const char HYBRID_LABEL[] = "MLKEM1024-RSAOAEP3072";

/* ================================================================ suites */
typedef enum { S_RSA, S_ML768, S_ML1024, S_HYB, S_N } suite_t;
typedef enum { F_SEED, F_EXP, F_NA } fmt_t;
static const char *SUITE_NAME[] = {"rsa3072", "mlkem768", "mlkem1024", "hybrid"};
static const char *FMT_NAME[]   = {"seed", "expanded", "na"};
static const unsigned char SUITE_ID[] = {0x01, 0x02, 0x03, 0x04};

static const char *ml_alg(suite_t s) { return s == S_ML768 ? "ML-KEM-768" : "ML-KEM-1024"; }
static int has_ml(suite_t s)  { return s != S_RSA; }
static int has_rsa(suite_t s) { return s == S_RSA || s == S_HYB; }

/* Public side (what an encapsulating client holds). */
typedef struct {
    EVP_PKEY *ml, *rsa;
    unsigned char rsa_pub_der[512]; size_t rsa_pub_len;  /* RSAPublicKey, for the combiner */
    size_t ml_pub_len;
} pub_t;
/* Private side, as loaded from stored credential bytes. */
typedef struct { EVP_PKEY *ml, *rsa; } priv_t;

static EVP_PKEY_CTX *rsa_oaep_ctx(EVP_PKEY *k, int enc) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    if (!c || (enc ? EVP_PKEY_encrypt_init(c) : EVP_PKEY_decrypt_init(c)) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(c, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(c, EVP_sha256()) <= 0) die("rsa oaep ctx");
    return c;
}

/* Generate a credential: stored private bytes (PKCS#8 DER) + public handles. */
static buf_t gen_credential(suite_t s, fmt_t f, pub_t *pub) {
    memset(pub, 0, sizeof *pub);
    unsigned char seed[64], exp[3168];
    size_t seedlen = 0, explen = 0;
    EVP_PKEY *ml = NULL, *rsa = NULL;
    if (has_ml(s)) {
        ml = EVP_PKEY_Q_keygen(NULL, NULL, ml_alg(s));
        if (!ml) die("ml keygen");
        if (!EVP_PKEY_get_octet_string_param(ml, OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof seed, &seedlen) ||
            !EVP_PKEY_get_octet_string_param(ml, OSSL_PKEY_PARAM_PRIV_KEY, exp, sizeof exp, &explen)) die("ml export");
        unsigned char pk[1568]; size_t pklen = 0;
        if (!EVP_PKEY_get_octet_string_param(ml, OSSL_PKEY_PARAM_PUB_KEY, pk, sizeof pk, &pklen)) die("ml pub");
        pub->ml_pub_len = pklen;
    }
    if (has_rsa(s)) {
        rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072);
        if (!rsa) die("rsa keygen");
        unsigned char *q = pub->rsa_pub_der;
        int n = i2d_PublicKey(rsa, &q);
        if (n <= 0) die("rsa pub der");
        pub->rsa_pub_len = (size_t)n;
    }
    pub->ml = ml; pub->rsa = rsa;

    buf_t out = {0};
    if (s == S_RSA) {
        PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(rsa);
        int n = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
        out.p = malloc((size_t)n); out.n = out.cap = (size_t)n;
        unsigned char *q = out.p; i2d_PKCS8_PRIV_KEY_INFO(p8, &q);
        PKCS8_PRIV_KEY_INFO_free(p8);
    } else if (s == S_ML768 || s == S_ML1024) {
        const unsigned char *oid = s == S_ML768 ? OID_MLKEM768 : OID_MLKEM1024;
        buf_t choice = {0};
        if (f == F_SEED) der_tlv(&choice, 0x80, seed, seedlen);          /* seed [0] IMPLICIT */
        else             der_tlv(&choice, 0x04, exp, explen);            /* expandedKey */
        out = pkcs8_wrap(oid, sizeof OID_MLKEM1024, choice.p, choice.n);
        free(choice.p);
    } else { /* hybrid: (seed | expanded) || RSAPrivateKey */
        buf_t raw = {0};
        if (f == F_SEED) b_put(&raw, seed, seedlen); else b_put(&raw, exp, explen);
        int n = i2d_PrivateKey(rsa, NULL);
        unsigned char *tmp = malloc((size_t)n), *q = tmp;
        i2d_PrivateKey(rsa, &q);
        b_put(&raw, tmp, (size_t)n); free(tmp);
        out = pkcs8_wrap(OID_HYBRID, sizeof OID_HYBRID, raw.p, raw.n);
        free(raw.p);
    }
    OPENSSL_cleanse(seed, sizeof seed); OPENSSL_cleanse(exp, sizeof exp);
    return out;
}

static __attribute__((unused)) EVP_PKEY *ml_from_raw(suite_t s, const unsigned char *p, size_t n, fmt_t f) {
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(f == F_SEED ? OSSL_PKEY_PARAM_ML_KEM_SEED : OSSL_PKEY_PARAM_PRIV_KEY,
                                          (void *)p, n),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, ml_alg(s), NULL);
    if (!c || EVP_PKEY_fromdata_init(c) <= 0 || EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, params) <= 0) die("ml fromdata");
    EVP_PKEY_CTX_free(c);
    return k;
}

/* Load a stored credential (the cost a client pays on every cold open). */
static void load_credential(suite_t s, fmt_t f, const buf_t *der, priv_t *pv) {
    pv->ml = pv->rsa = NULL;
    const unsigned char *q = der->p;
    if (s != S_HYB) {
        /* Standard PKCS#8: RSA, or ML-KEM seed / expanded CHOICE (RFC 9935). */
        EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &q, (long)der->n);
        if (!k) die("d2i credential");
        if (s == S_RSA) pv->rsa = k; else pv->ml = k;
        return;
    }
    PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &q, (long)der->n);
    const unsigned char *raw; int rawlen; const X509_ALGOR *alg;
    if (!p8 || !PKCS8_pkey_get0(NULL, &raw, &rawlen, &alg, p8)) die("hybrid p8");
    size_t mllen = f == F_SEED ? 64 : 3168;
    /* Same loading path as the pure ML-KEM suites (D-013): the ML-KEM component is
     * decoded through the library's PKCS#8 decoder (RFC 9935 encoding), so that
     * library defaults on import (e.g. the pairwise consistency test that OpenSSL
     * runs on expanded keys) apply identically to every suite. */
    {
        buf_t choice = {0};
        der_tlv(&choice, f == F_SEED ? 0x80 : 0x04, raw, mllen);
        buf_t mlp8 = pkcs8_wrap(OID_MLKEM1024, sizeof OID_MLKEM1024, choice.p, choice.n);
        const unsigned char *mq = mlp8.p;
        pv->ml = d2i_AutoPrivateKey(NULL, &mq, (long)mlp8.n);
        OPENSSL_clear_free(choice.p, choice.n); OPENSSL_clear_free(mlp8.p, mlp8.n);
        if (!pv->ml) die("hybrid ml part");
    }
    const unsigned char *r = raw + mllen;
    pv->rsa = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &r, rawlen - (long)mllen);
    if (!pv->rsa) die("hybrid rsa part");
    PKCS8_PRIV_KEY_INFO_free(p8);
}
static void free_priv(priv_t *pv) { EVP_PKEY_free(pv->ml); EVP_PKEY_free(pv->rsa); }

static void hybrid_combine(const unsigned char *ssml, const unsigned char *ssrsa,
                           const unsigned char *ctrsa, const pub_t *pubinfo_or_null,
                           const unsigned char *rsapub, size_t rsapublen, unsigned char out[32]) {
    (void)pubinfo_or_null;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned int olen = 0;
    if (!m || !EVP_DigestInit_ex(m, EVP_sha3_256(), NULL) ||
        !EVP_DigestUpdate(m, ssml, 32) || !EVP_DigestUpdate(m, ssrsa, 32) ||
        !EVP_DigestUpdate(m, ctrsa, 384) || !EVP_DigestUpdate(m, rsapub, rsapublen) ||
        !EVP_DigestUpdate(m, HYBRID_LABEL, strlen(HYBRID_LABEL)) ||
        !EVP_DigestFinal_ex(m, out, &olen) || olen != 32) die("sha3 combiner");
    EVP_MD_CTX_free(m);
}

/* Encapsulate to a holder's public key: ct (returned length) and 32-byte ss. */
static size_t encap(suite_t s, const pub_t *pub, unsigned char *ct, unsigned char ss[32]) {
    size_t mlct = 0;
    unsigned char ssml[32];
    if (has_ml(s)) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, pub->ml, NULL);
        size_t ctlen = 1568, sslen = 32;
        if (!c || EVP_PKEY_encapsulate_init(c, NULL) <= 0 ||
            EVP_PKEY_encapsulate(c, ct, &ctlen, ssml, &sslen) <= 0) die("ml encap");
        EVP_PKEY_CTX_free(c);
        mlct = ctlen;
        if (s != S_HYB) { memcpy(ss, ssml, 32); return mlct; }
    }
    unsigned char ssrsa[32];
    if (RAND_bytes(ssrsa, 32) != 1) die("rand");
    EVP_PKEY_CTX *c = rsa_oaep_ctx(pub->rsa, 1);
    size_t ctlen = 384;
    if (EVP_PKEY_encrypt(c, ct + mlct, &ctlen, ssrsa, 32) <= 0) die("rsa encrypt");
    EVP_PKEY_CTX_free(c);
    if (s == S_RSA) { memcpy(ss, ssrsa, 32); return ctlen; }
    hybrid_combine(ssml, ssrsa, ct + mlct, NULL, pub->rsa_pub_der, pub->rsa_pub_len, ss);
    return mlct + ctlen;
}

static void decap(suite_t s, const priv_t *pv, const unsigned char *ct, size_t ctlen, unsigned char ss[32],
                  const unsigned char *rsapub, size_t rsapublen) {
    unsigned char ssml[32], ssrsa[32];
    size_t mlct = 0;
    if (has_ml(s)) {
        mlct = (s == S_ML768) ? 1088 : 1568;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, pv->ml, NULL);
        size_t sslen = 32;
        if (!c || EVP_PKEY_decapsulate_init(c, NULL) <= 0 ||
            EVP_PKEY_decapsulate(c, ssml, &sslen, ct, mlct) <= 0) die("ml decap");
        EVP_PKEY_CTX_free(c);
        if (s != S_HYB) { memcpy(ss, ssml, 32); return; }
    }
    EVP_PKEY_CTX *c = rsa_oaep_ctx(pv->rsa, 0);
    size_t outlen = 32 + 0;
    unsigned char tmp[384];
    outlen = sizeof tmp;
    if (EVP_PKEY_decrypt(c, tmp, &outlen, ct + mlct, ctlen - mlct) <= 0 || outlen != 32) die("rsa decrypt");
    EVP_PKEY_CTX_free(c);
    memcpy(ssrsa, tmp, 32);
    if (s == S_RSA) { memcpy(ss, ssrsa, 32); return; }
    /* Combiner needs the holder's own RSA public key (derivable from the private key). */
    hybrid_combine(ssml, ssrsa, ct + mlct, NULL, rsapub, rsapublen, ss);
}

/* ------------------------------------------------------- KDF and key wrap */
static EVP_KDF *g_hkdf;
static EVP_CIPHER *g_kw;
static void kek_derive(const unsigned char ss[32], suite_t s, uint32_t holder, unsigned char kek[32]) {
    unsigned char info[32]; size_t il = 0;
    static const char lbl[] = "P15/A1/package/v1";
    memcpy(info, lbl, sizeof lbl - 1); il = sizeof lbl - 1;
    info[il++] = SUITE_ID[s];
    info[il++] = (unsigned char)(holder >> 24); info[il++] = (unsigned char)(holder >> 16);
    info[il++] = (unsigned char)(holder >> 8);  info[il++] = (unsigned char)holder;
    EVP_KDF_CTX *k = EVP_KDF_CTX_new(g_hkdf);
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ss, 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, il),
        OSSL_PARAM_construct_end()
    };
    if (!k || EVP_KDF_derive(k, kek, 32, p) <= 0) die("hkdf");
    EVP_KDF_CTX_free(k);
}
static int kw(int enc, const unsigned char key[32], const unsigned char *in, size_t inlen, unsigned char *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l1 = 0, l2 = 0;
    EVP_CIPHER_CTX_set_flags(c, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    int ok = EVP_CipherInit_ex2(c, g_kw, key, NULL, enc, NULL) &&
             EVP_CipherUpdate(c, out, &l1, in, (int)inlen) &&
             EVP_CipherFinal_ex(c, out + l1, &l2);
    EVP_CIPHER_CTX_free(c);
    return ok ? l1 + l2 : -1;
}

/* ------------------------------------------------------------ account (A1) */
#define MAXNF 256
typedef struct {
    suite_t s; fmt_t f;
    buf_t cred;            /* holder's stored private credential */
    pub_t pub;
    unsigned char pkg[2048]; size_t pkglen;      /* holder's access package */
    unsigned char root[32];
    unsigned char child_wrapped[MAXNF][40]; int nf;
} account_t;

static void account_create(account_t *a, suite_t s, fmt_t f, int nf, uint32_t holder) {
    memset(a, 0, sizeof *a);
    a->s = s; a->f = f; a->nf = nf;
    a->cred = gen_credential(s, f, &a->pub);
    if (RAND_bytes(a->root, 32) != 1) die("rand");
    unsigned char ss[32], kek[32];
    a->pkg[0] = 0x01; a->pkg[1] = SUITE_ID[s];
    size_t ctlen = encap(s, &a->pub, a->pkg + 2, ss);
    kek_derive(ss, s, holder, kek);
    if (kw(1, kek, a->root, 32, a->pkg + 2 + ctlen) != 40) die("wrap root");
    a->pkglen = 2 + ctlen + 40;
    for (int i = 0; i < nf; i++) {
        unsigned char child[32];
        if (RAND_bytes(child, 32) != 1) die("rand");
        if (kw(1, a->root, child, 32, a->child_wrapped[i]) != 40) die("wrap child");
    }
}

/* E2: open the account from cold stored credential bytes. Returns 0 on success. */
static int account_open(const account_t *a, uint32_t holder, unsigned char root_out[32]) {
    priv_t pv;
    load_credential(a->s, a->f, &a->cred, &pv);
    if (a->pkg[0] != 0x01 || a->pkg[1] != SUITE_ID[a->s]) { free_priv(&pv); return -1; }
    size_t ctlen = a->pkglen - 2 - 40;
    unsigned char ss[32], kek[32], child[40];
    decap(a->s, &pv, a->pkg + 2, ctlen, ss, a->pub.rsa_pub_der, a->pub.rsa_pub_len);
    kek_derive(ss, a->s, holder, kek);
    if (kw(0, kek, a->pkg + 2 + ctlen, 40, root_out) != 32) { free_priv(&pv); return -1; }
    for (int i = 0; i < a->nf; i++)
        if (kw(0, root_out, a->child_wrapped[i], 40, child) != 32) { free_priv(&pv); return -1; }
    free_priv(&pv);
    return 0;
}
static void account_free(account_t *a) {
    EVP_PKEY_free(a->pub.ml); EVP_PKEY_free(a->pub.rsa);
    OPENSSL_clear_free(a->cred.p, a->cred.n);
}

/* ================================================================ selftest */
static int fails = 0;
#define CHECK(c, ...) do { int _ok = (c); if (!_ok) fails++; printf("  %s ", _ok ? "ok:  " : "FAIL:"); printf(__VA_ARGS__); printf("\n"); } while (0)

#include "composite_kat.h"
static int b64dec(const char *in, unsigned char *out) {
    int n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)strlen(in));
    for (const char *c = in; *c; c++) if (*c == '=') n--;   /* EVP_DecodeBlock counts pad bytes */
    return n;
}

static void selftest(void) {
    printf("P15 A1 selftest -- %s\n", OpenSSL_version(OPENSSL_VERSION));
    /* RFC 9935 Appendix C.1.3.1: ML-KEM-1024 seed-format private key for seed 00..3f */
    const char *rfc_seed_pem = "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    unsigned char rfc[128]; int rl = b64dec(rfc_seed_pem, rfc);
    unsigned char seed[64]; for (int i = 0; i < 64; i++) seed[i] = (unsigned char)i;
    buf_t choice = {0}; der_tlv(&choice, 0x80, seed, 64);
    buf_t mine = pkcs8_wrap(OID_MLKEM1024, sizeof OID_MLKEM1024, choice.p, choice.n);
    CHECK(rl == 86 && mine.n == 86 && memcmp(mine.p, rfc, 86) == 0,
          "seed-format PKCS#8 encoding matches RFC 9935 C.1.3.1 byte for byte (%zu bytes)", mine.n);
    const unsigned char *q = mine.p;
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &q, (long)mine.n);
    CHECK(k != NULL, "OpenSSL decodes the RFC 9935 seed-format key");
    if (k) {
        /* The RFC's expanded key for this seed begins f77b7f6b15c73fe2 (C.1.3.2). */
        unsigned char exp[3168]; size_t el = 0;
        EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, exp, sizeof exp, &el);
        static const unsigned char head[8] = {0xf7,0x7b,0x7f,0x6b,0x15,0xc7,0x3f,0xe2};
        CHECK(el == 3168 && memcmp(exp, head, 8) == 0, "expanded key derived from the RFC seed matches C.1.3.2 prefix");
        EVP_PKEY_free(k);
    }
    free(choice.p); free(mine.p);

    /* Known answers from the composite ML-KEM draft (tools/gen_composite_kat.py). */
    {
        static unsigned char dk[4096], c[4096], pub[1024], kk[64], ss[32];
        priv_t pv;
        buf_t cred = { dk, (size_t)b64dec(KAT_ML_DK_PKCS8, dk), 0 };
        int cl = b64dec(KAT_ML_C, c), kl = b64dec(KAT_ML_K, kk);
        load_credential(S_ML1024, F_SEED, &cred, &pv);
        decap(S_ML1024, &pv, c, (size_t)cl, ss, NULL, 0);
        CHECK(kl == 32 && memcmp(ss, kk, 32) == 0, "ML-KEM-1024 decapsulation matches composite-draft vector");
        free_priv(&pv);
        cred.n = (size_t)b64dec(KAT_HYB_DK_PKCS8, dk);
        cl = b64dec(KAT_HYB_C, c); kl = b64dec(KAT_HYB_K, kk);
        int pl = b64dec(KAT_HYB_RSA_PUB, pub);
        load_credential(S_HYB, F_SEED, &cred, &pv);
        decap(S_HYB, &pv, c, (size_t)cl, ss, pub, (size_t)pl);
        CHECK(kl == 32 && memcmp(ss, kk, 32) == 0,
              "hybrid decapsulation and combiner match id-MLKEM1024-RSA3072-SHA3-256 vector");
        free_priv(&pv);
    }

    for (suite_t s = 0; s < S_N; s++) {
        for (fmt_t f = F_SEED; f <= F_EXP; f++) {
            if (s == S_RSA && f == F_EXP) continue;
            fmt_t ff = (s == S_RSA) ? F_NA : f;
            account_t a; account_create(&a, s, ff == F_NA ? F_SEED : ff, 7, 1);
            a.f = ff == F_NA ? F_SEED : ff;
            unsigned char root[32];
            int ok = account_open(&a, 1, root) == 0 && memcmp(root, a.root, 32) == 0;
            CHECK(ok, "%-9s %-8s open account round trip (package %zu B, credential %zu B)",
                  SUITE_NAME[s], FMT_NAME[ff], a.pkglen, a.cred.n);
            int bad = account_open(&a, 2, root) != 0;
            CHECK(bad, "%-9s %-8s wrong holder id is rejected (KEK binding)", SUITE_NAME[s], FMT_NAME[ff]);
            account_t b = a; unsigned char saved = b.pkg[1];
            b.pkg[1] = SUITE_ID[(s + 1) % S_N];
            CHECK(account_open(&b, 1, root) != 0, "%-9s %-8s tampered suite id is rejected", SUITE_NAME[s], FMT_NAME[ff]);
            b.pkg[1] = saved;
            account_free(&a);
        }
    }
    printf("\n%s (%d failure%s)\n", fails ? "SELFTEST FAILED" : "SELFTEST PASSED", fails, fails == 1 ? "" : "s");
}

/* ================================================================ sizes (E1) */
static void sizes(void) {
    printf("suite,format,credential_pkcs8,public_raw,public_spki,kem_ct,access_package\n");
    for (suite_t s = 0; s < S_N; s++)
        for (fmt_t f = F_SEED; f <= F_EXP; f++) {
            if (s == S_RSA && f == F_EXP) continue;
            fmt_t ff = (s == S_RSA) ? F_NA : f;
            account_t a; account_create(&a, s, ff == F_NA ? F_SEED : ff, 1, 1);
            size_t praw = (s == S_RSA) ? a.pub.rsa_pub_len
                        : (s == S_HYB) ? a.pub.ml_pub_len + a.pub.rsa_pub_len : a.pub.ml_pub_len;
            int spki = (s == S_HYB) ? -1 : i2d_PUBKEY(s == S_RSA ? a.pub.rsa : a.pub.ml, NULL);
            printf("%s,%s,%zu,%zu,%d,%zu,%zu\n", SUITE_NAME[s], FMT_NAME[ff], a.cred.n, praw, spki,
                   a.pkglen - 42, a.pkglen);
            account_free(&a);
        }
}

/* ================================================================ bench */
static int parse_suite(const char *x) { for (int i = 0; i < S_N; i++) if (!strcmp(x, SUITE_NAME[i])) return i; return -1; }
static int parse_fmt(const char *x) { for (int i = 0; i < 3; i++) if (!strcmp(x, FMT_NAME[i])) return i; return -1; }

static void usage(void) {
    fprintf(stderr,
      "usage: p15_a1 selftest | sizes | cpus |\n"
      "       p15_a1 bench --suite {rsa3072|mlkem768|mlkem1024|hybrid} --format {seed|expanded|na}\n"
      "                    --op {open|keygen|encap|decap|load|rewrap} [--iters N] [--warmup W] [--nf K]\n"
      "                    [--cpu C] [--out FILE] [--run-id ID]\n");
    exit(1);
}

static int bench(int argc, char **argv) {
    int s = -1, f = -1, iters = 1000, warm = 50, nf = 7, cpu = -1;
    const char *op = NULL, *outpath = NULL, *runid = "";
    for (int i = 2; i < argc; i++) {
        if (i + 1 >= argc) usage();
        if (!strcmp(argv[i], "--suite")) s = parse_suite(argv[++i]);
        else if (!strcmp(argv[i], "--format")) f = parse_fmt(argv[++i]);
        else if (!strcmp(argv[i], "--op")) op = argv[++i];
        else if (!strcmp(argv[i], "--iters")) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup")) warm = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--nf")) nf = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu")) cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--out")) outpath = argv[++i];
        else if (!strcmp(argv[i], "--run-id")) runid = argv[++i];
        else usage();
    }
    if (s < 0 || f < 0 || !op || iters < 1 || nf < 0 || nf > MAXNF) usage();
    if (s == S_RSA) f = F_NA;
    else if (f == F_NA) usage();
    fmt_t lf = (f == F_NA) ? F_SEED : (fmt_t)f;   /* load format used internally */

    char pininfo[128];
    if (pin_cpu(cpu, pininfo, sizeof pininfo) != 0) die("could not pin CPU");
    FILE *out = outpath ? fopen(outpath, "w") : stdout;
    if (!out) die("open output");

    fprintf(out, "# p15_a1 bench\n# openssl=%s\n# suite=%s format=%s op=%s iters=%d warmup=%d nf=%d\n# pin=%s\n# run_id=%s\n# time_source=%s\n",
            OpenSSL_version(OPENSSL_VERSION), SUITE_NAME[s], FMT_NAME[f], op, iters, warm, nf, pininfo, runid,
#ifdef _WIN32
            "QueryPerformanceCounter"
#else
            "clock_gettime(CLOCK_MONOTONIC)"
#endif
    );
    fprintf(out, "run_id,suite,format,op,iter,ns\n");

    account_t a; account_create(&a, (suite_t)s, lf, nf, 1);
    double *ns = malloc(sizeof(double) * (size_t)iters);
    unsigned char root[32], ss[32], ct[2048];
    priv_t pv;
    for (int phase = 0; phase < 2; phase++) {
        int n = phase == 0 ? warm : iters;
        for (int i = 0; i < n; i++) {
            uint64_t t0 = 0, t1 = 0;
            if (!strcmp(op, "open")) {
                t0 = now_ticks();
                int r = account_open(&a, 1, root);
                t1 = now_ticks();
                if (r != 0) die("open failed");
            } else if (!strcmp(op, "load")) {
                t0 = now_ticks();
                load_credential(a.s, a.f, &a.cred, &pv);
                t1 = now_ticks();
                free_priv(&pv);
            } else if (!strcmp(op, "encap")) {
                t0 = now_ticks();
                encap(a.s, &a.pub, ct, ss);
                t1 = now_ticks();
            } else if (!strcmp(op, "decap")) {
                load_credential(a.s, a.f, &a.cred, &pv);      /* warm key: decapsulation alone */
                size_t ctlen = a.pkglen - 42;
                t0 = now_ticks();
                decap(a.s, &pv, a.pkg + 2, ctlen, ss, a.pub.rsa_pub_der, a.pub.rsa_pub_len);
                t1 = now_ticks();
                free_priv(&pv);
            } else if (!strcmp(op, "rewrap")) {
                /* One step of a key migration: unwrap a child key under its old parent and
                 * wrap it under the new parent (AES-256-KW both ways); suite-independent. */
                static unsigned char newroot[32], child[40], rewrapped[40];
                if (i == 0 && phase == 0 && RAND_bytes(newroot, 32) != 1) die("rand");
                t0 = now_ticks();
                if (kw(0, a.root, a.child_wrapped[0], 40, child) != 32 ||
                    kw(1, newroot, child, 32, rewrapped) != 40) die("rewrap");
                t1 = now_ticks();
            } else if (!strcmp(op, "keygen")) {
                pub_t p;
                t0 = now_ticks();
                buf_t c = gen_credential(a.s, a.f, &p);
                t1 = now_ticks();
                EVP_PKEY_free(p.ml); EVP_PKEY_free(p.rsa); OPENSSL_clear_free(c.p, c.n);
            } else usage();
            if (phase == 1) ns[i] = (double)(t1 - t0) * tick_ns;
        }
    }
    for (int i = 0; i < iters; i++)
        fprintf(out, "%s,%s,%s,%s,%d,%.0f\n", runid, SUITE_NAME[s], FMT_NAME[f], op, i, ns[i]);
    free(ns);
    account_free(&a);
    if (outpath) fclose(out);
    return 0;
}

/* ============================================== FIPS 203 ACVP vectors (D-023) */
static int hexdec(const char *h, unsigned char *out, size_t max) {
    size_t n = 0;
    while (h[0] && h[1] && h[0] != ' ' && h[0] != '\n' && h[0] != '\r' && n < max) {
        unsigned v; if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (unsigned char)v; h += 2;
    }
    return (int)n;
}
/* Every vector goes through the same PKCS#8 loading path as the measurements. */
static int acvp(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) die("open ACVP file");
    static char line[32768];
    static unsigned char a[4096], c[4096], k[64], ss[32], exp[4096];
    int n = 0, bad = 0;
    while (fgets(line, sizeof line, fp)) {
        if (line[0] == '#' || strlen(line) < 4) continue;
        char kind[4], sname[16]; int off = 0;
        if (sscanf(line, "%3s %15s %n", kind, sname, &off) != 2) continue;
        suite_t s = (suite_t)parse_suite(sname);
        const char *p = line + off;
        int al = hexdec(p, a, sizeof a); p = strchr(p, ' ');
        const unsigned char *oid = s == S_ML768 ? OID_MLKEM768 : OID_MLKEM1024;
        buf_t choice = {0}, cred; priv_t pv; int ok;
        if (!strcmp(kind, "kg")) {
            int dl = hexdec(p + 1, c, sizeof c);
            der_tlv(&choice, 0x80, a, (size_t)al);
            cred = pkcs8_wrap(oid, 11, choice.p, choice.n);
            load_credential(s, F_SEED, &cred, &pv);
            size_t el = 0;
            EVP_PKEY_get_octet_string_param(pv.ml, OSSL_PKEY_PARAM_PRIV_KEY, exp, sizeof exp, &el);
            ok = (int)el == dl && memcmp(exp, c, el) == 0;
        } else {
            int cl = hexdec(p + 1, c, sizeof c); p = strchr(p + 1, ' ');
            hexdec(p + 1, k, sizeof k);
            der_tlv(&choice, 0x04, a, (size_t)al);
            cred = pkcs8_wrap(oid, 11, choice.p, choice.n);
            load_credential(s, F_EXP, &cred, &pv);
            decap(s, &pv, c, (size_t)cl, ss, NULL, 0);
            ok = memcmp(ss, k, 32) == 0;
        }
        free_priv(&pv); free(choice.p); free(cred.p);
        n++; bad += !ok;
        if (!ok) printf("  FAIL: %s %s vector %d\n", kind, sname, n);
    }
    fclose(fp);
    printf("ACVP ML-KEM (%s): %d vectors, %d failure%s\n", OpenSSL_version(OPENSSL_VERSION), n, bad, bad == 1 ? "" : "s");
    return bad || n == 0;
}

/* ============================================== cross-platform interchange (D-023) */
static void hexout(FILE *f, const char *key, const unsigned char *p, size_t n) {
    fprintf(f, "%s ", key);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", p[i]);
    if (n == 0) fputc('-', f);
    fputc('\n', f);
}
static int xexport(const char *dir) {
    for (suite_t s = 0; s < S_N; s++) for (fmt_t f = F_SEED; f <= F_EXP; f++) {
        if (s == S_RSA && f == F_EXP) continue;
        account_t a; account_create(&a, s, f, 7, 1);
        const char *fn = s == S_RSA ? "na" : FMT_NAME[f];
        char path[1024]; snprintf(path, sizeof path, "%s/openssl_%s_%s.txt", dir, SUITE_NAME[s], fn);
        FILE *o = fopen(path, "w"); if (!o) die("open export file");
        fprintf(o, "impl openssl\nsuite %s\nformat %s\n", SUITE_NAME[s], fn);
        hexout(o, "cred", a.cred.p, a.cred.n);
        hexout(o, "rsa_pub", a.pub.rsa_pub_der, a.pub.rsa_pub_len);
        hexout(o, "pkg", a.pkg, a.pkglen);
        hexout(o, "root", a.root, 32);
        for (int i = 0; i < a.nf; i++) hexout(o, "child", a.child_wrapped[i], 40);
        fclose(o); account_free(&a);
    }
    return 0;
}
static int xopen(int n, char **files) {
    int bad = 0;
    static char line[32768];
    for (int i = 0; i < n; i++) {
        FILE *fp = fopen(files[i], "r"); if (!fp) die("open interchange file");
        account_t a; memset(&a, 0, sizeof a);
        unsigned char root[32], want[32]; char impl[32] = "?", sn[16] = "", fn[16] = "";
        static unsigned char credbuf[8192];
        while (fgets(line, sizeof line, fp)) {
            char key[16]; int off = 0;
            if (sscanf(line, "%15s %n", key, &off) != 1) continue;
            const char *v = line + off;
            if (!strcmp(key, "impl")) sscanf(v, "%31s", impl);
            else if (!strcmp(key, "suite")) sscanf(v, "%15s", sn);
            else if (!strcmp(key, "format")) sscanf(v, "%15s", fn);
            else if (!strcmp(key, "cred")) { a.cred.p = credbuf; a.cred.n = (size_t)hexdec(v, credbuf, sizeof credbuf); }
            else if (!strcmp(key, "rsa_pub")) a.pub.rsa_pub_len = v[0] == '-' ? 0 : (size_t)hexdec(v, a.pub.rsa_pub_der, sizeof a.pub.rsa_pub_der);
            else if (!strcmp(key, "pkg")) a.pkglen = (size_t)hexdec(v, a.pkg, sizeof a.pkg);
            else if (!strcmp(key, "root")) hexdec(v, want, 32);
            else if (!strcmp(key, "child") && a.nf < MAXNF) hexdec(v, a.child_wrapped[a.nf++], 40);
        }
        fclose(fp);
        a.s = (suite_t)parse_suite(sn);
        a.f = !strcmp(fn, "expanded") ? F_EXP : F_SEED;
        int ok = account_open(&a, 1, root) == 0 && memcmp(root, want, 32) == 0;
        bad += !ok;
        printf("  %s  %-8s -> openssl: %-9s %-8s (%d children)\n", ok ? "ok:  " : "FAIL:", impl, sn, fn, a.nf);
    }
    printf("Cross-platform open on OpenSSL: %d files, %d failure%s\n", n, bad, bad == 1 ? "" : "s");
    return bad != 0;
}

int main(int argc, char **argv) {
    clock_init();
    g_hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    g_kw = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL);
    if (!g_hkdf || !g_kw) die("fetch HKDF / AES-256-WRAP");
    if (argc < 2) usage();
    if (!strcmp(argv[1], "selftest")) { selftest(); return fails ? 1 : 0; }
    if (!strcmp(argv[1], "sizes")) { sizes(); return 0; }
    if (!strcmp(argv[1], "cpus")) { list_cpus(); return 0; }
    if (!strcmp(argv[1], "bench")) return bench(argc, argv);
    if (!strcmp(argv[1], "acvp") && argc > 2) return acvp(argv[2]);
    if (!strcmp(argv[1], "xexport") && argc > 2) return xexport(argv[2]);
    if (!strcmp(argv[1], "xopen") && argc > 2) return xopen(argc - 2, argv + 2);
    usage();
    return 1;
}
