/*
 * P15 -- exploratory end-to-end validation of the migration cost model (D-026).
 *
 * Native only. Implements the four architectures with the same primitives as the
 * frozen A1 client, which is reused unchanged: p15_a1.c is included below with its
 * main() renamed, so no line of the measured A1 code is edited or duplicated.
 *
 *   A1   account root (JCP): one access package per holder; the n_f top-level node
 *        keys are wrapped under the root; deeper node keys under their parent.
 *   A1b  one key per top-level shared folder (Nextcloud model), encapsulated to each
 *        holder; its children wrapped under it. Every top-level item is a shared
 *        folder with all holders as members (the pre-registered upper bound).
 *   A2   one key pair per node (Proton Drive model): the node's private key (PKCS#8,
 *        seed form, RFC 9935) is wrapped (AES-256-KWP) under a key derived from a
 *        packet encapsulated to the parent's public key; top-level nodes encapsulate
 *        to a share key pair, whose private key is wrapped under packets encapsulated
 *        to each holder; each file has a content-key packet encapsulated to its node.
 *   A3   password vault (Cryptomator model): scrypt-derived master key, AES-KW node
 *        keys, no public keys; migration to a public-key suite touches nothing.
 *
 * Migration semantics (pre-registration, D-030): every node at the asymmetric
 * boundary receives a fresh secret, its outgoing edges are re-wrapped and the secret
 * is re-encapsulated under the target suite; in A2 the fresh secret is a new key pair.
 * The migration runs in an unlocked session: the old tree keys and content keys are
 * in memory (no decapsulation under the old suite is timed), and the holders'
 * target-suite credentials already exist (holder key generation is excluded, as in
 * the model). The account state is first built under RSA-3072 (untimed).
 *
 * Per run, one line: the measured migration time and the structural counts that the
 * cost model multiplies by the unit costs (K, E, W), and the suite-dependent bytes.
 *
 * Usage:
 *   p15_arch run --arch A1|A1b|A2|A3 --suite mlkem1024|hybrid --account ID
 *                --n-total N --n-f F --n-h H [--phi 0.8] [--cpu C] [--run-id R] [--out FILE]
 *   p15_arch check      (all architectures and suites on small accounts, with verification)
 */
#define main p15_a1_main
#include "p15_a1.c"
#undef main
#include <math.h>

static EVP_CIPHER *g_kwp;   /* AES-256-WRAP-PAD, for wrapping PKCS#8 private keys */

static int kwp(int enc, const unsigned char key[32], const unsigned char *in, size_t inlen, unsigned char *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l1 = 0, l2 = 0;
    EVP_CIPHER_CTX_set_flags(c, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    int ok = EVP_CipherInit_ex2(c, g_kwp, key, NULL, enc, NULL) &&
             EVP_CipherUpdate(c, out, &l1, in, (int)inlen) &&
             EVP_CipherFinal_ex(c, out + l1, &l2);
    EVP_CIPHER_CTX_free(c);
    return ok ? l1 + l2 : -1;
}

/* ------------------------------------------------------------ account tree */
/* Deterministic per account (xorshift64*), so every architecture and suite of an
 * account sees the same tree. Nodes 0..nf-1 are the top-level folders. The other
 * nodes are subfolders or files (n_files = min(round(phi n_total), n_total - n_f));
 * each picks its parent uniformly among the folders created so far. */
typedef struct { int n, nf, nh, nfiles, c; int *parent; unsigned char *is_file; } tree_t;

static uint64_t rng_state;
static uint64_t rng_next(void) {
    uint64_t x = rng_state; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; rng_state = x;
    return x * 2685821657736338717ull;
}
static void tree_build(tree_t *t, int n, int nf, int nh, double phi, uint64_t seed) {
    t->n = n; t->nf = nf; t->nh = nh;
    t->parent = malloc(sizeof(int) * (size_t)n); t->is_file = calloc((size_t)n, 1);
    int m = n - nf;
    long want = lround(phi * n);
    t->nfiles = (int)(want < m ? want : m);
    rng_state = seed * 0x9E3779B97F4A7C15ull + 1;
    unsigned char *type = calloc((size_t)m + 1, 1);          /* 1 = file */
    for (int i = 0; i < t->nfiles; i++) type[i] = 1;
    for (int i = m - 1; i > 0; i--) { int j = (int)(rng_next() % (uint64_t)(i + 1)); unsigned char x = type[i]; type[i] = type[j]; type[j] = x; }
    int *folders = malloc(sizeof(int) * (size_t)n), nfold = 0;
    for (int i = 0; i < nf; i++) { t->parent[i] = -1; folders[nfold++] = i; }
    t->c = 0;
    for (int k = 0; k < m; k++) {
        int id = nf + k;
        int p = folders[rng_next() % (uint64_t)nfold];
        t->parent[id] = p; t->is_file[id] = type[k];
        if (p < nf) t->c++;
        if (!type[k]) folders[nfold++] = id;
    }
    free(type); free(folders);
}
static void tree_free(tree_t *t) { free(t->parent); free(t->is_file); }

/* --------------------------------------------------------------- holders */
typedef struct { suite_t s; buf_t cred; pub_t pub; } cred_t;
static void cred_gen(cred_t *c, suite_t s) { c->s = s; c->cred = gen_credential(s, F_SEED, &c->pub); }
static void cred_free(cred_t *c) { EVP_PKEY_free(c->pub.ml); EVP_PKEY_free(c->pub.rsa); OPENSSL_clear_free(c->cred.p, c->cred.n); }

/* An access package: suite header, KEM ciphertext, wrapped 32-byte key. */
typedef struct { unsigned char ct[2048]; size_t ctlen; unsigned char wrapped[40]; } pkg_t;
static void pkg_make(pkg_t *p, suite_t s, const pub_t *to, uint32_t holder, const unsigned char key[32]) {
    unsigned char ss[32], kek[32];
    p->ctlen = encap(s, to, p->ct, ss);
    kek_derive(ss, s, holder, kek);
    if (kw(1, kek, key, 32, p->wrapped) != 40) die("pkg wrap");
}
static int pkg_open(const pkg_t *p, suite_t s, const cred_t *c, uint32_t holder, unsigned char key[32]) {
    priv_t pv; unsigned char ss[32], kek[32];
    load_credential(s, F_SEED, &c->cred, &pv);
    decap(s, &pv, p->ct, p->ctlen, ss, c->pub.rsa_pub_der, c->pub.rsa_pub_len);
    free_priv(&pv);
    kek_derive(ss, s, holder, kek);
    return kw(0, kek, p->wrapped, 40, key) == 32 ? 0 : -1;
}

typedef struct { long K, E, W; long bytes; } counts_t;

/* =============================================================== A1 / A1b */
typedef struct {
    tree_t *t; suite_t s;
    unsigned char root[32];                 /* A1 only */
    unsigned char (*key)[32];               /* node keys (in memory: unlocked session) */
    unsigned char (*wrapped)[40];           /* node key wrapped under its parent (or root) */
    pkg_t *pkgs;                            /* A1: nh;  A1b: nf * nh */
} sym_t;

static void sym_build(sym_t *a, tree_t *t, suite_t s, cred_t *holders, int a1b) {
    a->t = t; a->s = s;
    a->key = malloc(sizeof *a->key * (size_t)t->n);
    a->wrapped = malloc(sizeof *a->wrapped * (size_t)t->n);
    if (RAND_bytes(a->root, 32) != 1) die("rand");
    for (int i = 0; i < t->n; i++) if (RAND_bytes(a->key[i], 32) != 1) die("rand");
    for (int i = 0; i < t->n; i++) {
        const unsigned char *pk = t->parent[i] < 0 ? a->root : a->key[t->parent[i]];
        if (t->parent[i] < 0 && a1b) continue;      /* A1b: top folders are shared by packages */
        if (kw(1, pk, a->key[i], 32, a->wrapped[i]) != 40) die("wrap");
    }
    int np = a1b ? t->nf * t->nh : t->nh;
    a->pkgs = malloc(sizeof(pkg_t) * (size_t)np);
    for (int h = 0; h < t->nh; h++) {
        if (!a1b) pkg_make(&a->pkgs[h], s, &holders[h].pub, (uint32_t)h + 1, a->root);
        else for (int f = 0; f < t->nf; f++) pkg_make(&a->pkgs[f * t->nh + h], s, &holders[h].pub, (uint32_t)h + 1, a->key[f]);
    }
}
static void sym_free(sym_t *a) { free(a->key); free(a->wrapped); free(a->pkgs); }

/* A1: fresh root; re-wrap the n_f top-level keys; one package per holder. */
static void a1_migrate(sym_t *a, suite_t to, cred_t *holders, counts_t *k) {
    tree_t *t = a->t;
    unsigned char newroot[32], child[40];
    if (RAND_bytes(newroot, 32) != 1) die("rand");
    for (int i = 0; i < t->nf; i++) {
        if (kw(0, a->root, a->wrapped[i], 40, child) != 32 || kw(1, newroot, child, 32, a->wrapped[i]) != 40) die("rewrap");
        k->W++;
    }
    for (int h = 0; h < t->nh; h++) { pkg_make(&a->pkgs[h], to, &holders[h].pub, (uint32_t)h + 1, newroot); k->E++; k->bytes += (long)a->pkgs[h].ctlen; }
    memcpy(a->root, newroot, 32); a->s = to;
}
/* A1b: rotate each shared folder key; re-wrap its c_i children; one package per holder. */
static void a1b_migrate(sym_t *a, suite_t to, cred_t *holders, counts_t *k) {
    tree_t *t = a->t;
    unsigned char child[40];
    for (int f = 0; f < t->nf; f++) {
        unsigned char nk[32];
        if (RAND_bytes(nk, 32) != 1) die("rand");
        for (int i = t->nf; i < t->n; i++) {
            if (t->parent[i] != f) continue;
            if (kw(0, a->key[f], a->wrapped[i], 40, child) != 32 || kw(1, nk, child, 32, a->wrapped[i]) != 40) die("rewrap");
            k->W++;
        }
        for (int h = 0; h < t->nh; h++) {
            pkg_t *p = &a->pkgs[f * t->nh + h];
            pkg_make(p, to, &holders[h].pub, (uint32_t)h + 1, nk); k->E++; k->bytes += (long)p->ctlen;
        }
        memcpy(a->key[f], nk, 32);
    }
    a->s = to;
}
/* Verification: holder 1 opens the root (A1) or folder 0 (A1b) and unwraps every child. */
static int sym_verify(sym_t *a, cred_t *holders, int a1b) {
    tree_t *t = a->t; unsigned char k0[32], child[40];
    if (pkg_open(&a->pkgs[0], a->s, &holders[0], 1, k0) != 0) return -1;
    if (memcmp(k0, a1b ? a->key[0] : a->root, 32)) return -1;
    for (int i = 0; i < t->n; i++) {
        int top = t->parent[i] < 0;
        if (!a1b && top && kw(0, k0, a->wrapped[i], 40, child) != 32) return -1;
        if (a1b && t->parent[i] == 0 && kw(0, k0, a->wrapped[i], 40, child) != 32) return -1;
    }
    return 0;
}

/* ===================================================================== A2 */
typedef struct {
    tree_t *t; suite_t s;
    cred_t share;                           /* share key pair; sk wrapped per holder */
    pkg_t *share_pkgs; unsigned char share_key[32];
    unsigned char (*share_wrapped_sk); int share_wrapped_len;
    cred_t *node;                           /* node key pairs */
    pkg_t *node_pkg;                        /* packet to the parent (or share) public key */
    unsigned char *node_sk; int *node_sk_len;  /* node PKCS#8 wrapped (KWP) under the packet key */
    unsigned char (*content)[32];           /* file content keys (in memory) */
    pkg_t *file_pkg;                        /* content key packet to the file's node key */
} a2_t;
#define SKMAX 2048

static void a2_alloc(a2_t *a, tree_t *t) {
    memset(a, 0, sizeof *a); a->t = t;
    a->share_pkgs = malloc(sizeof(pkg_t) * (size_t)t->nh);
    a->share_wrapped_sk = malloc(SKMAX);
    a->node = calloc((size_t)t->n, sizeof(cred_t));
    a->node_pkg = malloc(sizeof(pkg_t) * (size_t)t->n);
    a->node_sk = malloc((size_t)SKMAX * (size_t)t->n);
    a->node_sk_len = malloc(sizeof(int) * (size_t)t->n);
    a->content = malloc(sizeof *a->content * (size_t)t->n);
    a->file_pkg = malloc(sizeof(pkg_t) * (size_t)t->n);
    for (int i = 0; i < t->n; i++) if (RAND_bytes(a->content[i], 32) != 1) die("rand");
}
static void a2_release_keys(a2_t *a) {
    if (a->share.cred.p) cred_free(&a->share);
    for (int i = 0; i < a->t->n; i++) if (a->node[i].cred.p) cred_free(&a->node[i]);
}
static void a2_free(a2_t *a) {
    a2_release_keys(a);
    free(a->share_pkgs); free(a->share_wrapped_sk); free(a->node); free(a->node_pkg);
    free(a->node_sk); free(a->node_sk_len); free(a->content); free(a->file_pkg);
}
/* Build (or rebuild, for the migration) every asymmetric item under suite s.
 * The node list is in creation order, so a parent always precedes its children. */
static void a2_generate(a2_t *a, suite_t s, cred_t *holders, counts_t *k) {
    tree_t *t = a->t;
    unsigned char ss[32], kek[32];
    a2_release_keys(a);
    a->s = s;
    /* share key pair and its packets to the holders (n_h E); the share key pair itself is
     * one key generation the model does not count (a per-account overhead). */
    cred_gen(&a->share, s);
    if (RAND_bytes(a->share_key, 32) != 1) die("rand");
    a->share_wrapped_len = kwp(1, a->share_key, a->share.cred.p, a->share.cred.n, a->share_wrapped_sk);
    if (a->share_wrapped_len < 0) die("kwp share");
    for (int h = 0; h < t->nh; h++) {
        pkg_make(&a->share_pkgs[h], s, &holders[h].pub, (uint32_t)h + 1, a->share_key);
        if (k) { k->E++; k->bytes += (long)a->share_pkgs[h].ctlen; }
    }
    for (int i = 0; i < t->n; i++) {
        cred_gen(&a->node[i], s);                                   /* K */
        const pub_t *to = t->parent[i] < 0 ? &a->share.pub : &a->node[t->parent[i]].pub;
        pkg_t *p = &a->node_pkg[i];
        p->ctlen = encap(s, to, p->ct, ss);                         /* E: node packet */
        kek_derive(ss, s, (uint32_t)i, kek);
        a->node_sk_len[i] = kwp(1, kek, a->node[i].cred.p, a->node[i].cred.n, a->node_sk + (size_t)i * SKMAX);
        if (a->node_sk_len[i] < 0) die("kwp node");
        if (k) {
            k->K++; k->E++;
            k->bytes += (long)(a->node[i].pub.ml_pub_len + a->node[i].pub.rsa_pub_len) + a->node_sk_len[i] + (long)p->ctlen;
        }
        if (t->is_file[i]) {
            pkg_make(&a->file_pkg[i], s, &a->node[i].pub, (uint32_t)i, a->content[i]);   /* E: content key packet */
            if (k) { k->E++; k->bytes += (long)a->file_pkg[i].ctlen; }
        }
    }
}
/* Verification: holder 1 unlocks the share, then walks down to one file (or the
 * deepest node) decapsulating at every level, and recovers its content key. */
static int a2_unlock(a2_t *a, int i, cred_t *out) {
    tree_t *t = a->t;
    cred_t parent;
    if (t->parent[i] < 0) parent = a->share;
    else if (a2_unlock(a, t->parent[i], &parent) != 0) return -1;
    priv_t pv; unsigned char ss[32], kek[32];
    load_credential(a->s, F_SEED, &parent.cred, &pv);
    decap(a->s, &pv, a->node_pkg[i].ct, a->node_pkg[i].ctlen, ss, parent.pub.rsa_pub_der, parent.pub.rsa_pub_len);
    free_priv(&pv);
    if (t->parent[i] >= 0) OPENSSL_clear_free(parent.cred.p, parent.cred.n);
    kek_derive(ss, a->s, (uint32_t)i, kek);
    unsigned char *sk = malloc(SKMAX);
    int n = kwp(0, kek, a->node_sk + (size_t)i * SKMAX, (size_t)a->node_sk_len[i], sk);
    if (n < 0) { free(sk); return -1; }
    out->s = a->s; out->cred.p = sk; out->cred.n = (size_t)n; out->pub = a->node[i].pub;
    return 0;
}
static int a2_verify(a2_t *a, cred_t *holders) {
    tree_t *t = a->t; unsigned char sk_key[32];
    if (pkg_open(&a->share_pkgs[0], a->s, &holders[0], 1, sk_key) != 0 || memcmp(sk_key, a->share_key, 32)) return -1;
    {   /* the share private key unwraps from the stored blob */
        unsigned char *sk = malloc(SKMAX);
        int n = kwp(0, sk_key, a->share_wrapped_sk, (size_t)a->share_wrapped_len, sk);
        int same = n == (int)a->share.cred.n && CRYPTO_memcmp(sk, a->share.cred.p, (size_t)n) == 0;
        OPENSSL_clear_free(sk, SKMAX);
        if (!same) return -1;
    }
    int target = t->n - 1;
    for (int i = t->n - 1; i >= 0; i--) if (t->is_file[i]) { target = i; break; }
    cred_t c;
    if (a2_unlock(a, target, &c) != 0) return -1;
    int ok = c.cred.n == a->node[target].cred.n && CRYPTO_memcmp(c.cred.p, a->node[target].cred.p, c.cred.n) == 0;
    if (ok && t->is_file[target]) {
        unsigned char ck[32];
        cred_t fc = c; fc.pub = a->node[target].pub;
        ok = pkg_open(&a->file_pkg[target], a->s, &fc, (uint32_t)target, ck) == 0 && !memcmp(ck, a->content[target], 32);
    }
    OPENSSL_clear_free(c.cred.p, c.cred.n);
    return ok ? 0 : -1;
}

/* ===================================================================== A3 */
typedef struct { tree_t *t; unsigned char master[32]; unsigned char (*wrapped)[40]; } a3_t;
static void a3_build(a3_t *a, tree_t *t) {
    a->t = t;
    static const char pw[] = "p15-validation-vault";
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof salt) != 1) die("rand");
    if (!EVP_PBE_scrypt(pw, sizeof pw - 1, salt, sizeof salt, 1u << 15, 8, 1, 64u << 20, a->master, 32)) die("scrypt");
    a->wrapped = malloc(sizeof *a->wrapped * (size_t)t->n);
    for (int i = 0; i < t->n; i++) {
        unsigned char k[32];
        if (RAND_bytes(k, 32) != 1 || kw(1, a->master, k, 32, a->wrapped[i]) != 40) die("a3 wrap");
    }
}
/* Migration to a public-key suite: the vault has no asymmetric item, so nothing is done.
 * The function still walks the structure, as a client would, to find none. */
static void a3_migrate(a3_t *a, counts_t *k) {
    volatile long asym = 0;
    for (int i = 0; i < a->t->n; i++) asym += a->wrapped[i][0] & 0;   /* no item has a public key */
    (void)k;
}

/* ================================================================== driver */
static int run_one(const char *arch, suite_t to, int n, int nf, int nh, double phi, long account,
                   int cpu, const char *runid, const char *outpath, int verify_only) {
    tree_t t; tree_build(&t, n, nf, nh, phi, (uint64_t)account);
    char pininfo[128];
    if (pin_cpu(cpu, pininfo, sizeof pininfo) != 0) die("could not pin CPU");
    cred_t *old_h = calloc((size_t)nh, sizeof(cred_t)), *new_h = calloc((size_t)nh, sizeof(cred_t));
    for (int h = 0; h < nh; h++) { cred_gen(&old_h[h], S_RSA); cred_gen(&new_h[h], to); }
    counts_t k = {0, 0, 0, 0};
    uint64_t t0 = 0, t1 = 0;
    int ok = 0;
    if (!strcmp(arch, "A1") || !strcmp(arch, "A1b")) {
        int a1b = arch[2] == 'b';
        sym_t a; sym_build(&a, &t, S_RSA, old_h, a1b);
        if (sym_verify(&a, old_h, a1b) != 0) die("verify before");
        t0 = now_ticks();
        if (a1b) a1b_migrate(&a, to, new_h, &k); else a1_migrate(&a, to, new_h, &k);
        t1 = now_ticks();
        ok = sym_verify(&a, new_h, a1b) == 0;
        sym_free(&a);
    } else if (!strcmp(arch, "A2")) {
        a2_t a; a2_alloc(&a, &t);
        a2_generate(&a, S_RSA, old_h, NULL);
        if (a2_verify(&a, old_h) != 0) die("verify before");
        t0 = now_ticks();
        a2_generate(&a, to, new_h, &k);
        t1 = now_ticks();
        ok = a2_verify(&a, new_h) == 0;
        a2_free(&a);
    } else if (!strcmp(arch, "A3")) {
        a3_t a; a3_build(&a, &t);
        t0 = now_ticks();
        a3_migrate(&a, &k);
        t1 = now_ticks();
        ok = 1; free(a.wrapped);
    } else usage();
    for (int h = 0; h < nh; h++) { cred_free(&old_h[h]); cred_free(&new_h[h]); }
    free(old_h); free(new_h);
    if (!ok) { fprintf(stderr, "fatal: verification after migration failed (%s %s account %ld)\n", arch, SUITE_NAME[to], account); exit(3); }
    if (!verify_only) {
        FILE *out = outpath ? fopen(outpath, "a") : stdout;
        if (!out) die("open output");
        if (outpath && ftell(out) == 0)
            fprintf(out, "run_id,account,arch,suite,n_total,n_f,n_h,n_files,c,K_ops,E_ops,W_ops,bytes,ns,pin\n");
        fprintf(out, "%s,%ld,%s,%s,%d,%d,%d,%d,%d,%ld,%ld,%ld,%ld,%.0f,%s\n", runid, account, arch, SUITE_NAME[to],
                n, nf, nh, t.nfiles, t.c, k.K, k.E, k.W, k.bytes, (double)(t1 - t0) * tick_ns, pininfo);
        if (outpath) fclose(out);
    }
    tree_free(&t);
    return 0;
}

static void arch_usage(void) {
    fprintf(stderr, "usage: p15_arch run --arch A1|A1b|A2|A3 --suite mlkem1024|hybrid --account ID --n-total N --n-f F --n-h H [--phi 0.8] [--cpu C] [--run-id R] [--out FILE]\n"
                    "       p15_arch check\n");
    exit(1);
}

int main(int argc, char **argv) {
    clock_init();
    g_hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    g_kw = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL);
    g_kwp = EVP_CIPHER_fetch(NULL, "AES-256-WRAP-PAD", NULL);
    if (!g_hkdf || !g_kw || !g_kwp) die("fetch HKDF / AES-256-WRAP / AES-256-WRAP-PAD");
    if (argc < 2) arch_usage();
    if (!strcmp(argv[1], "check")) {
        /* Small accounts, every architecture and target suite, verified after migration. */
        static const int shapes[][3] = {{1, 1, 1}, {5, 5, 2}, {12, 3, 1}, {40, 7, 3}, {120, 6, 2}};
        static const char *archs[] = {"A1", "A1b", "A2", "A3"};
        static const suite_t tos[] = {S_ML1024, S_HYB};
        int nrun = 0;
        for (size_t sh = 0; sh < sizeof shapes / sizeof shapes[0]; sh++)
            for (int ai = 0; ai < 4; ai++)
                for (int si = 0; si < 2; si++) {
                    run_one(archs[ai], tos[si], shapes[sh][0], shapes[sh][1], shapes[sh][2], 0.8, 1000 + (long)sh, -1, "check", NULL, 1);
                    nrun++;
                }
        printf("ARCH CHECK PASSED (%d migrations verified)\n", nrun);
        return 0;
    }
    if (strcmp(argv[1], "run")) arch_usage();
    const char *arch = NULL, *runid = "", *outpath = NULL;
    int s = -1, n = -1, nf = -1, nh = -1, cpu = -1; long account = -1; double phi = 0.8;
    for (int i = 2; i < argc; i++) {
        if (i + 1 >= argc) arch_usage();
        if (!strcmp(argv[i], "--arch")) arch = argv[++i];
        else if (!strcmp(argv[i], "--suite")) s = parse_suite(argv[++i]);
        else if (!strcmp(argv[i], "--account")) account = atol(argv[++i]);
        else if (!strcmp(argv[i], "--n-total")) n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--n-f")) nf = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--n-h")) nh = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--phi")) phi = atof(argv[++i]);
        else if (!strcmp(argv[i], "--cpu")) cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--run-id")) runid = argv[++i];
        else if (!strcmp(argv[i], "--out")) outpath = argv[++i];
        else arch_usage();
    }
    if (!arch || (s != S_ML1024 && s != S_HYB) || account < 0 || n < 1 || nf < 1 || nf > n || nh < 1) arch_usage();
    return run_one(arch, (suite_t)s, n, nf, nh, phi, account, cpu, runid, outpath, 0);
}
