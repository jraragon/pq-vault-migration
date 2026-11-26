package es.usal.p15bench;

/*
 * P15 -- architecture A1 on the Bouncy Castle lightweight API (Android client).
 * Mirror of native/src/p15_a1.c: same suites, same byte formats, same access
 * package and the same loading path (stored PKCS#8 parsed by the library's
 * private-key factory for every suite, including the ML-KEM part of the hybrid).
 * Plain Java: no Android dependency, so it can also be tested on a desktop JVM.
 */

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

public final class P15Core {

    public enum Suite {
        RSA3072("rsa3072", 0x01), MLKEM768("mlkem768", 0x02), MLKEM1024("mlkem1024", 0x03), HYBRID("hybrid", 0x04);
        public final String name; public final int id;
        Suite(String n, int i) { name = n; id = i; }
        boolean hasMl() { return this != RSA3072; }
        boolean hasRsa() { return this == RSA3072 || this == HYBRID; }
        MLKEMParameters mlParams() { return this == MLKEM768 ? MLKEMParameters.ml_kem_768 : MLKEMParameters.ml_kem_1024; }
        int mlCt() { return this == MLKEM768 ? 1088 : 1568; }
        public static Suite of(String n) { for (Suite s : values()) if (s.name.equals(n)) return s; throw new IllegalArgumentException(n); }
    }
    public enum Fmt { SEED("seed"), EXPANDED("expanded"), NA("na");
        public final String name; Fmt(String n) { name = n; }
        public static Fmt of(String n) { for (Fmt f : values()) if (f.name.equals(n)) return f; throw new IllegalArgumentException(n); }
    }

    static final SecureRandom RNG = new SecureRandom();
    static final byte[] OID_MLKEM768  = {0x06,0x09,0x60,(byte)0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x02};
    static final byte[] OID_MLKEM1024 = {0x06,0x09,0x60,(byte)0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x03};
    static final byte[] OID_HYBRID    = {0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x06,0x3e};
    static final byte[] HYBRID_LABEL  = "MLKEM1024-RSAOAEP3072".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    static final byte[] KDF_LABEL     = "P15/A1/package/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    // ---------------------------------------------------------------- DER
    static void derLen(ByteArrayOutputStream b, int n) {
        if (n < 0x80) b.write(n);
        else if (n < 0x100) { b.write(0x81); b.write(n); }
        else { b.write(0x82); b.write(n >> 8); b.write(n & 0xff); }
    }
    static byte[] tlv(int tag, byte[] v) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(tag); derLen(b, v.length); b.write(v, 0, v.length); return b.toByteArray();
    }
    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] p : parts) b.write(p, 0, p.length);
        return b.toByteArray();
    }
    static byte[] pkcs8(byte[] oidDer, byte[] privateKeyContent) {
        return tlv(0x30, cat(new byte[]{0x02, 0x01, 0x00}, tlv(0x30, oidDer), tlv(0x04, privateKeyContent)));
    }

    // ---------------------------------------------------------------- keys
    public static final class Pub {
        MLKEMPublicKeyParameters ml; RSAKeyParameters rsa;
        byte[] rsaPubDer = new byte[0]; int mlPubLen;
    }
    public static final class Priv { MLKEMPrivateKeyParameters ml; RSAPrivateCrtKeyParameters rsa; }

    static byte[] rsaPublicKeyDer(RSAKeyParameters k) throws Exception {
        return new org.bouncycastle.asn1.pkcs.RSAPublicKey(k.getModulus(), k.getExponent()).getEncoded("DER");
    }
    static byte[] rsaPrivateKeyDer(RSAPrivateCrtKeyParameters k) throws Exception {
        return PrivateKeyInfoFactory.createPrivateKeyInfo(k).parsePrivateKey().toASN1Primitive().getEncoded("DER");
    }

    /** Generate a credential: returns the stored private bytes (PKCS#8 DER), fills pub. */
    public static byte[] genCredential(Suite s, Fmt f, Pub pub) throws Exception {
        MLKEMPrivateKeyParameters mlPriv = null;
        RSAPrivateCrtKeyParameters rsaPriv = null;
        if (s.hasMl()) {
            MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
            g.init(new MLKEMKeyGenerationParameters(RNG, s.mlParams()));
            AsymmetricCipherKeyPair kp = g.generateKeyPair();
            pub.ml = (MLKEMPublicKeyParameters) kp.getPublic();
            mlPriv = (MLKEMPrivateKeyParameters) kp.getPrivate();
            pub.mlPubLen = pub.ml.getEncoded().length;
        }
        if (s.hasRsa()) {
            RSAKeyPairGenerator g = new RSAKeyPairGenerator();
            g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), RNG, 3072, 100));
            AsymmetricCipherKeyPair kp = g.generateKeyPair();
            pub.rsa = (RSAKeyParameters) kp.getPublic();
            rsaPriv = (RSAPrivateCrtKeyParameters) kp.getPrivate();
            pub.rsaPubDer = rsaPublicKeyDer(pub.rsa);
        }
        switch (s) {
            case RSA3072:
                return PrivateKeyInfoFactory.createPrivateKeyInfo(rsaPriv).getEncoded("DER");
            case MLKEM768: case MLKEM1024: {
                byte[] oid = s == Suite.MLKEM768 ? OID_MLKEM768 : OID_MLKEM1024;
                byte[] choice = f == Fmt.SEED ? tlv(0x80, mlPriv.getSeed()) : tlv(0x04, expanded(mlPriv));
                return pkcs8(oid, choice);
            }
            default: {
                byte[] mlPart = f == Fmt.SEED ? mlPriv.getSeed() : expanded(mlPriv);
                return pkcs8(OID_HYBRID, cat(mlPart, rsaPrivateKeyDer(rsaPriv)));
            }
        }
    }
    static byte[] expanded(MLKEMPrivateKeyParameters k) {
        return k.getParametersWithFormat(MLKEMPrivateKeyParameters.EXPANDED_KEY).getEncoded();
    }

    /** Load a stored credential through the library's private-key factories (D-013). */
    public static Priv loadCredential(Suite s, Fmt f, byte[] der) throws Exception {
        Priv p = new Priv();
        if (s == Suite.RSA3072) {
            p.rsa = (RSAPrivateCrtKeyParameters) org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(der);
            return p;
        }
        if (s != Suite.HYBRID) {
            p.ml = (MLKEMPrivateKeyParameters) org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(der);
            return p;
        }
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(der);
        byte[] raw = ASN1OctetString.getInstance(info.getPrivateKey()).getOctets();
        int mlLen = f == Fmt.SEED ? 64 : 3168;
        byte[] mlPart = Arrays.copyOfRange(raw, 0, mlLen);
        byte[] rsaPart = Arrays.copyOfRange(raw, mlLen, raw.length);
        byte[] mlP8 = pkcs8(OID_MLKEM1024, f == Fmt.SEED ? tlv(0x80, mlPart) : tlv(0x04, mlPart));
        p.ml = (MLKEMPrivateKeyParameters) org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(mlP8);
        org.bouncycastle.asn1.pkcs.RSAPrivateKey r = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(rsaPart);
        p.rsa = new RSAPrivateCrtKeyParameters(r.getModulus(), r.getPublicExponent(), r.getPrivateExponent(),
                r.getPrime1(), r.getPrime2(), r.getExponent1(), r.getExponent2(), r.getCoefficient());
        return p;
    }

    // ---------------------------------------------------------------- KEM
    static OAEPEncoding oaep(boolean enc, AsymmetricKeyParameter k) {
        OAEPEncoding o = new OAEPEncoding(new RSABlindedEngine(), new SHA256Digest(), new SHA256Digest(), null);
        o.init(enc, enc ? new ParametersWithRandom(k, RNG) : k);
        return o;
    }
    static byte[] combine(byte[] ssMl, byte[] ssRsa, byte[] ctRsa, byte[] rsaPub) {
        SHA3Digest d = new SHA3Digest(256);
        for (byte[] x : new byte[][]{ssMl, ssRsa, ctRsa, rsaPub, HYBRID_LABEL}) d.update(x, 0, x.length);
        byte[] out = new byte[32]; d.doFinal(out, 0); return out;
    }

    /** Returns {ct, ss}. */
    public static byte[][] encap(Suite s, Pub pub) throws Exception {
        byte[] ctMl = new byte[0], ssMl = null;
        if (s.hasMl()) {
            SecretWithEncapsulation e = new MLKEMGenerator(RNG).generateEncapsulated(pub.ml);
            ctMl = e.getEncapsulation(); ssMl = e.getSecret();
            if (s != Suite.HYBRID) return new byte[][]{ctMl, ssMl};
        }
        byte[] ssRsa = new byte[32]; RNG.nextBytes(ssRsa);
        byte[] ctRsa = oaep(true, pub.rsa).processBlock(ssRsa, 0, 32);
        if (s == Suite.RSA3072) return new byte[][]{ctRsa, ssRsa};
        return new byte[][]{cat(ctMl, ctRsa), combine(ssMl, ssRsa, ctRsa, pub.rsaPubDer)};
    }

    public static byte[] decap(Suite s, Priv p, byte[] ct, byte[] rsaPubDer) throws Exception {
        byte[] ssMl = null; int mlCt = 0;
        if (s.hasMl()) {
            mlCt = s.mlCt();
            ssMl = new MLKEMExtractor(p.ml).extractSecret(Arrays.copyOfRange(ct, 0, mlCt));
            if (s != Suite.HYBRID) return ssMl;
        }
        byte[] ctRsa = Arrays.copyOfRange(ct, mlCt, ct.length);
        byte[] ssRsa = oaep(false, p.rsa).processBlock(ctRsa, 0, ctRsa.length);
        if (s == Suite.RSA3072) return ssRsa;
        return combine(ssMl, ssRsa, ctRsa, rsaPubDer);
    }

    // ---------------------------------------------------------------- KDF, key wrap
    static byte[] kek(byte[] ss, Suite s, int holder) {
        byte[] info = cat(KDF_LABEL, new byte[]{(byte) s.id, (byte) (holder >>> 24), (byte) (holder >>> 16),
                (byte) (holder >>> 8), (byte) holder});
        HKDFBytesGenerator h = new HKDFBytesGenerator(new SHA256Digest());
        h.init(new HKDFParameters(ss, null, info));
        byte[] k = new byte[32]; h.generateBytes(k, 0, 32); return k;
    }
    static byte[] wrap(byte[] key, byte[] in) {
        RFC3394WrapEngine w = new RFC3394WrapEngine(AESEngine.newInstance());
        w.init(true, new KeyParameter(key)); return w.wrap(in, 0, in.length);
    }
    static byte[] unwrap(byte[] key, byte[] in) throws Exception {
        RFC3394WrapEngine w = new RFC3394WrapEngine(AESEngine.newInstance());
        w.init(false, new KeyParameter(key)); return w.unwrap(in, 0, in.length);
    }

    // ---------------------------------------------------------------- account (A1)
    public static final class Account {
        public Suite s; public Fmt f; public byte[] cred; public Pub pub = new Pub();
        public byte[] pkg; public byte[] root = new byte[32]; public byte[][] children;
    }
    public static Account createAccount(Suite s, Fmt f, int nf, int holder) throws Exception {
        Account a = new Account(); a.s = s; a.f = f;
        a.cred = genCredential(s, f, a.pub);
        RNG.nextBytes(a.root);
        byte[][] e = encap(s, a.pub);
        a.pkg = cat(new byte[]{0x01, (byte) s.id}, e[0], wrap(kek(e[1], s, holder), a.root));
        a.children = new byte[nf][];
        for (int i = 0; i < nf; i++) { byte[] c = new byte[32]; RNG.nextBytes(c); a.children[i] = wrap(a.root, c); }
        return a;
    }
    /** E2: open the account from cold stored credential bytes; returns the root key or throws. */
    public static byte[] openAccount(Account a, int holder) throws Exception {
        Priv p = loadCredential(a.s, a.f, a.cred);
        if (a.pkg[0] != 0x01 || a.pkg[1] != (byte) a.s.id) throw new Exception("bad header");
        int ctLen = a.pkg.length - 2 - 40;
        byte[] ss = decap(a.s, p, Arrays.copyOfRange(a.pkg, 2, 2 + ctLen), a.pub.rsaPubDer);
        byte[] root = unwrap(kek(ss, a.s, holder), Arrays.copyOfRange(a.pkg, 2 + ctLen, a.pkg.length));
        for (byte[] c : a.children) unwrap(root, c);
        return root;
    }

    public static String bcVersion() {
        // getVersionStr() does not exist on Android's java.security.Provider; getInfo() does.
        return new org.bouncycastle.jce.provider.BouncyCastleProvider().getInfo();
    }

    // ---------------------------------------------------------------- selftest, sizes
    public static String selftest() {
        StringBuilder out = new StringBuilder("P15 A1 selftest (Bouncy Castle " + bcVersion() + ")\n");
        int fails = 0;
        try {
            byte[] seed = new byte[64]; for (int i = 0; i < 64; i++) seed[i] = (byte) i;
            byte[] mine = pkcs8(OID_MLKEM1024, tlv(0x80, seed));
            byte[] rfc = java.util.Base64.getDecoder().decode(
                "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");
            boolean ok = Arrays.equals(mine, rfc);
            fails += ok ? 0 : 1; out.append(ok ? "  ok:   " : "  FAIL: ").append("seed-format PKCS#8 matches RFC 9935 C.1.3.1\n");
            MLKEMPrivateKeyParameters k = (MLKEMPrivateKeyParameters) org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(rfc);
            byte[] e = expanded(k);
            ok = e.length == 3168 && (e[0] & 0xff) == 0xf7 && (e[1] & 0xff) == 0x7b && (e[2] & 0xff) == 0x7f && (e[3] & 0xff) == 0x6b;
            fails += ok ? 0 : 1; out.append(ok ? "  ok:   " : "  FAIL: ").append("expanded key from the RFC seed matches C.1.3.2 prefix\n");
        } catch (Exception ex) { fails++; out.append("  FAIL: RFC vector: ").append(ex).append('\n'); }
        // Known answers from the composite ML-KEM draft (tools/gen_composite_kat.py)
        try {
            java.util.Base64.Decoder d = java.util.Base64.getDecoder();
            Priv pm = loadCredential(Suite.MLKEM1024, Fmt.SEED, d.decode(CompositeKat.ML_DK_PKCS8));
            boolean ok = Arrays.equals(decap(Suite.MLKEM1024, pm, d.decode(CompositeKat.ML_C), null), d.decode(CompositeKat.ML_K));
            fails += ok ? 0 : 1; out.append(ok ? "  ok:   " : "  FAIL: ").append("ML-KEM-1024 decapsulation matches composite-draft vector\n");
            Priv ph = loadCredential(Suite.HYBRID, Fmt.SEED, d.decode(CompositeKat.HYB_DK_PKCS8));
            ok = Arrays.equals(decap(Suite.HYBRID, ph, d.decode(CompositeKat.HYB_C), d.decode(CompositeKat.HYB_RSA_PUB)),
                               d.decode(CompositeKat.HYB_K));
            fails += ok ? 0 : 1; out.append(ok ? "  ok:   " : "  FAIL: ")
                .append("hybrid decapsulation and combiner match id-MLKEM1024-RSA3072-SHA3-256 vector\n");
        } catch (Exception ex) { fails++; out.append("  FAIL: composite-draft vectors: ").append(ex).append('\n'); }
        for (Suite s : Suite.values()) for (Fmt f : new Fmt[]{Fmt.SEED, Fmt.EXPANDED}) {
            if (s == Suite.RSA3072 && f == Fmt.EXPANDED) continue;
            String tag = String.format("%-9s %-8s ", s.name, s == Suite.RSA3072 ? "na" : f.name);
            try {
                Account a = createAccount(s, f, 7, 1);
                boolean ok = Arrays.equals(openAccount(a, 1), a.root);
                fails += ok ? 0 : 1;
                out.append(ok ? "  ok:   " : "  FAIL: ").append(tag)
                   .append("open account round trip (package ").append(a.pkg.length).append(" B, credential ")
                   .append(a.cred.length).append(" B)\n");
                boolean rejected; try { openAccount(a, 2); rejected = false; } catch (Exception x) { rejected = true; }
                fails += rejected ? 0 : 1;
                out.append(rejected ? "  ok:   " : "  FAIL: ").append(tag).append("wrong holder id is rejected\n");
            } catch (Exception ex) { fails++; out.append("  FAIL: ").append(tag).append(ex).append('\n'); }
        }
        out.append(fails == 0 ? "\nSELFTEST PASSED (0 failures)\n" : "\nSELFTEST FAILED (" + fails + " failures)\n");
        return out.toString();
    }

    public static String sizes() throws Exception {
        StringBuilder out = new StringBuilder("suite,format,credential_pkcs8,public_raw,kem_ct,access_package\n");
        for (Suite s : Suite.values()) for (Fmt f : new Fmt[]{Fmt.SEED, Fmt.EXPANDED}) {
            if (s == Suite.RSA3072 && f == Fmt.EXPANDED) continue;
            Account a = createAccount(s, f, 1, 1);
            int praw = s == Suite.RSA3072 ? a.pub.rsaPubDer.length
                     : s == Suite.HYBRID ? a.pub.mlPubLen + a.pub.rsaPubDer.length : a.pub.mlPubLen;
            out.append(s.name).append(',').append(s == Suite.RSA3072 ? "na" : f.name).append(',')
               .append(a.cred.length).append(',').append(praw).append(',').append(a.pkg.length - 42).append(',')
               .append(a.pkg.length).append('\n');
        }
        return out.toString();
    }

    // ---------------------------------------------------------------- bench (one run)
    /** Runs `warmup` untimed and `iters` timed operations; returns nanoseconds per timed op. */
    public static long[] bench(Suite s, Fmt f, String op, int iters, int warmup, int nf) throws Exception {
        Fmt lf = f == Fmt.NA ? Fmt.SEED : f;
        Account a = createAccount(s, lf, nf, 1);
        long[] ns = new long[iters];
        byte[] newRoot = new byte[32]; RNG.nextBytes(newRoot);
        for (int phase = 0; phase < 2; phase++) {
            int n = phase == 0 ? warmup : iters;
            for (int i = 0; i < n; i++) {
                long t0, t1;
                switch (op) {
                    case "open":   t0 = System.nanoTime(); openAccount(a, 1); t1 = System.nanoTime(); break;
                    case "load":   t0 = System.nanoTime(); loadCredential(s, lf, a.cred); t1 = System.nanoTime(); break;
                    case "encap":  t0 = System.nanoTime(); encap(s, a.pub); t1 = System.nanoTime(); break;
                    case "decap": {
                        Priv p = loadCredential(s, lf, a.cred);
                        int ctLen = a.pkg.length - 42;
                        byte[] ct = Arrays.copyOfRange(a.pkg, 2, 2 + ctLen);
                        t0 = System.nanoTime(); decap(s, p, ct, a.pub.rsaPubDer); t1 = System.nanoTime(); break;
                    }
                    case "keygen": t0 = System.nanoTime(); genCredential(s, lf, new Pub()); t1 = System.nanoTime(); break;
                    case "rewrap": {  // one migration step: unwrap a child under the old parent, wrap under the new one
                        t0 = System.nanoTime(); wrap(newRoot, unwrap(a.root, a.children[0])); t1 = System.nanoTime(); break;
                    }
                    default: throw new IllegalArgumentException(op);
                }
                if (phase == 1) ns[i] = t1 - t0;
            }
        }
        return ns;
    }

    /** FIPS 203 ACVP vectors (testdata/acvp_mlkem.txt) through the measurement loading path (D-023). */
    static int acvp(String path) throws Exception {
        int n = 0, bad = 0;
        for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get(path))) {
            if (line.startsWith("#") || line.trim().isEmpty()) continue;
            String[] f = line.trim().split(" ");
            Suite s = Suite.of(f[1]);
            byte[] oid = s == Suite.MLKEM768 ? OID_MLKEM768 : OID_MLKEM1024;
            boolean ok;
            if (f[0].equals("kg")) {
                Priv p = loadCredential(s, Fmt.SEED, pkcs8(oid, tlv(0x80, hex(f[2]))));
                ok = Arrays.equals(expanded(p.ml), hex(f[3]));
            } else {
                Priv p = loadCredential(s, Fmt.EXPANDED, pkcs8(oid, tlv(0x04, hex(f[2]))));
                ok = Arrays.equals(decap(s, p, hex(f[3]), null), hex(f[4]));
            }
            n++; if (!ok) { bad++; System.out.println("  FAIL: " + f[0] + " " + f[1] + " vector " + n); }
        }
        System.out.println("ACVP ML-KEM (Bouncy Castle " + bcVersion() + "): " + n + " vectors, " + bad + " failures");
        return bad == 0 && n > 0 ? 0 : 1;
    }

    // ------------------------------------------------ cross-platform interchange (D-023)
    static String hx(byte[] b) {
        if (b == null || b.length == 0) return "-";
        StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x & 0xff)); return sb.toString();
    }
    static void xexport(String dir) throws Exception {
        for (Suite s : Suite.values()) for (Fmt f : new Fmt[]{Fmt.SEED, Fmt.EXPANDED}) {
            if (s == Suite.RSA3072 && f == Fmt.EXPANDED) continue;
            Account a = createAccount(s, f, 7, 1);
            String fn = s == Suite.RSA3072 ? "na" : f.name;
            StringBuilder o = new StringBuilder("impl bouncycastle\nsuite " + s.name + "\nformat " + fn + "\n");
            o.append("cred ").append(hx(a.cred)).append("\nrsa_pub ").append(hx(a.pub.rsaPubDer))
             .append("\npkg ").append(hx(a.pkg)).append("\nroot ").append(hx(a.root)).append('\n');
            for (byte[] c : a.children) o.append("child ").append(hx(c)).append('\n');
            java.nio.file.Files.write(java.nio.file.Paths.get(dir, "bouncycastle_" + s.name + "_" + fn + ".txt"),
                                      o.toString().getBytes("US-ASCII"));
        }
    }
    static int xopen(String[] files) throws Exception {
        int bad = 0;
        for (String file : files) {
            Account a = new Account(); String impl = "?", fn = "";
            java.util.List<byte[]> ch = new java.util.ArrayList<>(); byte[] want = null;
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get(file))) {
                String[] kv = line.trim().split(" ", 2); if (kv.length < 2) continue;
                switch (kv[0]) {
                    case "impl": impl = kv[1]; break;
                    case "suite": a.s = Suite.of(kv[1]); break;
                    case "format": fn = kv[1]; break;
                    case "cred": a.cred = hex(kv[1]); break;
                    case "rsa_pub": a.pub.rsaPubDer = kv[1].equals("-") ? new byte[0] : hex(kv[1]); break;
                    case "pkg": a.pkg = hex(kv[1]); break;
                    case "root": want = hex(kv[1]); break;
                    case "child": ch.add(hex(kv[1])); break;
                    default: break;
                }
            }
            a.f = fn.equals("expanded") ? Fmt.EXPANDED : Fmt.SEED;
            a.children = ch.toArray(new byte[0][]);
            boolean ok;
            try { ok = Arrays.equals(openAccount(a, 1), want); } catch (Exception e) { ok = false; }
            if (!ok) bad++;
            System.out.printf("  %s  %-12s -> bouncycastle: %-9s %-8s (%d children)%n", ok ? "ok:  " : "FAIL:", impl, a.s.name, fn, ch.size());
        }
        System.out.println("Cross-platform open on Bouncy Castle: " + files.length + " files, " + bad + " failures");
        return bad == 0 ? 0 : 1;
    }

    static byte[] hex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    /** Desktop entry point for testing on a JVM: java P15Core selftest|sizes|bench suite fmt op iters */
    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("selftest")) { System.out.print(selftest()); return; }
        if (args[0].equals("sizes")) { System.out.print(sizes()); return; }
        if (args[0].equals("acvp")) { System.exit(acvp(args[1])); }
        if (args[0].equals("xexport")) { xexport(args[1]); return; }
        if (args[0].equals("xopen")) { System.exit(xopen(Arrays.copyOfRange(args, 1, args.length))); }
        long[] ns = bench(Suite.of(args[1]), Fmt.of(args[2]), args[3], Integer.parseInt(args[4]), 50, 7);
        long[] c = ns.clone(); Arrays.sort(c);
        System.out.printf("%s %s %s median %.1f us%n", args[1], args[2], args[3], c[c.length / 2] / 1000.0);
    }
}
