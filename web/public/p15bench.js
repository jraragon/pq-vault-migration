(() => {
  // node_modules/@noble/hashes/_u64.js
  var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
  var _32n = /* @__PURE__ */ BigInt(32);
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }

  // node_modules/@noble/hashes/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  var atitle = (title) => title ? `"${title}" ` : "";
  function anumber(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abool(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function abytes(value, length, title = "") {
    if (isBytes(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber(length, "length");
    const bytes = isBytes(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  var aobject = (value, label) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
  };
  var aopts = (value, label) => {
    aobject(value, label);
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`"${label}" expected plain object`);
    if (Object.hasOwn(value, "__proto__"))
      throw new TypeError(`"${label}.__proto__" is not allowed`);
  };
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput(out2, instance) {
    abytes(out2, void 0, "output");
    const min = instance.outputLen;
    if (!(out2.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;
  function checkOpts(defaults, opts2, title = "opts") {
    aopts(defaults, "defaults");
    if (opts2 !== void 0)
      aopts(opts2, title);
    const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts2);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    if (typeof hashCons !== "function")
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    info = checkOpts({}, info, "info");
    const hashC = (msg, opts2) => hashCons(opts2).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts2) => hashCons(opts2);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  function randomBytes(bytesLength = 32) {
    anumber(bytesLength, "bytesLength");
    const cr = typeof globalThis === "object" ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined");
    if (bytesLength > 65536)
      throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
    return cr.getRandomValues(new Uint8Array(bytesLength));
  }
  var oidNist = (suffix) => ({
    // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
    // Larger suffix values would need base-128 OID encoding and a different length byte.
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
  });

  // node_modules/@noble/hashes/sha3.js
  var _0n = BigInt(0);
  var _1n = BigInt(1);
  var _2n = BigInt(2);
  var _7n = BigInt(7);
  var _256n = BigInt(256);
  var _0x71n = BigInt(113);
  var SHA3_PI = [];
  var SHA3_ROTL = [];
  var _SHA3_IOTA = [];
  for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n)
        t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
  }
  var IOTAS = split(_SHA3_IOTA, true);
  var SHA3_IOTA_H = IOTAS[0];
  var SHA3_IOTA_L = IOTAS[1];
  var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
  var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  var B = new Uint32Array(5 * 2);
  function keccakP(s, rounds = 24) {
    if (!(s instanceof Uint32Array))
      throw new TypeError('"s" expected Uint32Array(50), got type=' + typeof s);
    if (s.length !== 50)
      throw new RangeError('"s" expected Uint32Array(50), got length=' + s.length);
    anumber(rounds, "rounds");
    if (rounds < 1 || rounds > 24)
      throw new Error('"rounds" expected integer 1..24');
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++)
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      for (let x = 0; x < 10; x += 2) {
        const idx1 = (x + 8) % 10;
        const idx0 = (x + 2) % 10;
        const B0 = B[idx0];
        const B1 = B[idx0 + 1];
        const Th = rotlH(B0, B1, 1) ^ B[idx1];
        const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
        for (let y = 0; y < 50; y += 10) {
          s[x + y] ^= Th;
          s[x + y + 1] ^= Tl;
        }
      }
      let curH = s[2];
      let curL = s[3];
      for (let t = 0; t < 24; t++) {
        const shift = SHA3_ROTL[t];
        const Th = rotlH(curH, curL, shift);
        const Tl = rotlL(curH, curL, shift);
        const PI = SHA3_PI[t];
        curH = s[PI];
        curL = s[PI + 1];
        s[PI] = Th;
        s[PI + 1] = Tl;
      }
      for (let y = 0; y < 50; y += 10) {
        const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
        s[y] ^= ~s[y + 2] & s[y + 4];
        s[y + 1] ^= ~s[y + 3] & s[y + 5];
        s[y + 2] ^= ~s[y + 4] & s[y + 6];
        s[y + 3] ^= ~s[y + 5] & s[y + 7];
        s[y + 4] ^= ~s[y + 6] & s[y + 8];
        s[y + 5] ^= ~s[y + 7] & s[y + 9];
        s[y + 6] ^= ~s[y + 8] & b0;
        s[y + 7] ^= ~s[y + 9] & b1;
        s[y + 8] ^= ~b0 & b2;
        s[y + 9] ^= ~b1 & b3;
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
  }
  var Keccak = class _Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    canXOF;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
      anumber(blockLen, "blockLen");
      anumber(suffix, "suffix");
      anumber(rounds, "rounds");
      abool(enableXOF, "enableXOF");
      this.blockLen = blockLen;
      this.suffix = suffix;
      this.outputLen = outputLen;
      this.enableXOF = enableXOF;
      this.canXOF = enableXOF;
      this.rounds = rounds;
      anumber(outputLen, "outputLen");
      if (!(0 < blockLen && blockLen < 200))
        throw new Error('"blockLen" must be 1..199');
      this.state = new Uint8Array(200);
      this.state32 = u32(this.state);
    }
    clone() {
      return this._cloneInto();
    }
    keccak() {
      swap32IfBE(this.state32);
      keccakP(this.state32, this.rounds);
      swap32IfBE(this.state32);
      this.posOut = 0;
      this.pos = 0;
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { blockLen, state, state32 } = this;
      const len = data.length;
      const canUseU32 = blockLen % 4 === 0 && data.byteOffset % 4 === 0;
      const blockLen32 = blockLen / 4;
      const data32 = canUseU32 && len >= blockLen ? u32(data) : void 0;
      for (let pos = 0; pos < len; ) {
        if (data32 !== void 0 && this.pos === 0 && pos % 4 === 0 && len - pos >= blockLen) {
          for (let i = 0, o = pos / 4; i < blockLen32; i++)
            state32[i] ^= data32[o + i];
          pos += blockLen;
          this.pos = blockLen;
          this.keccak();
          continue;
        }
        const take = Math.min(blockLen - this.pos, len - pos);
        for (let i = 0; i < take; i++)
          state[this.pos++] ^= data[pos++];
        if (this.pos === blockLen)
          this.keccak();
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      const { state, suffix, pos, blockLen } = this;
      state[pos] ^= suffix;
      if ((suffix & 128) !== 0 && pos === blockLen - 1)
        this.keccak();
      state[blockLen - 1] ^= 128;
      this.keccak();
    }
    writeInto(out2) {
      aexists(this, false);
      abytes(out2);
      this.finish();
      const bufferOut = this.state;
      const { blockLen } = this;
      for (let pos = 0, len = out2.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.keccak();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out2.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out2;
    }
    xofInto(out2) {
      if (!this.enableXOF)
        throw new Error("XOF is not enabled");
      return this.writeInto(out2);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out2) {
      aoutput(out2, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.writeInto(out2.length === this.outputLen ? out2 : out2.subarray(0, this.outputLen));
      this.destroy();
    }
    digest() {
      const out2 = new Uint8Array(this.outputLen);
      this.digestInto(out2);
      return out2;
    }
    destroy() {
      this.destroyed = true;
      clean(this.state);
    }
    _cloneInto(to) {
      const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
      to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
      to.blockLen = blockLen;
      to.state32.set(this.state32);
      to.pos = this.pos;
      to.posOut = this.posOut;
      to.finished = this.finished;
      to.rounds = rounds;
      to.suffix = suffix;
      to.outputLen = outputLen;
      to.enableXOF = enableXOF;
      to.canXOF = this.canXOF;
      to.destroyed = this.destroyed;
      return to;
    }
  };
  var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
  var sha3_256 = /* @__PURE__ */ genKeccak(
    6,
    136,
    32,
    /* @__PURE__ */ oidNist(8)
  );
  var sha3_512 = /* @__PURE__ */ genKeccak(
    6,
    72,
    64,
    /* @__PURE__ */ oidNist(10)
  );
  var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts2 = {}) => {
    opts2 = checkOpts({}, opts2);
    return new Keccak(blockLen, suffix, opts2.dkLen === void 0 ? outputLen : opts2.dkLen, true);
  }, info);
  var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
  var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

  // node_modules/@noble/curves/utils.js
  function aobject2(value, title = "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
    return value;
  }
  function validateObject(object, fields = {}, optFields = {}, title = "object") {
    aobject2(object, title);
    aobject2(fields, "fields");
    aobject2(optFields, "optFields");
    function checkField(fieldName, expectedType, isOpt) {
      const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
      const val = object[fieldName];
      if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
        throw new TypeError(`${label} is invalid: expected own property`);
      }
      if (isOpt && val === void 0)
        return;
      const current = typeof val;
      if (current !== expectedType || val === null)
        throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
    }
    const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
    iter(fields, false);
    iter(optFields, true);
  }

  // node_modules/@noble/curves/abstract/fft.js
  function checkU32(n, title = "n") {
    if (typeof n !== "number")
      throw new TypeError(`wrong u32 integer "${title}": expected number, got type=${typeof n}`);
    if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
      throw new RangeError(`wrong u32 integer "${title}": expected 0..4294967295, got ${n}`);
    return n;
  }
  function isPowerOfTwo(x) {
    checkU32(x, "x");
    return (x & x - 1) === 0 && x !== 0;
  }
  function reverseBits(n, bits) {
    checkU32(n);
    if (typeof bits !== "number")
      throw new TypeError('"bits" expected number, got type=' + typeof bits);
    if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
      throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
    let reversed = 0;
    for (let i = 0; i < bits; i++, n >>>= 1)
      reversed = reversed << 1 | n & 1;
    return reversed >>> 0;
  }
  function log2(n) {
    checkU32(n);
    return 31 - Math.clz32(n);
  }
  function bitReversalInplace(values) {
    if (!values || typeof values !== "object" || typeof values.length !== "number")
      throw new TypeError('"values" expected array-like, got type=' + typeof values);
    const n = values.length;
    if (!isPowerOfTwo(n))
      throw new Error("expected positive power-of-two length, got " + n);
    const bits = log2(n);
    for (let i = 0; i < n; i++) {
      const j = reverseBits(i, bits);
      if (i < j) {
        const tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
      }
    }
    return values;
  }
  var FFTCore = (F2, coreOpts) => {
    validateObject(coreOpts, { N: "number", roots: "object", dit: "boolean" }, { invertButterflies: "boolean", skipStages: "number", brp: "boolean" }, "coreOpts");
    const { N: N2, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
    checkU32(N2, "coreOpts.N");
    const bits = log2(N2);
    if (!isPowerOfTwo(N2))
      throw new Error("FFT: Polynomial size should be power of two");
    checkU32(skipStages, "coreOpts.skipStages");
    const maxSkipStages = bits === 0 ? 0 : bits - 1;
    if (skipStages > maxSkipStages)
      throw new Error(`FFT: wrong skipStages: expected 0 <= skipStages <= ${maxSkipStages}`);
    if (roots.length !== N2)
      throw new Error(`FFT: wrong roots length: expected ${N2}, got ${roots.length}`);
    const isDit = dit !== invertButterflies;
    return (values) => {
      if (values.length !== N2)
        throw new Error("FFT: wrong Polynomial length");
      if (dit && brp)
        bitReversalInplace(values);
      for (let i = 0, g = 1; i < bits - skipStages; i++) {
        const s = dit ? i + 1 + skipStages : bits - i;
        const m = 1 << s;
        const m2 = m >> 1;
        const stride = N2 >> s;
        for (let k = 0; k < N2; k += m) {
          for (let j = 0, grp = g++; j < m2; j++) {
            const rootPos = invertButterflies ? dit ? N2 - grp : grp : j * stride;
            const i0 = k + j;
            const i1 = k + j + m2;
            const omega = roots[rootPos];
            const b = values[i1];
            const a = values[i0];
            if (isDit) {
              const t = F2.mul(b, omega);
              values[i0] = F2.add(a, t);
              values[i1] = F2.sub(a, t);
            } else if (invertButterflies) {
              values[i0] = F2.add(b, a);
              values[i1] = F2.mul(F2.sub(b, a), omega);
            } else {
              values[i0] = F2.add(a, b);
              values[i1] = F2.mul(F2.sub(a, b), omega);
            }
          }
        }
      }
      if (!dit && brp)
        bitReversalInplace(values);
      return values;
    };
  };

  // node_modules/@noble/post-quantum/utils.js
  var abytesDoc = abytes;
  var randomBytes2 = randomBytes;
  function aarray2(item, title, inner = () => {
  }) {
    if (!Array.isArray(item))
      throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
    for (let i = 0; i < item.length; i++)
      inner(item[i], `${title}[${i}]`);
    return item;
  }
  function equalBytes(a, b) {
    a = abytes(a);
    b = abytes(b);
    if (a.length !== b.length)
      return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
      diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function copyBytes(bytes) {
    return new Uint8Array(abytes(bytes));
  }
  function splitCoder(label, ...lengths) {
    const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
    const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
    return {
      bytesLen,
      encode: (bufs) => {
        const res = new Uint8Array(bytesLen);
        for (let i = 0, pos = 0; i < lengths.length; i++) {
          const c = lengths[i];
          const l = getLength(c);
          const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
          abytes(b, l, label);
          res.set(b, pos);
          if (typeof c !== "number")
            b.fill(0);
          pos += l;
        }
        return res;
      },
      decode: (buf) => {
        abytes(buf, bytesLen, label);
        const res = [];
        for (const c of lengths) {
          const l = getLength(c);
          const b = buf.subarray(0, l);
          res.push(typeof c === "number" ? b : c.decode(b));
          buf = buf.subarray(l);
        }
        return res;
      }
    };
  }
  function vecCoder(c, vecLen) {
    const coder = c;
    const bytesLen = vecLen * coder.bytesLen;
    return {
      bytesLen,
      encode: (u) => {
        const uArr = aarray2(u, "u");
        if (uArr.length !== vecLen)
          throw new RangeError(`vecCoder.encode: wrong length=${uArr.length}. Expected: ${vecLen}`);
        const res = new Uint8Array(bytesLen);
        for (let i = 0, pos = 0; i < uArr.length; i++) {
          const b = coder.encode(uArr[i]);
          res.set(b, pos);
          b.fill(0);
          pos += b.length;
        }
        return res;
      },
      decode: (a) => {
        abytes(a, bytesLen);
        const r = [];
        for (let i = 0; i < a.length; i += coder.bytesLen)
          r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
        return r;
      }
    };
  }
  function cleanBytes(...list) {
    for (const t of list) {
      if (Array.isArray(t))
        for (const b of t)
          b.fill(0);
      else
        t.fill(0);
    }
  }
  function getMask(bits) {
    anumber(bits, "bits");
    if (bits > 32)
      throw new RangeError('"bits" expected <= 32, got ' + bits);
    return bits === 32 ? 4294967295 : ~(-1 << bits) >>> 0;
  }

  // node_modules/@noble/post-quantum/_crystals.js
  var genCrystals = (opts2) => {
    const { newPoly, N: N2, Q: Q2, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts2;
    const mod = (a, modulo = Q2) => {
      const result = a % modulo | 0;
      return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
    };
    const smod = (a, modulo = Q2) => {
      const r = mod(a, modulo) | 0;
      return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
    };
    function getZettas() {
      const out2 = newPoly(N2);
      for (let i = 0; i < N2; i++) {
        const b = reverseBits(i, brvBits);
        const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q2);
        out2[i] = Number(p) | 0;
      }
      return out2;
    }
    const nttZetas = getZettas();
    const inv = (_a) => {
      throw new Error("not implemented");
    };
    const field = isKyber ? {
      add: (a, b) => {
        const r = a + b | 0;
        return r >= Q2 ? r - Q2 | 0 : r;
      },
      sub: (a, b) => {
        const r = a - b | 0;
        return r < 0 ? r + Q2 | 0 : r;
      },
      mul: (a, b) => mod((a | 0) * (b | 0)) | 0,
      inv
    } : {
      add: (a, b) => mod((a | 0) + (b | 0)) | 0,
      sub: (a, b) => mod((a | 0) - (b | 0)) | 0,
      mul: (a, b) => mod((a | 0) * (b | 0)) | 0,
      inv
    };
    const nttOpts = {
      N: N2,
      roots: nttZetas,
      invertButterflies: true,
      skipStages: isKyber ? 1 : 0,
      brp: false
    };
    const dif = FFTCore(field, { dit: false, ...nttOpts });
    const dit = FFTCore(field, { dit: true, ...nttOpts });
    const NTT = {
      encode: (r) => {
        return dif(r);
      },
      decode: (r) => {
        dit(r);
        for (let i = 0; i < r.length; i++)
          r[i] = mod(F2 * r[i]);
        return r;
      }
    };
    const bitsCoder = (d, c) => {
      for (let i = 0, bufLen = 0; i < N2; i++) {
        bufLen += d;
        if (bufLen > 32)
          getMask(bufLen);
        bufLen %= 8;
      }
      const mask = getMask(d);
      const bytesLen = d * (N2 / 8);
      return {
        bytesLen,
        encode: (poly_) => {
          const poly = poly_;
          const r = new Uint8Array(bytesLen);
          for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
            buf |= (c.encode(poly[i]) & mask) << bufLen;
            bufLen += d;
            for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
              r[pos++] = buf & 255;
          }
          return r;
        },
        decode: (bytes) => {
          const r = newPoly(N2);
          for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
            buf |= bytes[i] << bufLen;
            bufLen += 8;
            for (; bufLen >= d; bufLen -= d, buf >>= d)
              r[pos++] = c.decode(buf & mask);
          }
          return r;
        }
      };
    };
    return {
      mod,
      smod,
      nttZetas,
      NTT: {
        encode: (r) => NTT.encode(r),
        decode: (r) => NTT.decode(r)
      },
      bitsCoder
    };
  };
  var createXofShake = (shake) => (seed, blockLen) => {
    if (!blockLen)
      blockLen = shake.blockLen;
    const _seed = new Uint8Array(seed.length + 2);
    _seed.set(seed);
    const seedLen = seed.length;
    const buf = new Uint8Array(blockLen);
    let h = shake.create({});
    let calls = 0;
    let xofs = 0;
    return {
      stats: () => ({ calls, xofs }),
      get: (x, y) => {
        _seed[seedLen + 0] = x;
        _seed[seedLen + 1] = y;
        h.destroy();
        h = shake.create({}).update(_seed);
        calls++;
        return () => {
          xofs++;
          return h.xofInto(buf);
        };
      },
      clean: () => {
        h.destroy();
        cleanBytes(buf, _seed);
      }
    };
  };
  var XOF128 = /* @__PURE__ */ createXofShake(shake128);

  // node_modules/@noble/post-quantum/ml-kem.js
  var N = 256;
  var Q = 3329;
  var F = 3303;
  var ROOT_OF_UNITY = 17;
  var crystals = /* @__PURE__ */ genCrystals({
    N,
    Q,
    F,
    ROOT_OF_UNITY,
    newPoly: (n) => new Uint16Array(n),
    brvBits: 7,
    isKyber: true
  });
  var PARAMS = /* @__PURE__ */ (() => Object.freeze({
    512: Object.freeze({ N, Q, K: 2, ETA1: 3, ETA2: 2, du: 10, dv: 4, RBGstrength: 128 }),
    768: Object.freeze({ N, Q, K: 3, ETA1: 2, ETA2: 2, du: 10, dv: 4, RBGstrength: 192 }),
    1024: Object.freeze({ N, Q, K: 4, ETA1: 2, ETA2: 2, du: 11, dv: 5, RBGstrength: 256 })
  }))();
  var compress = (d) => {
    if (d >= 12)
      return { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i };
    const a = 2 ** (d - 1);
    return {
      // This only matches standalone Compress_d after bitsCoder masks the result into Z_(2^d).
      encode: (i) => ((i << d) + Q / 2) / Q,
      // const decompress = (i: number) => round((Q / 2 ** d) * i);
      decode: (i) => i * Q + a >>> d
    };
  };
  var byteCoder = (d) => crystals.bitsCoder(d, d === 12 ? { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i } : { encode: (i) => i, decode: (i) => i });
  var polyCoder = (d) => d === 12 ? byteCoder(12) : crystals.bitsCoder(d, compress(d));
  function polyAdd(a_, b_) {
    const a = a_;
    const b = b_;
    for (let i = 0; i < N; i++) {
      const r = a[i] + b[i];
      a[i] = r >= Q ? r - Q : r;
    }
  }
  function polySub(a_, b_) {
    const a = a_;
    const b = b_;
    for (let i = 0; i < N; i++) {
      const r = a[i] - b[i];
      a[i] = r < 0 ? r + Q : r;
    }
  }
  function BaseCaseMultiply(a0, a1, b0, b1, zeta) {
    const c0 = crystals.mod(crystals.mod(a1 * b1) * zeta + a0 * b0);
    const c1 = crystals.mod(a0 * b1 + a1 * b0);
    return { c0, c1 };
  }
  function MultiplyNTTs(f_, g_) {
    const f = f_;
    const g = g_;
    for (let i = 0; i < N / 2; i++) {
      let z = crystals.nttZetas[64 + (i >> 1)];
      if (i & 1)
        z = -z;
      const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
      f[2 * i + 0] = c0;
      f[2 * i + 1] = c1;
    }
    return f;
  }
  function SampleNTT(xof_) {
    const xof = xof_;
    const r = new Uint16Array(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      if (b.length % 3)
        throw new Error("SampleNTT: unaligned block");
      for (let i = 0; j < N && i + 3 <= b.length; i += 3) {
        const d1 = (b[i + 0] >> 0 | b[i + 1] << 8) & 4095;
        const d2 = (b[i + 1] >> 4 | b[i + 2] << 4) & 4095;
        if (d1 < Q)
          r[j++] = d1;
        if (j < N && d2 < Q)
          r[j++] = d2;
      }
    }
    return r;
  }
  var sampleCBDBytes = (buf, eta) => {
    const r = new Uint16Array(N);
    const b32 = u32(buf);
    swap32IfBE(b32);
    let len = 0;
    for (let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++) {
      let b = b32[i];
      for (let j = 0; j < 32; j++) {
        bb += b & 1;
        b >>= 1;
        len += 1;
        if (len === eta) {
          t0 = bb;
          bb = 0;
        } else if (len === 2 * eta) {
          r[p++] = crystals.mod(t0 - bb);
          bb = 0;
          len = 0;
        }
      }
    }
    swap32IfBE(b32);
    if (len)
      throw new Error(`sampleCBD: leftover bits: ${len}`);
    return r;
  };
  function sampleCBD(PRF_, seed, nonce, eta) {
    const PRF = PRF_;
    return sampleCBDBytes(PRF(eta * N / 4, seed, nonce), eta);
  }
  var genKPKE = (opts_) => {
    const opts2 = opts_;
    const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts2;
    const poly1 = polyCoder(1);
    const polyV = polyCoder(dv);
    const polyU = polyCoder(du);
    const publicCoder = splitCoder("publicKey", vecCoder(polyCoder(12), K), 32);
    const secretCoder = vecCoder(polyCoder(12), K);
    const cipherCoder = splitCoder("ciphertext", vecCoder(polyU, K), polyV);
    const seedCoder = splitCoder("seed", 32, 32);
    const encryptCore = (tHat, getA, msg, seed) => {
      const rHat = [];
      for (let i = 0; i < K; i++)
        rHat.push(crystals.NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
      const tmp2 = new Uint16Array(N);
      const u = [];
      for (let i = 0; i < K; i++) {
        const e1 = sampleCBD(PRF, seed, K + i, ETA2);
        const tmp = new Uint16Array(N);
        for (let j = 0; j < K; j++) {
          const aij = getA(i, j);
          polyAdd(tmp, MultiplyNTTs(aij, rHat[j]));
        }
        polyAdd(e1, crystals.NTT.decode(tmp));
        u.push(e1);
        polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i]));
        cleanBytes(tmp);
      }
      const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
      polyAdd(e2, crystals.NTT.decode(tmp2));
      const v = poly1.decode(msg);
      polyAdd(v, e2);
      cleanBytes(tHat, rHat, tmp2, e2);
      return cipherCoder.encode([u, v]);
    };
    return {
      secretCoder,
      lengths: {
        secretKey: secretCoder.bytesLen,
        publicKey: publicCoder.bytesLen,
        cipherText: cipherCoder.bytesLen
      },
      keygen: (seed) => {
        abytesDoc(seed, 32, "seed");
        const seedDst = new Uint8Array(33);
        seedDst.set(seed);
        seedDst[32] = K;
        const seedHash = HASH512(seedDst);
        const [rho, sigma] = seedCoder.decode(seedHash);
        const sHat = [];
        const tHat = [];
        for (let i = 0; i < K; i++)
          sHat.push(crystals.NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
        const x = XOF(rho);
        for (let i = 0; i < K; i++) {
          const e = crystals.NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
          for (let j = 0; j < K; j++) {
            const aji = SampleNTT(x.get(j, i));
            polyAdd(e, MultiplyNTTs(aji, sHat[j]));
          }
          tHat.push(e);
        }
        x.clean();
        const res = {
          publicKey: publicCoder.encode([tHat, rho]),
          secretKey: secretCoder.encode(sHat)
        };
        cleanBytes(rho, sigma, sHat, tHat, seedDst, seedHash);
        return res;
      },
      encrypt: (publicKey, msg, seed) => {
        const [tHat, rho] = publicCoder.decode(publicKey);
        const x = XOF(rho);
        const res = encryptCore(tHat, (i, j) => SampleNTT(x.get(i, j)), msg, seed);
        x.clean();
        return res;
      },
      // Expands the full Â matrix (public data derived from rho) once, so repeated encryptions
      // against the same ek skip the K² SampleNTT XOF expansions. Cached polys are copied per
      // call because encryptCore mutates its inputs in place.
      prepare: (publicKey) => {
        const [tHat, rho] = publicCoder.decode(publicKey);
        const x = XOF(rho);
        const A = [];
        for (let i = 0; i < K; i++)
          for (let j = 0; j < K; j++)
            A.push(SampleNTT(x.get(i, j)));
        x.clean();
        return {
          encrypt: (msg, seed) => encryptCore(tHat.map((p) => p.slice()), (i, j) => A[i * K + j].slice(), msg, seed),
          clean: () => cleanBytes(tHat, A)
        };
      },
      decrypt: (cipherText, privateKey) => {
        const [u, v] = cipherCoder.decode(cipherText);
        const sk = secretCoder.decode(privateKey);
        const tmp = new Uint16Array(N);
        for (let i = 0; i < K; i++)
          polyAdd(tmp, MultiplyNTTs(sk[i], crystals.NTT.encode(u[i])));
        polySub(v, crystals.NTT.decode(tmp));
        const res = poly1.encode(v);
        cleanBytes(tmp, sk, u, v);
        return res;
      }
    };
  };
  function createKyber(opts2) {
    const rawOpts = opts2;
    const KPKE = genKPKE(rawOpts);
    const { HASH256, HASH512, KDF } = rawOpts;
    const { secretCoder: KPKESecretCoder, lengths } = KPKE;
    const secretCoder = splitCoder("secretKey", lengths.secretKey, lengths.publicKey, 32, 32);
    const msgLen = 32;
    const seedLen = 64;
    const validateModulus = (publicKey, fn) => {
      const eke = publicKey.subarray(0, 384 * rawOpts.K);
      const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes(eke)));
      const ok = equalBytes(ek, eke);
      cleanBytes(ek);
      if (!ok)
        throw new Error(`ML-KEM.${fn}: wrong publicKey modulus`);
    };
    const kemLengths = Object.freeze({
      ...lengths,
      seed: 64,
      msg: msgLen,
      msgRand: msgLen,
      secretKey: secretCoder.bytesLen
    });
    return Object.freeze({
      info: Object.freeze({ type: "ml-kem" }),
      lengths: kemLengths,
      keygen: (seed) => {
        const ownSeed = seed === void 0;
        const s = ownSeed ? randomBytes2(seedLen) : seed;
        let sk;
        let publicKeyHash;
        try {
          abytesDoc(s, seedLen, "seed");
          const keys = KPKE.keygen(s.subarray(0, 32));
          const publicKey = keys.publicKey;
          sk = keys.secretKey;
          publicKeyHash = HASH256(publicKey);
          const secretKey = secretCoder.encode([sk, publicKey, publicKeyHash, s.subarray(32)]);
          return {
            publicKey,
            secretKey
          };
        } finally {
          if (sk !== void 0)
            cleanBytes(sk);
          if (publicKeyHash !== void 0)
            cleanBytes(publicKeyHash);
          if (ownSeed)
            cleanBytes(s);
        }
      },
      getPublicKey: (secretKey) => {
        const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
        return Uint8Array.from(publicKey);
      },
      encapsulate: (publicKey, msg) => {
        const ownMsg = msg === void 0;
        const m = ownMsg ? randomBytes2(msgLen) : msg;
        let kr;
        try {
          abytesDoc(publicKey, lengths.publicKey, "publicKey");
          abytesDoc(m, msgLen, "message");
          validateModulus(publicKey, "encapsulate");
          kr = HASH512.create().update(m).update(HASH256(publicKey)).digest();
          const cipherText = KPKE.encrypt(publicKey, m, kr.subarray(32, 64));
          return {
            cipherText,
            sharedSecret: kr.subarray(0, 32)
          };
        } finally {
          if (kr !== void 0)
            cleanBytes(kr.subarray(32));
          if (ownMsg)
            cleanBytes(m);
        }
      },
      decapsulate: (cipherText, secretKey) => {
        abytesDoc(secretKey, secretCoder.bytesLen, "secretKey");
        abytesDoc(cipherText, lengths.cipherText, "cipherText");
        const k768 = secretCoder.bytesLen - 96;
        const start = k768 + 32;
        const test = HASH256(secretKey.subarray(k768 / 2, start));
        if (!equalBytes(test, secretKey.subarray(start, start + 32)))
          throw new Error("invalid secretKey: hash check failed");
        const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
        const msg = KPKE.decrypt(cipherText, sk);
        const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
        const Khat = kr.subarray(0, 32);
        const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
        const isValid = equalBytes(cipherText, cipherText2);
        const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
        cleanBytes(msg, cipherText2, kr.subarray(32), !isValid ? Khat : Kbar);
        return isValid ? Khat : Kbar;
      },
      /**
       * Experimental prototype: pre-expand a public key so repeated encapsulate/decapsulate
       * against the same key skip re-validation, H(ek), t̂ decoding and the K² SampleNTT
       * XOF expansions of Â. Only public data is cached; see {@link KEMPrepared}.
       */
      prepare: (publicKey) => {
        abytesDoc(publicKey, lengths.publicKey, "publicKey");
        validateModulus(publicKey, "prepare");
        const ek = copyBytes(publicKey);
        const publicKeyHash = HASH256(ek);
        const cached = KPKE.prepare(ek);
        return Object.freeze({
          publicKey: ek,
          encapsulate: (msg) => {
            const ownMsg = msg === void 0;
            const m = ownMsg ? randomBytes2(msgLen) : msg;
            let kr;
            try {
              abytesDoc(m, msgLen, "message");
              kr = HASH512.create().update(m).update(publicKeyHash).digest();
              const cipherText = cached.encrypt(m, kr.subarray(32, 64));
              return {
                cipherText,
                sharedSecret: kr.subarray(0, 32)
              };
            } finally {
              if (kr !== void 0)
                cleanBytes(kr.subarray(32));
              if (ownMsg)
                cleanBytes(m);
            }
          },
          decapsulate: (cipherText, secretKey) => {
            abytesDoc(secretKey, secretCoder.bytesLen, "secretKey");
            abytesDoc(cipherText, lengths.cipherText, "cipherText");
            const [sk, ekEmbedded, storedHash, z] = secretCoder.decode(secretKey);
            if (!equalBytes(ekEmbedded, ek) || !equalBytes(storedHash, publicKeyHash))
              throw new Error("ML-KEM.decapsulate: secretKey does not match prepared publicKey");
            const msg = KPKE.decrypt(cipherText, sk);
            const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
            const Khat = kr.subarray(0, 32);
            const cipherText2 = cached.encrypt(msg, kr.subarray(32, 64));
            const isValid = equalBytes(cipherText, cipherText2);
            const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
            cleanBytes(msg, cipherText2, kr.subarray(32), !isValid ? Khat : Kbar);
            return isValid ? Khat : Kbar;
          },
          clean: cached.clean
        });
      }
    });
  }
  function shakePRF(dkLen, key, nonce) {
    return shake256.create({ dkLen }).update(key).update(new Uint8Array([nonce])).digest();
  }
  var opts = /* @__PURE__ */ (() => ({
    HASH256: sha3_256,
    HASH512: sha3_512,
    KDF: shake256,
    XOF: XOF128,
    PRF: shakePRF
  }))();
  var mk = (params2) => createKyber({
    ...opts,
    ...params2
  });
  var ml_kem768 = /* @__PURE__ */ (() => mk(PARAMS[768]))();
  var ml_kem1024 = /* @__PURE__ */ (() => mk(PARAMS[1024]))();

  // src/composite_kat.js
  var HYB_DK_PKCS8 = "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";
  var HYB_RSA_PUB = "MIIBigKCAYEAzgRkZqMdBFqq4xJq7zT/lPeh6jHIszQaJZegA7lQRzQiHeXmAMo9n9yLYcXdbM6vyDTYxPNYmht8c3NxHv9p2wQCN4d1TAP6oIafG9Xg0RkwzaXH4iZrwpkQLx3g4FQKYxMNfmqhUXi6uGhqwioD1DwPrNgj/TwRI3d9lKXl3o5wrGkaYSKPyhbiY8Kh+vRFjUxC/8Fcq0+aYzE+i6QFXGH+WUjhFhFDhQG0ANItvcuPsxB8Z3lIq43gE1WDqHMK0jRDrsQa6oXn4LQxpuU5832UHQmf5DQRQRj2GLwNpqeKVbiZiqxJGwWLe2VKHO+t/0dQ9T+MRk55iWHcKMuUFG09CYSGVfb9ngqw4CwE7chJyTpLpISUbjyO38A+hzNW3JITPogJg0+YTFRxI1JeuT9AyEiI2nbHaJ2osgYM4L68DvTJ+bTa66j0jrbu+xelcVDHqrF63gHA331M0PDkpN+uh9zeJb9+gy0bJvw5hbNYmmbruP+G8GWBTjlpJSZdAgMBAAE=";
  var HYB_C = "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";
  var HYB_K = "smNPMrd5yE/zwIiSYi5Az5LtyHc0FY5LkqQrNJz1JJI=";
  var ML_DK_PKCS8 = "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQJRoTjN9hDQ1NYpCU5tGZSoIUM5ZoDmzLDjwBQcHaxHWeYzsdDrtHqIiP8AvurOMrG6+BzDqugsXKqTRbsenEzE=";
  var ML_C = "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";
  var ML_K = "MuSw3ep7ky0TI/amQG60QsspB4EF1fXhOEkWOzZHU4U=";

  // src/core.js
  var subtle = globalThis.crypto.subtle;
  var rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
  var enc = new TextEncoder();
  var SUITES = {
    rsa3072: { id: 1, ml: null, rsa: true },
    mlkem768: { id: 2, ml: ml_kem768, rsa: false, mlCt: 1088 },
    mlkem1024: { id: 3, ml: ml_kem1024, rsa: false, mlCt: 1568 },
    hybrid: { id: 4, ml: ml_kem1024, rsa: true, mlCt: 1568 }
  };
  var OID_MLKEM768 = Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 4, 2]);
  var OID_MLKEM1024 = Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 4, 3]);
  var OID_HYBRID = Uint8Array.from([6, 8, 43, 6, 1, 5, 5, 7, 6, 62]);
  var ALG_RSA = Uint8Array.from([6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]);
  var HYBRID_LABEL = enc.encode("MLKEM1024-RSAOAEP3072");
  var KDF_LABEL = enc.encode("P15/A1/package/v1");
  var RSA_ALG = { name: "RSA-OAEP", hash: "SHA-256" };
  function cat(...parts) {
    const n = parts.reduce((a, p) => a + p.length, 0), out2 = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
      out2.set(p, o);
      o += p.length;
    }
    return out2;
  }
  function derLen(n) {
    if (n < 128) return Uint8Array.of(n);
    if (n < 256) return Uint8Array.of(129, n);
    return Uint8Array.of(130, n >> 8, n & 255);
  }
  var tlv = (tag, v) => cat(Uint8Array.of(tag), derLen(v.length), v);
  var pkcs8 = (algContent, priv) => tlv(48, cat(Uint8Array.of(2, 1, 0), tlv(48, algContent), tlv(4, priv)));
  function readTLV(b, off) {
    const tag = b[off];
    let len = b[off + 1], p = off + 2;
    if (len & 128) {
      const n = len & 127;
      len = 0;
      for (let i = 0; i < n; i++) len = len << 8 | b[p++];
    }
    return { tag, start: p, end: p + len };
  }
  function pkcs8PrivateKey(der) {
    const seq = readTLV(der, 0);
    const ver = readTLV(der, seq.start);
    const alg = readTLV(der, ver.end);
    const oct = readTLV(der, alg.end);
    if (oct.tag !== 4) throw new Error("bad PKCS#8");
    return der.subarray(oct.start, oct.end);
  }
  function spkiToRsaPublicKey(spki) {
    const seq = readTLV(spki, 0), alg = readTLV(spki, seq.start), bits = readTLV(spki, alg.end);
    return spki.slice(bits.start + 1, bits.end);
  }
  async function genCredential(suiteName, fmt) {
    const s = SUITES[suiteName];
    const pub = { ml: null, rsa: null, rsaPubDer: new Uint8Array(0) };
    let seed, expanded, rsaPkcs8;
    if (s.ml) {
      seed = rand(64);
      const kp = s.ml.keygen(seed);
      pub.ml = kp.publicKey;
      expanded = kp.secretKey;
    }
    if (s.rsa) {
      const kp = await subtle.generateKey(
        { ...RSA_ALG, modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1) },
        true,
        ["encrypt", "decrypt"]
      );
      pub.rsa = kp.publicKey;
      pub.rsaPubDer = spkiToRsaPublicKey(new Uint8Array(await subtle.exportKey("spki", kp.publicKey)));
      rsaPkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
    }
    let cred;
    if (suiteName === "rsa3072") cred = rsaPkcs8;
    else if (suiteName !== "hybrid")
      cred = pkcs8(
        suiteName === "mlkem768" ? OID_MLKEM768 : OID_MLKEM1024,
        fmt === "seed" ? tlv(128, seed) : tlv(4, expanded)
      );
    else cred = pkcs8(OID_HYBRID, cat(fmt === "seed" ? seed : expanded, pkcs8PrivateKey(rsaPkcs8)));
    return { cred, pub };
  }
  async function loadCredential(suiteName, fmt, der) {
    const s = SUITES[suiteName], p = { ml: null, rsa: null };
    if (suiteName === "rsa3072") {
      p.rsa = await subtle.importKey("pkcs8", der, RSA_ALG, false, ["decrypt"]);
      return p;
    }
    const raw = pkcs8PrivateKey(der);
    if (suiteName !== "hybrid") {
      const c = readTLV(raw, 0), v = raw.subarray(c.start, c.end);
      p.ml = c.tag === 128 ? s.ml.keygen(v).secretKey : v.slice();
      return p;
    }
    const mlLen = fmt === "seed" ? 64 : 3168;
    const mlPart = raw.subarray(0, mlLen);
    p.ml = fmt === "seed" ? s.ml.keygen(mlPart).secretKey : mlPart.slice();
    p.rsa = await subtle.importKey("pkcs8", pkcs8(ALG_RSA, raw.subarray(mlLen)), RSA_ALG, false, ["decrypt"]);
    return p;
  }
  var combine = (ssMl, ssRsa, ctRsa, rsaPub) => sha3_256(cat(ssMl, ssRsa, ctRsa, rsaPub, HYBRID_LABEL));
  async function encap(suiteName, pub) {
    const s = SUITES[suiteName];
    let ctMl = new Uint8Array(0), ssMl = null;
    if (s.ml) {
      const r = s.ml.encapsulate(pub.ml);
      ctMl = r.cipherText;
      ssMl = r.sharedSecret;
      if (!s.rsa) return { ct: ctMl, ss: ssMl };
    }
    const ssRsa = rand(32);
    const ctRsa = new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, pub.rsa, ssRsa));
    if (!s.ml) return { ct: ctRsa, ss: ssRsa };
    return { ct: cat(ctMl, ctRsa), ss: combine(ssMl, ssRsa, ctRsa, pub.rsaPubDer) };
  }
  async function decap(suiteName, priv, ct, rsaPubDer) {
    const s = SUITES[suiteName];
    let ssMl = null, mlCt = 0;
    if (s.ml) {
      mlCt = s.mlCt;
      ssMl = s.ml.decapsulate(ct.subarray(0, mlCt), priv.ml);
      if (!s.rsa) return ssMl;
    }
    const ctRsa = ct.subarray(mlCt);
    const ssRsa = new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, priv.rsa, ctRsa));
    if (!s.ml) return ssRsa;
    return combine(ssMl, ssRsa, ctRsa, rsaPubDer);
  }
  async function kek(ss, suiteName, holder) {
    const info = cat(KDF_LABEL, Uint8Array.of(
      SUITES[suiteName].id,
      holder >>> 24,
      holder >>> 16 & 255,
      holder >>> 8 & 255,
      holder & 255
    ));
    const base = await subtle.importKey("raw", ss, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
      base,
      { name: "AES-KW", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }
  var kwKey = (bytes, extractable = true) => subtle.importKey("raw", bytes, "AES-KW", extractable, ["wrapKey", "unwrapKey"]);
  var wrap = async (wrappingKey, keyBytes) => new Uint8Array(await subtle.wrapKey("raw", await kwKey(keyBytes), wrappingKey, "AES-KW"));
  var unwrap = (wrappingKey, wrapped) => subtle.unwrapKey("raw", wrapped, wrappingKey, "AES-KW", "AES-KW", true, ["wrapKey", "unwrapKey"]);
  async function createAccount(suiteName, fmt, nf, holder) {
    const { cred, pub } = await genCredential(suiteName, fmt);
    const root = rand(32);
    const { ct, ss } = await encap(suiteName, pub);
    const pkg = cat(Uint8Array.of(1, SUITES[suiteName].id), ct, await wrap(await kek(ss, suiteName, holder), root));
    const rootKey = await kwKey(root);
    const children = [];
    for (let i = 0; i < nf; i++) children.push(await wrap(rootKey, rand(32)));
    return { suiteName, fmt, cred, pub, pkg, root, children };
  }
  async function openAccount(a, holder) {
    const p = await loadCredential(a.suiteName, a.fmt, a.cred);
    if (a.pkg[0] !== 1 || a.pkg[1] !== SUITES[a.suiteName].id) throw new Error("bad header");
    const ctLen = a.pkg.length - 42;
    const ss = await decap(a.suiteName, p, a.pkg.subarray(2, 2 + ctLen), a.pub.rsaPubDer);
    const rootKey = await unwrap(await kek(ss, a.suiteName, holder), a.pkg.subarray(2 + ctLen));
    for (const c of a.children) await unwrap(rootKey, c);
    return rootKey;
  }
  var b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  var eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  async function selftest(log) {
    let fails = 0;
    const check = (ok, msg) => {
      if (!ok) fails++;
      log(`  ${ok ? "ok:  " : "FAIL:"} ${msg}`);
    };
    const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
    const rfc = b64("MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");
    check(eq(pkcs8(OID_MLKEM1024, tlv(128, seed)), rfc), "seed-format PKCS#8 matches RFC 9935 C.1.3.1");
    const ex = (await loadCredential("mlkem1024", "seed", rfc)).ml;
    check(
      ex.length === 3168 && eq(ex.subarray(0, 4), Uint8Array.of(247, 123, 127, 107)),
      "expanded key from the RFC seed matches C.1.3.2 prefix"
    );
    try {
      const pm = await loadCredential("mlkem1024", "seed", b64(ML_DK_PKCS8));
      check(eq(await decap("mlkem1024", pm, b64(ML_C)), b64(ML_K)), "ML-KEM-1024 decapsulation matches composite-draft vector");
      const ph = await loadCredential("hybrid", "seed", b64(HYB_DK_PKCS8));
      check(
        eq(await decap("hybrid", ph, b64(HYB_C), b64(HYB_RSA_PUB)), b64(HYB_K)),
        "hybrid decapsulation and combiner match id-MLKEM1024-RSA3072-SHA3-256 vector"
      );
    } catch (e) {
      check(false, `composite-draft vectors: ${e}`);
    }
    for (const s of Object.keys(SUITES)) for (const f of ["seed", "expanded"]) {
      if (s === "rsa3072" && f === "expanded") continue;
      const tag = `${s.padEnd(9)} ${(s === "rsa3072" ? "na" : f).padEnd(8)}`;
      try {
        const a = await createAccount(s, f, 7, 1);
        const root = new Uint8Array(await subtle.exportKey("raw", await openAccount(a, 1)));
        check(eq(root, a.root), `${tag} open account round trip (package ${a.pkg.length} B, credential ${a.cred.length} B)`);
        let rejected = false;
        try {
          await openAccount(a, 2);
        } catch {
          rejected = true;
        }
        check(rejected, `${tag} wrong holder id is rejected`);
      } catch (e) {
        check(false, `${tag} ${e}`);
      }
    }
    log(fails ? `
SELFTEST FAILED (${fails} failures)` : "\nSELFTEST PASSED (0 failures)");
    return fails;
  }
  async function sizes() {
    const rows = ["suite,format,credential_pkcs8,public_raw,kem_ct,access_package"];
    for (const s of Object.keys(SUITES)) for (const f of ["seed", "expanded"]) {
      if (s === "rsa3072" && f === "expanded") continue;
      const a = await createAccount(s, f, 1, 1);
      const praw = (a.pub.ml ? a.pub.ml.length : 0) + a.pub.rsaPubDer.length;
      rows.push([s, s === "rsa3072" ? "na" : f, a.cred.length, praw, a.pkg.length - 42, a.pkg.length].join(","));
    }
    return rows.join("\n");
  }
  async function bench(suiteName, fmt, op, iters, warmup, nf) {
    const lf = fmt === "na" ? "seed" : fmt;
    const a = await createAccount(suiteName, lf, nf, 1);
    const ns = new Float64Array(iters);
    const ctLen = a.pkg.length - 42, ct = a.pkg.subarray(2, 2 + ctLen);
    const oldRoot = await kwKey(a.root), newRoot = await kwKey(rand(32));
    for (let phase = 0; phase < 2; phase++) {
      const n = phase === 0 ? warmup : iters;
      for (let i = 0; i < n; i++) {
        let t0, t1;
        if (op === "open") {
          t0 = performance.now();
          await openAccount(a, 1);
          t1 = performance.now();
        } else if (op === "load") {
          t0 = performance.now();
          await loadCredential(suiteName, lf, a.cred);
          t1 = performance.now();
        } else if (op === "encap") {
          t0 = performance.now();
          await encap(suiteName, a.pub);
          t1 = performance.now();
        } else if (op === "decap") {
          const p = await loadCredential(suiteName, lf, a.cred);
          t0 = performance.now();
          await decap(suiteName, p, ct, a.pub.rsaPubDer);
          t1 = performance.now();
        } else if (op === "rewrap") {
          t0 = performance.now();
          await subtle.wrapKey("raw", await unwrap(oldRoot, a.children[0]), newRoot, "AES-KW");
          t1 = performance.now();
        } else if (op === "keygen") {
          t0 = performance.now();
          await genCredential(suiteName, lf);
          t1 = performance.now();
        } else throw new Error(`unknown op ${op}`);
        if (phase === 1) ns[i] = Math.round((t1 - t0) * 1e6);
      }
    }
    return ns;
  }
  function timerResolutionUs() {
    let min = Infinity, last = performance.now();
    for (let i = 0; i < 2e5; i++) {
      const t = performance.now();
      if (t > last) {
        min = Math.min(min, t - last);
        last = t;
      }
    }
    return min * 1e3;
  }

  // src/main.js
  var $ = (id) => document.getElementById(id);
  var out = (s) => {
    $("out").textContent += s + "\n";
  };
  var params = new URLSearchParams(location.search);
  function guessLabel() {
    const ua = navigator.userAgent, mobile = /Android|Mobile/.test(ua);
    const br = /Firefox\//.test(ua) ? "firefox" : /Edg\//.test(ua) ? "edge" : /Chrome\//.test(ua) ? "chrome" : "browser";
    return `${br}-${mobile ? "android" : "desktop"}`;
  }
  var fullVersion = "na";
  async function initFullVersion() {
    try {
      const h = await Promise.race([
        navigator.userAgentData.getHighEntropyValues(["fullVersionList", "platformVersion"]),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 3e3))
      ]);
      fullVersion = h.fullVersionList.map((b) => `${b.brand} ${b.version}`).join("; ") + ` | platform ${h.platformVersion}`;
    } catch {
      fullVersion = "na";
    }
  }
  function envLines(res) {
    return [
      `user_agent=${navigator.userAgent}`,
      `browser_full_version=${fullVersion}`,
      `cross_origin_isolated=${globalThis.crossOriginIsolated}`,
      `timer_resolution_us=${res.toFixed(3)}`,
      `hardware_concurrency=${navigator.hardwareConcurrency}`,
      `noble_post_quantum=0.7.1 noble_hashes=2.4.0`
    ];
  }
  async function runPlanStep(planId, i) {
    const plan = await (await fetch(`/api/plan/${planId}`)).json();
    const run = plan.runs[i];
    $("status").textContent = `[${plan.op}] Run ${i + 1}/${plan.runs.length}: ${run.id}${run.id.startsWith("r00") ? " (warm-up block)" : ""}. Do not touch the device.`;
    if (i === 0) {
      $("status").textContent = `Session ${plan.op}: selftest...`;
      let log = "";
      const fails = await selftest((l) => {
        log += l + "\n";
      });
      const r = await (await fetch(`/api/selftest/${planId}`, { method: "POST", body: log })).json();
      if (fails || !r.ok) {
        $("status").textContent = `SELFTEST FAILED -- session ${plan.op} not run.`;
        return;
      }
      $("status").textContent = `Session ${plan.op}: starting in ${plan.start_delay_s} s. Do not touch the device.`;
      await new Promise((r2) => setTimeout(r2, plan.start_delay_s * 1e3));
    }
    window.__p15running = true;
    if (params.has("r")) {
      await fetch(`/api/event/${planId}`, {
        method: "POST",
        body: `watchdog reload ${params.get("r")} of run page i=${i} (${run.id}); run started normally`
      });
    }
    const res = timerResolutionUs();
    const ns = await bench(run.suite, run.format, plan.op, plan.iters, plan.warmup, plan.nf);
    const lines = [
      "# p15_web bench",
      ...envLines(res).map((l) => "# " + l),
      `# suite=${run.suite} format=${run.format} op=${plan.op} iters=${plan.iters} warmup=${plan.warmup} nf=${plan.nf}`,
      `# run_id=${run.id}`,
      "# time_source=performance.now",
      "run_id,suite,format,op,iter,ns"
    ];
    for (let k = 0; k < ns.length; k++) lines.push(`${run.id},${run.suite},${run.format},${plan.op},${k},${ns[k]}`);
    await fetch(`/api/result/${planId}/${run.id}`, { method: "POST", body: lines.join("\n") + "\n" });
    if (i + 1 >= plan.runs.length) {
      await fetch(`/api/done/${planId}`, { method: "POST" });
      if (plan.next) {
        $("status").textContent = `Session ${plan.op} finished; next session in ${plan.cooldown_s} s. Do not touch the device.`;
        setTimeout(() => location.replace(`?plan=${plan.next}&i=0`), plan.cooldown_s * 1e3);
        return;
      }
      $("status").textContent = `Finished: ${plan.runs.length} runs saved by the server in ${plan.dir}. ALL SESSIONS DONE.`;
      return;
    }
    let left = plan.cooldown_s;
    const tick = () => {
      $("status").textContent = `Run ${i + 1}/${plan.runs.length} saved. Next run in ${left} s. Do not touch the device.`;
      if (left-- <= 0) location.replace(`?plan=${planId}&i=${i + 1}`);
      else setTimeout(tick, 1e3);
    };
    tick();
  }
  async function startPilot() {
    $("out").textContent = "";
    $("status").textContent = "Selftest before the session...";
    let log = "";
    const fails = await selftest((l) => {
      log += l + "\n";
      out(l);
    });
    if (fails) {
      $("status").textContent = "SELFTEST FAILED -- session not started.";
      return;
    }
    const body = {
      selftest: log,
      label: $("label").value.trim(),
      kind: $("kind").value,
      op: $("op").value,
      reps: +$("reps").value,
      iters: +$("iters").value,
      cooldown_s: +$("cooldown").value,
      env: envLines(timerResolutionUs())
    };
    const r = await (await fetch("/api/plan", { method: "POST", body: JSON.stringify(body) })).json();
    if (r.error) {
      $("status").textContent = "NOT STARTED: " + r.error;
      return;
    }
    location.replace(`?plan=${r.id}&i=0`);
  }
  async function main() {
    if (params.has("plan")) $("setup").hidden = true;
    await initFullVersion();
    if (params.has("plan")) return runPlanStep(params.get("plan"), +params.get("i"));
    $("label").value = guessLabel();
    $("cooldown").value = /Android|Mobile/.test(navigator.userAgent) ? 20 : 2;
    const res = timerResolutionUs();
    envLines(res).forEach(out);
    if (!globalThis.crossOriginIsolated) out("WARNING: page is not cross-origin isolated; timer resolution is coarse. Open it through server.py.");
    $("selftest").onclick = async () => {
      $("out").textContent = "";
      envLines(res).forEach(out);
      out("");
      await selftest(out);
      out("\n" + await sizes());
    };
    $("start").onclick = startPilot;
  }
  main().catch((e) => {
    $("status").textContent = "ERROR: " + e;
    console.error(e);
  });
})();
/*! Bundled license information:

@noble/curves/utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/utils.js:
@noble/post-quantum/_crystals.js:
@noble/post-quantum/ml-kem.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)
*/
