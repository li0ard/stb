import { abytes, aexists, aoutput, createHasher, hexToBytes, u32, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { F } from "./bashf.js";

/** `Bash` hash function (STB 34.101.77) */
abstract class Bash<T extends Bash<T>> implements Hash<Bash<T>> {
    readonly blockLen: number;
    readonly outputLen: number;
    readonly canXOF = false;

    protected S: Uint8Array;
    protected S32: Uint32Array;
    protected pos = 0;
    protected finished = false;
    protected destroyed = false;

    constructor(l: number) {
        if (l <= 0 || l % 16 !== 0 || l > 256)
            throw new Error("Incorrect `l` parameter (0 < l <= 256, l % 16 === 0)");
        this.blockLen = 192 - l / 2;
        this.outputLen = l / 4;

        this.S = new Uint8Array(192);
        this.S32 = u32(this.S);
        this.S[184] = this.outputLen;
    }

    destroy() {
        this.destroyed = true;
        this.S.fill(0);
        this.pos = 0;
    }

    abstract _cloneInto(to?: T): T;

    protected _cloneIntoMeta(to: Bash<T>) {
        to.S.set(this.S);
        to.pos = this.pos;
        to.finished = this.finished;
        to.destroyed = this.destroyed;
    }
 
    clone(): T { return this._cloneInto(); }

    private processBlock() {
        F(this.S32);
    }

    update(buf: TArg<Uint8Array>): this {
        aexists(this);
        abytes(buf, undefined, "buf");
        let off = 0, len = buf.length;
        if (len < this.blockLen - this.pos) {
            this.S.set(buf, this.pos);
            this.pos += len;
            return this;
        }

        this.S.set(buf.subarray(0, this.blockLen - this.pos), this.pos);
        off = this.blockLen - this.pos;
        len -= off;
        this.processBlock();

        while (len >= this.blockLen) {
            this.S.set(buf.subarray(off, off + this.blockLen));
            off += this.blockLen;
            len -= this.blockLen;
            this.processBlock();
        }

        this.pos = len;
        if (len) this.S.set(buf.subarray(off, off + len));

        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aexists(this);
        aoutput(buf, this);
        this.finished = true;
        this.S.fill(0, this.pos, this.blockLen);
        this.S[this.pos] = 0x40;

        F(this.S32);
        buf.set(this.S.subarray(0, this.outputLen));
        this.destroy();
    }

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);

        return out;
    }
}

/** Internal `Bash-128` hash class */
export class _Bash128 extends Bash<_Bash128> {
    /** Internal `Bash-128` hash class */
    constructor() { super(128); }

    _cloneInto(to?: _Bash128): _Bash128 {
        to ||= new _Bash128();
        this._cloneIntoMeta(to);
        return to;
    }
}

/** Internal `Bash-192` hash class */
export class _Bash192 extends Bash<_Bash192> {
    /** Internal `Bash-128` hash class */
    constructor() { super(192); }

    _cloneInto(to?: _Bash192): _Bash192 {
        to ||= new _Bash192();
        this._cloneIntoMeta(to);
        return to;
    }
}

/** Internal `Bash-256` hash class */
export class _Bash256 extends Bash<_Bash256> {
    /** Internal `Bash-128` hash class */
    constructor() { super(256); }

    _cloneInto(to?: _Bash256): _Bash256 {
        to ||= new _Bash256();
        this._cloneIntoMeta(to);
        return to;
    }
}

/**
 * `Bash-128` hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { bash128 } from "@li0ard/gost/bash.js";
 * 
 * bash128(new Uint8Array([97, 98, 99]));
 * bash128.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const bash128 = createHasher(() => new _Bash128(), {
    oid: hexToBytes("06092A7000020022654D0B")
});

/**
 * `Bash-192` hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { bash192 } from "@li0ard/gost/bash.js";
 * 
 * bash192(new Uint8Array([97, 98, 99]));
 * bash192.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const bash192 = createHasher(() => new _Bash192(), {
    oid: hexToBytes("06092A7000020022654D0C")
});

/**
 * `Bash-256` hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { bash256 } from "@li0ard/gost/bash.js";
 * 
 * bash256(new Uint8Array([97, 98, 99]));
 * bash256.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const bash256 = createHasher(() => new _Bash256(), {
    oid: hexToBytes("06092A7000020022654D0D")
});

export * from "./prg.js";