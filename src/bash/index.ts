import { copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { bytesToUint64sBE, uint64sToBytesBE } from "../utils.js";
import { F } from "./bashf.js";

/** `Bash` hash function (STB 34.101.77) */
abstract class Bash<T extends Bash<T>> implements Hash<Bash<T>> {
    readonly blockLen: number;
    readonly outputLen: number;
    readonly canXOF = false;

    protected S: Uint8Array;
    protected pos = 0;

    constructor(l: number) {
        if (l <= 0 || l % 16 !== 0 || l > 256)
            throw new Error("Incorrect `l` parameter (0 < l <= 256, l % 16 === 0)");
        this.blockLen = 192 - l / 2;
        this.outputLen = l / 4;

        this.S = new Uint8Array(192);
        this.S[184] = this.outputLen;
    }

    destroy() {
        this.S.fill(0);
        this.pos = 0;
    }

    abstract _cloneInto(to?: T): T;
 
    clone(): T { return this._cloneInto(); }

    private processBlock() {
        const words = bytesToUint64sBE(this.S);
        F(words);
        this.S.set(uint64sToBytesBE(words));
    }

    update(buf: TArg<Uint8Array>): this {
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
        const s = copyBytes(this.S).fill(0, this.pos, this.blockLen);
        s[this.pos] = 0x40;

        const words = bytesToUint64sBE(s);
        F(words);
        buf.set(uint64sToBytesBE(words).subarray(0, this.outputLen));
        this.destroy();
    }

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);

        return out;
    }
}

/** `Bash-128` hash function */
export class Bash128 extends Bash<Bash128> {
    constructor() { super(128); }

    _cloneInto(to?: Bash128): Bash128 {
        to ||= new Bash128();
        to.S.set(this.S);
        to.pos = this.pos;

        return to;
    }

    static create(): Bash128 { return new Bash128(); }
}

/** `Bash-192` hash function */
export class Bash192 extends Bash<Bash192> {
    constructor() { super(192); }

    _cloneInto(to?: Bash192): Bash192 {
        to ||= new Bash192();
        to.S.set(this.S);
        to.pos = this.pos;

        return to;
    }

    static create(): Bash192 { return new Bash192(); }
}

/** `Bash-256` hash function */
export class Bash256 extends Bash<Bash256> {
    constructor() { super(256); }

    _cloneInto(to?: Bash256): Bash256 {
        to ||= new Bash256();
        to.S.set(this.S);
        to.pos = this.pos;

        return to;
    }

    static create(): Bash256 { return new Bash256(); }
}

/** `Bash-128` hash function */
export const bash128 = createHasher(Bash128.create);
/** `Bash-192` hash function */
export const bash192 = createHasher(Bash192.create);
/** `Bash-256` hash function */
export const bash256 = createHasher(Bash256.create);
export * from "./prg.js";