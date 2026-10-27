import { abytes, aoutput, concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { H } from "../belt/const.js";
import { compress } from "../modes/compress.js";
import { xorBytesInPlace } from "../utils.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

/** Internal BelT hash class */
export class _BeltHash implements Hash<_BeltHash> {
    readonly blockLen = 32;
    readonly outputLen = 32;
    readonly canXOF = false;

    private h!: Uint8Array;
    private s!: Uint8Array;
    private buffer!: Uint8Array;
    private pos!: number;
    private length!: bigint;

    /** Internal BelT hash class */
    constructor() { this.destroy(); }

    destroy() {
        this.h = H.slice(0, 32);
        this.s = new Uint8Array(16);
        this.buffer = new Uint8Array(this.blockLen);
        this.pos = 0;
        this.length = 0n;
    }

    private processBlock(block: TArg<Uint8Array>) {
        const [t, h] = compress(concatBytes(block, this.h));
        xorBytesInPlace(this.s, t);
        this.h.set(h);
    }

    update(buf: TArg<Uint8Array>): this {
        abytes(buf, undefined, "buf");
        let data: Uint8Array = copyBytes(buf);
        this.length += BigInt(data.length);

        while (data.length) {
            const take = Math.min(this.blockLen - this.pos, data.length);
            this.buffer.set(data.subarray(0, take), this.pos);
            this.pos += take;
            data = data.subarray(take);

            if (this.pos === this.blockLen) {
                this.processBlock(this.buffer);
                this.pos = 0;
            }
        }
        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        if (this.pos > 0) {
            this.buffer.fill(0, this.pos);
            this.processBlock(this.buffer);
            this.pos = 0;
        }

        const r = numberToBytesLE(this.length * 8n, 16);
        const [, y] = compress(concatBytes(r, this.s, this.h));
        buf.set(y.subarray(0, this.outputLen));
        this.destroy();
    }

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);
        
        return out;
    }

    _cloneInto(to?: _BeltHash): _BeltHash {
        to ||= new _BeltHash();
        to.h.set(this.h);
        to.s.set(this.s);
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.length = this.length;

        return to;
    }

    clone(): _BeltHash { return this._cloneInto(); }

    /** Create hash instance */
    static create() { return new _BeltHash(); }
}

/** BelT hash function */
export const beltHash = createHasher(_BeltHash.create);