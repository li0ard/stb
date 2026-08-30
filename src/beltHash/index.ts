import { concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { H } from "../belt/const.js";
import { compress } from "../modes/compress.js";
import { xorBytes } from "../utils.js";
import { numberToBytesLE } from "@noble/curves/utils.js";
import { _HMAC } from "@noble/hashes/hmac.js";

export class BeltHash implements Hash<BeltHash> {
    readonly blockLen = 32;
    readonly outputLen = 32;
    readonly canXOF = false;

    private h!: Uint8Array;
    private s!: Uint8Array;
    private buffer!: Uint8Array;
    private pos!: number;
    private length!: bigint;

    constructor() { this.destroy(); }

    destroy() {
        this.h = H.slice(0, 32);
        this.s = new Uint8Array(16);
        this.buffer = new Uint8Array(this.blockLen);
        this.pos = 0;
        this.length = 0n;
    }

    private processBlock(block: Uint8Array): void {
        const [t, h] = compress(concatBytes(block, this.h));
        this.s.set(xorBytes(this.s, t));
        this.h.set(h);
    }

    update(buf: TArg<Uint8Array>): this {
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

    digestInto(buf: TArg<Uint8Array>): void {
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

    _cloneInto(to?: BeltHash): BeltHash {
        to ||= new BeltHash();
        to.h.set(this.h);
        to.s.set(this.s);
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.length = this.length;

        return to;
    }

    clone(): BeltHash { return this._cloneInto(); }

    static create() { return new BeltHash(); }
}

export const beltHash = createHasher(BeltHash.create);

export class BeltHMAC extends _HMAC<Hash<BeltHash>> {
    constructor(key: TArg<Uint8Array>) { super(beltHash, key); }
}

export const beltHmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new BeltHMAC(key).update(msg).digest();