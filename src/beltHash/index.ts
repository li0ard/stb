import { HashMD } from "@noble/hashes/_md.js";
import { aexists, aoutput, concatBytes, createHasher, createView, hexToBytes, type TArg } from "@noble/hashes/utils.js";
import { H } from "../belt/const.js";
import { compress } from "../modes/compress.js";
import { xorBytesInPlace } from "../utils.js";

/** Internal BelT hash class */
export class _BeltHash extends HashMD<_BeltHash> {
    private h: Uint8Array = H.slice(0, 32);
    private s: Uint8Array = new Uint8Array(16);

    constructor() {
        super(32, 32, 16, true);
    }

    protected process(view: DataView, offset: number = 0) {
        const block = new Uint8Array(view.buffer, view.byteOffset + offset, this.blockLen);
        const [t, h] = compress(concatBytes(block, this.h));
        xorBytesInPlace(this.s, t);
        this.h.set(h);
    }

    override digestInto(out: TArg<Uint8Array>) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;

        if (this.pos > 0) {
            this.buffer.fill(0, this.pos);
            this.process(this.view);
            this.pos = 0;
        }

        const r = new Uint8Array(16);
        createView(r).setBigUint64(0, BigInt(this.length) * 8n, true);

        const [, y] = compress(concatBytes(r, this.s, this.h));
        out.set(y.subarray(0, this.outputLen));
    }

    // Unused
    protected get(): number[] { return []; }
    protected set(...words: number[]) {}
    protected roundClean() {}

    destroy() {
        this.destroyed = true;
        this.h.fill(0);
        this.s.fill(0);
        this.buffer.fill(0);
        this.pos = 0;
        this.length = 0;
    }

    _cloneInto(to?: _BeltHash): _BeltHash {
        to ||= new _BeltHash();
        this._cloneIntoMeta(to);
        to.h.set(this.h);
        to.s.set(this.s);
        return to;
    }
}

/**
 * BelT hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { beltHash } from "@li0ard/gost/belthash.js";
 * 
 * beltHash(new Uint8Array([97, 98, 99]));
 * beltHash.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const beltHash = createHasher(() => new _BeltHash(), {
    oid: hexToBytes("06092A7000020022651F51")
});

