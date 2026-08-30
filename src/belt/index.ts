import { concatBytes, rotl, u32, u8, type TArg, type TRet } from "@noble/hashes/utils.js";
import { H, keyIndex } from "./const.js";
import { compress } from "../modes/compress.js";
import type { Cipher } from "../types.js";

const G = (x: number, r: number): number => rotl(
    (H[x & 0xff]) | (H[(x >>> 8) & 0xff] << 8) |
    (H[(x >>> 16) & 0xff] << 16) | (H[x >>> 24] << 24),
    r
);

export const keyExpand = (key: TArg<Uint8Array>): TRet<Uint8Array> => {
    if(key.length < 16 || key.length > 32) throw new Error("Invalid key length");
    const ks = new Uint8Array(32);
    ks.set(key);
    if(key.length == 16) ks.set(key, 16);
    else if(key.length == 24) {
        for (let i = 0; i < 4; i++) ks[24 + i] = key[i] ^ key[i + 4] ^ key[i + 8];
        for (let i = 0; i < 4; i++) ks[28 + i] = key[i + 12] ^ key[i + 16] ^ key[i + 20];
    }
    
    return ks;
}

export const keyTransform = (
    key: TArg<Uint8Array>,
    level: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    outputLen: number
): TRet<Uint8Array> => {
    if (outputLen > key.length ||
        ![16, 24, 32].includes(outputLen) ||
        ![16, 24, 32].includes(key.length)
    ) throw new Error("Invalid key lengths: m must be <= n and both must be 16, 24, or 32");
    if (level.length !== 12) throw new Error("Level must be 12 bytes");
    if (iv.length !== 16) throw new Error("IV must be 16 bytes");
    const offset = 4 * (key.length - 16) + 2 * (outputLen - 16);

    return compress(concatBytes(
        H.subarray(offset, offset+4),
        level,
        iv,
        keyExpand(key)
    ))[1].slice(0, outputLen);
}

/** BelT (STB 34.101.31) cipher */
export class Belt implements Cipher {
    readonly blockSize = 16;
    private ks: Uint32Array;

    /**
     * BelT (STB 34.101.31) cipher
     * @param key Encryption key
     */
    constructor(key: TArg<Uint8Array>) { this.ks = u32(keyExpand(key)); }

    encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        const inBlock = u32(block);
        let a = inBlock[0],
            b = inBlock[1],
            c = inBlock[2],
            d = inBlock[3];
        for(let i = 0; i < 8; i++) {
            b ^= G(a + this.ks[keyIndex[i][0]], 5);
            c ^= G(d + this.ks[keyIndex[i][1]], 21);
            a = (a - G(b + this.ks[keyIndex[i][2]], 13)) >>> 0;
            const e = (G(b + c + this.ks[keyIndex[i][3]], 21) ^ (i + 1)) >>> 0;
            b += e;
            c = (c - e);
            d += G(c + this.ks[keyIndex[i][4]], 13);
            b ^= G(a + this.ks[keyIndex[i][5]], 21);
            c ^= G(d + this.ks[keyIndex[i][6]], 5);

            let tmp = a;
            a = b;
            b = tmp;
            tmp = c;
            c = d;
            d = tmp;
            tmp = b;
            b = c;
            c = tmp;
        }

        return u8(new Uint32Array([b, d, a, c]));
    }

    decrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        const inBlock = u32(block);
        let a = inBlock[0],
            b = inBlock[1],
            c = inBlock[2],
            d = inBlock[3];
        for(let i = 7; i >= 0; i--) {
            b ^= G(a + this.ks[keyIndex[i][6]], 5);
            c ^= G(d + this.ks[keyIndex[i][5]], 21);
            a = (a - G(b + this.ks[keyIndex[i][4]], 13)) >>> 0;
            const e = (G(b + c + this.ks[keyIndex[i][3]], 21) ^ (i + 1)) >>> 0;
            b += e;
            c = (c - e);
            d += G(c + this.ks[keyIndex[i][2]], 13);
            b ^= G(a + this.ks[keyIndex[i][1]], 21);
            c ^= G(d + this.ks[keyIndex[i][0]], 5);

            let tmp = a;
            a = b;
            b = tmp;
            tmp = c;
            c = d;
            d = tmp;
            tmp = a;
            a = d;
            d = tmp;
        }

        return u8(new Uint32Array([c, a, d, b]));
    }
}