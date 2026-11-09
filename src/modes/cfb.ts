import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { abytesAligned, splitBlocks, xorBytesInPlace } from "../utils.js";
import type { BlockMode } from "../types.js";

/** Cipher Feedback (CFB) mode */
export const cfb = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): BlockMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key), bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext, undefined, "plaintext");
            const r = splitBlocks(iv, bs), out = new Uint8Array(plaintext.length);
            let h = 0;
            for (let i = 0; i < plaintext.length; i += bs) {
                const ct = out.subarray(i, i + bs);
                ct.set(plaintext.subarray(i, i + bs));
                xorBytesInPlace(ct, cipher.encrypt(r[h]));
                r[h] = ct;
                h = (h + 1) % r.length;
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext, undefined, "ciphertext");
            const r = splitBlocks(iv, bs), out = new Uint8Array(ciphertext.length);
            let h = 0;
            for (let i = 0; i < ciphertext.length; i += bs) {
                const ct = ciphertext.subarray(i, i + bs),
                    block = out.subarray(i, i + bs);
                block.set(ct);
                xorBytesInPlace(block, cipher.encrypt(r[h]));
                r[h] = ct as TRet<Uint8Array>;
                h = (h + 1) % r.length;
            }

            return out;
        }
    });
}