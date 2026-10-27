import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { abytesAligned, xorBytes } from "../utils.js";
import type { BlockMode } from "../types.js";

/** Cipher Feedback (CFB) mode */
export const cfb = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): BlockMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key), bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext, undefined, "plaintext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(plaintext.length);
            for (let n = 0; n < Math.ceil(plaintext.length / bs); n++) {
                const i = n * bs;
                const ct = xorBytes(plaintext.subarray(i, i + bs), cipher.encrypt(r[0]));
                out.set(ct, i);
                r.shift();
                r.push(ct);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext, undefined, "ciphertext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(ciphertext.length);
            for (let n = 0; n < Math.ceil(ciphertext.length / bs); n++) {
                const i = n * bs;
                const ct = ciphertext.subarray(i, i + bs);
                out.set(xorBytes(ct, cipher.encrypt(r[0])), i);
                r.shift();
                r.push(ct);
            }

            return out;
        }
    });
}