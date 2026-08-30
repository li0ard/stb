import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { getPadLength, xorBytes } from "../utils.js";
import type { BlockMode } from "../types.js";

export const cfb = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): BlockMode => {
    const cipher = new Belt(key);
    if (iv.length == 0 || iv.length % cipher.blockSize !== 0)
        throw new Error("Invalid IV size");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < (plaintext.length + getPadLength(plaintext.length, cipher.blockSize)); i += cipher.blockSize) {
                result.push(xorBytes(cipher.encrypt(r[0]), plaintext.subarray(i, i + cipher.blockSize)));
                r = r.slice(1).concat(result[result.length - 1]);
            }

            return concatBytes(...result);
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < (ciphertext.length + getPadLength(ciphertext.length, cipher.blockSize)); i += cipher.blockSize) {
                const blk = ciphertext.slice(i, i + cipher.blockSize);
                result.push(xorBytes(cipher.encrypt(r[0]), blk));
                r = r.slice(1).concat(blk);
            }

            return concatBytes(...result);
        }
    });
}