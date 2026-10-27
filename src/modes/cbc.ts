import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { abytesAligned, xorBytes } from "../utils.js";
import type { BlockMode } from "../types.js";

/** Cipher Block Chaining (CBC) mode */
export const cbc = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): BlockMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key);
    abytes(iv, cipher.blockSize, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(plaintext, cipher.blockSize);
            let buf: TArg<Uint8Array> = new Uint8Array(iv);
            const output = new Uint8Array(plaintext.length);
            for(let i = 0; i < plaintext.length; i += cipher.blockSize) {
                const blk = cipher.encrypt(xorBytes(plaintext.subarray(i, i + cipher.blockSize), buf));
                output.set(blk, i);
                buf = blk;
            }

            return output;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(ciphertext, cipher.blockSize);
            let buf: TArg<Uint8Array> = new Uint8Array(iv);
            const output = new Uint8Array(ciphertext.length);
            for(let i = 0; i < ciphertext.length; i += cipher.blockSize) {
                const blk = ciphertext.subarray(i,i + cipher.blockSize);
                output.set(xorBytes(cipher.decrypt(blk), buf), i);
                buf = blk;
            }

            return output;
        }
    });
}