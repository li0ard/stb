import { copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { numberToBytesLE } from "@noble/curves/utils.js";
import type { BlockMode } from "../types.js";

const xorInPlace = (
    dst: Uint8Array,
    dstOff: number,
    src: Uint8Array,
    srcOff: number = 0,
) => {
    for (let k = 0; k < 16; k++) dst[dstOff + k] ^= src[srcOff + k];
}

export const wbl = (key: TArg<Uint8Array>): BlockMode => {
    const cipher = new Belt(key);

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const buf = copyBytes(plaintext);
            const count = buf.length;
            if (count < 2 * cipher.blockSize)
                throw new Error(`Data length must be >= ${2 * cipher.blockSize} octets`);

            const block = new Uint8Array(cipher.blockSize);
            for (let round = 1; round <= 2 * Math.ceil(count / cipher.blockSize); round++) {
                block.set(buf.subarray(0, cipher.blockSize));
                for (let i = cipher.blockSize; i + cipher.blockSize < count; i += cipher.blockSize)
                    xorInPlace(block, 0, buf, i);

                buf.copyWithin(0, cipher.blockSize, count);
                buf.set(block, count - cipher.blockSize);

                const enc = cipher.encrypt(block);
                const roundBytes = numberToBytesLE(BigInt(round), cipher.blockSize);
                for (let k = 0; k < cipher.blockSize; k++) block[k] = enc[k] ^ roundBytes[k];

                xorInPlace(buf, count - 2 * cipher.blockSize, block);
            }

            return buf;
        },

        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const buf = copyBytes(ciphertext);
            const count = buf.length;
            if (count < 2 * cipher.blockSize)
                throw new Error(`Data length must be >= ${2 * cipher.blockSize} octets`);

            const block = new Uint8Array(cipher.blockSize);
            for (let round = 2 * Math.ceil(count / cipher.blockSize); round >= 1; round--) {
                block.set(buf.subarray(count - cipher.blockSize, count));
                buf.copyWithin(cipher.blockSize, 0, count - cipher.blockSize);
                buf.set(block);

                const enc = cipher.encrypt(block);
                const roundBytes = numberToBytesLE(BigInt(round), cipher.blockSize);
                for (let k = 0; k < cipher.blockSize; k++) block[k] = enc[k] ^ roundBytes[k];
                xorInPlace(buf, count - cipher.blockSize, block);

                for (let i = cipher.blockSize; i + cipher.blockSize < count; i += cipher.blockSize)
                    xorInPlace(buf, 0, buf, i);
            }

            return buf;
        }
    });
}