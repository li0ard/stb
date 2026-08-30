import type { TArg, TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { xorBytes } from "../utils.js";
import type { StreamMode } from "../types.js";

const incrementCounterAt = (ctr: Uint8Array, pos: number) => {
    let j = pos;
    while (j < ctr.length) if (++ctr[j++] != 0) break;
}

export const ctr = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): StreamMode => {
    const cipher = new Belt(key);
    if (iv.length !== cipher.blockSize)
        throw new Error("Invalid IV size");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const buf = cipher.encrypt(iv);
            const output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounterAt(buf, 0);
                const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
                output.set(ct, i);
            }

            return output;
        }
    });
}