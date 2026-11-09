import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { xorBytes } from "../utils.js";
import type { StreamMode } from "../types.js";

const incrementCounterAt = (ctr: Uint8Array, pos: number) => {
    let j = pos;
    while (j < ctr.length) if (++ctr[j++] != 0) break;
}

/** Counter (CTR) mode */
export const ctr = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): StreamMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key);
    abytes(iv, cipher.blockSize, "iv");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const buf = cipher.encrypt(iv),
                output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounterAt(buf, 0);
                const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
                output.set(ct, i);
            }

            return output;
        }
    });
}