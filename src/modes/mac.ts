import { abytes, anumber, concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Belt } from "../belt/index.js";
import { xorBytes } from "../utils.js";
import type { MACMode } from "../types.js";

const phi1 = (u: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    u.subarray(4,8),
    u.subarray(8,12),
    u.subarray(12,16),
    xorBytes(u.subarray(0,4), u.subarray(4,8))
);

const phi2 = (u: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    xorBytes(u.subarray(0,4), u.subarray(12,16)),
    u.subarray(0,4),
    u.subarray(4,8),
    u.subarray(8,12)
);

const psi = (u: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(16);
    result.set(u);
    result[u.length] = 0x80;

    return result;
}

/** Message Authentication Code (MAC) mode */
export const mac = (key: TArg<Uint8Array>, length: number = 8): MACMode => {
    abytes(key, undefined, "key");
    anumber(length, "length");
    if(length < 1 || length > 8)
        throw new Error("MAC length must be between 1 and 8 bytes (64 bits)");

    const cipher = new Belt(key);
    const r = cipher.encrypt(new Uint8Array(cipher.blockSize));

    return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            let s = new Uint8Array(cipher.blockSize);

            const fullBlocks = Math.floor(msg.length / cipher.blockSize);
            const hasPartialBlock = (msg.length % cipher.blockSize) > 0;

            for (let i = 0; i < fullBlocks; i++) {
                const block = msg.subarray(i * cipher.blockSize, (i + 1) * cipher.blockSize);
                if (i < fullBlocks - 1 || hasPartialBlock) s = cipher.encrypt(xorBytes(s, block));
            }

            if (hasPartialBlock) s = xorBytes(
                xorBytes(
                    s,
                    psi(msg.subarray(fullBlocks * cipher.blockSize))
                ),
                phi2(r)
            );
            else if (fullBlocks > 0) {
                const lastBlock = msg.subarray(
                    (fullBlocks - 1) * cipher.blockSize,
                    fullBlocks * cipher.blockSize
                );

                if (fullBlocks === 1) s = xorBytes(xorBytes(s, lastBlock), phi1(r));
                else s = xorBytes(xorBytes(s, lastBlock), phi1(r));
            }
            else s = xorBytes(xorBytes(s, psi(new Uint8Array())), phi2(r));

            return cipher.encrypt(s).slice(0, length);
        }
    });
}