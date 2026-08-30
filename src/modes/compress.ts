import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { negBlock, xorBytes } from "../utils.js";
import { Belt } from "../belt/index.js";

export const compress = (msg: TArg<Uint8Array>): TRet<Uint8Array[]> => {
    if (msg.length !== 64)
        throw new Error("Input must be exactly 64 bytes (512 bits) long");

    const X1 = msg.subarray(0, 16),
        X2 = msg.subarray(16, 32),
        X3 = msg.subarray(32, 48),
        X4 = msg.subarray(48, 64);

    const temp = xorBytes(X3, X4);
    const S = xorBytes(new Belt(concatBytes(X1, X2)).encrypt(temp), temp);
    const Y1 = xorBytes(new Belt(concatBytes(S, X4)).encrypt(X1), X1);
    const Y2 = xorBytes(new Belt(concatBytes(negBlock(S), X3)).encrypt(X2), X2);

    return [S, concatBytes(Y1, Y2)];
}