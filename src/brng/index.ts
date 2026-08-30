import { concatBytes, copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { negBlock, xorBytes } from "../utils.js";
import { beltHash, beltHmac } from "../beltHash/index.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";

const EMPTY = new Uint8Array(beltHash.outputLen);

export const brngCtr = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>) => {
    const s = copyBytes(iv), r = negBlock(s);

    return (n: number, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
        if(aad && aad.length < beltHash.outputLen * n)
            throw new Error("Invalid additional vectors length");
        const output = new Uint8Array(beltHash.outputLen * n);
        for(let i = 0; i < n; i++) {
            const offset = beltHash.outputLen * i;
            const Yi = beltHash(concatBytes(
                key, s,
                aad ? aad.subarray(offset, offset + beltHash.outputLen) : EMPTY,
                r
            ));

            s.set(numberToBytesLE(bytesToNumberLE(s) + 1n, beltHash.outputLen));
            r.set(xorBytes(r, Yi));

            output.set(Yi, offset);
        }

        return output;
    }
}

export const brngHmac = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>) => {
    const r = beltHmac(key, iv);

    return (n: number): TRet<Uint8Array> => {
        const output = new Uint8Array(beltHash.outputLen * n);
        for(let i = 0; i < n; i++) {
            const Yi = beltHmac(key, concatBytes(r, iv));
            r.set(beltHmac(key, r));

            output.set(Yi, beltHash.outputLen * i);
        }

        return output;
    }
}

export * from "./otp.js";