import { beltHmac } from "../beltHash/index.js";
import { numberToBytesBE, type TArg } from "@noble/curves/utils.js";

export const botp = (secret: TArg<Uint8Array>, codeLength: number = 6) => {
    const hotp = (counter: TArg<Uint8Array>): string => {
        const digest = beltHmac(secret, counter);
        const offset = digest[digest.length - 1] & 0b1111;
        const code = (
            ((digest[offset] & 0b01111111) << 24) |
            ((digest[offset + 1]) << 16) |
            ((digest[offset + 2]) << 8) |
            digest[offset + 3]
        ).toString();

        return code.padStart(codeLength, '0').slice(-codeLength);
    }

    return Object.freeze({
        hotp,
        totp: (now: number = Date.now()): string => hotp(numberToBytesBE(Math.floor(now / 60), 8))
    });
}