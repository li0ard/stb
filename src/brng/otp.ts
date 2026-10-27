import { numberToBytesBE, type TArg, abytes, anumber } from "@noble/curves/utils.js";
import { beltHmac } from "../hmac.js";
import type { OTPGenerator } from "../types.js";

/** Initialize OTP generator with BelT-HMAC */
export const botp = (secret: TArg<Uint8Array>, codeLength: number = 6): OTPGenerator => {
    abytes(secret, undefined, "secret");
    anumber(codeLength, "codeLength");
    const hotp = (counter: TArg<Uint8Array>): string => {
        abytes(counter, undefined, "counter");
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
        totp: (now: number): string => hotp(numberToBytesBE(Math.floor(anumber(now, "now") / 60), 8))
    });
}