import { u32 } from "@noble/hashes/utils.js";
import { mulC, xorBytes } from "../utils.js";
import { Belt } from "../belt/index.js";
import { H } from "../belt/const.js";
import { ctr } from "./ctr.js";
import { abytes, concatBytes, copyBytes, abool, equalBytes, numberToBytesLE, type TArg, type TRet } from "@noble/curves/utils.js";
import type { AEADMode } from "../types.js";

const pad = (data: TArg<Uint8Array>): TRet<Uint8Array> => {
    const padded = new Uint8Array(16);
    padded.set(data);
    return padded;
}

const gf2mMul = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const temp = new Uint8Array(a), result = new Uint8Array(16);
    for (let i = 0; i < 128; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex = i % 8;
        if (byteIndex < b.length && (b[byteIndex] & (1 << bitIndex)))
            for (let j = 0; j < 16; j++) result[j] ^= temp[j];
      
        let carry = 0;
        for (let j = 0; j < 16; j++) {
            const nextCarry = (temp[j] & 0x80) ? 1 : 0;
            temp[j] = ((temp[j] << 1) & 0xFF) | carry;
            carry = nextCarry;
        }
      
        if (carry) temp[0] ^= 0x87;
    }
    
    return result;
}

const dwp_che = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>, isCHE: boolean): AEADMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key);
    abytes(iv, cipher.blockSize, "iv");
    abool(isCHE);
    const r = isCHE
        ? cipher.encrypt(iv)
        : cipher.encrypt(cipher.encrypt(iv));

    const ctr2 = (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
        const buf = cipher.encrypt(iv),
            buf32 = u32(buf),
            output = new Uint8Array(msg.length);
        for (let i = 0; i < msg.length; i += cipher.blockSize) {
            mulC(buf32);
            buf[0] ^= 1;
            const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
            output.set(ct, i);
        }

        return output;
    }

    // DWP - common CTR; CHE - modified CTR
    const crypt = isCHE ? ctr2 : ctr(key, iv).crypt;

    const calculateMac = (ciphertext: TArg<Uint8Array>, aad: TArg<Uint8Array>) => {
        const t = copyBytes(H.subarray(0, cipher.blockSize));
        const accumulateMac = (input: TArg<Uint8Array>) => {
            for (let i = 0; i < input.length; i += cipher.blockSize) {
                const blockLen = Math.min(cipher.blockSize, input.length - i);
                t.set(gf2mMul(
                    xorBytes(t, pad(input.subarray(i, i + blockLen))),
                    r
                ));
            }
        }
        accumulateMac(aad);
        accumulateMac(ciphertext);

        const lenBlock = concatBytes(
            numberToBytesLE(aad.length * 8, 8),
            numberToBytesLE(ciphertext.length * 8, 8)
        );
        
        return cipher.encrypt(
            gf2mMul(xorBytes(t, lenBlock), r)
        ).subarray(0, 8);
    }

    return Object.freeze({
        seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            aad ??= new Uint8Array();
            abytes(plaintext, undefined, "plaintext");
            abytes(aad, undefined, "aad");
            const ciphertext = crypt(plaintext),
                mac = calculateMac(ciphertext, aad);

            return concatBytes(ciphertext, mac);
        },
        open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            aad ??= new Uint8Array();
            abytes(ciphertext, undefined, "ciphertext");
            abytes(aad, undefined, "aad");
            const ct = ciphertext.subarray(0, -8),
                mac = calculateMac(ct, aad);
            if(!equalBytes(ciphertext.subarray(-8), mac)) throw new Error("Incorrect MAC");

            return crypt(ct);
        }
    });
}

/** Datawrap (DWP) mode (AEAD) */
export const dwp = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): AEADMode => dwp_che(key, iv, false);
/** Ctr-Hash-Encrypt (CHE) mode (AEAD) */
export const che = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>): AEADMode => dwp_che(key, iv, true);