import { abytes, copyBytes, u32, type TArg, type TRet } from "@noble/hashes/utils.js";
import { mulC, xorBytes } from "../utils.js";
import { Belt } from "../belt/index.js";
import { wbl } from "./wbl.js";
import type { DiskMode } from "../types.js";

export const bde = (key: TArg<Uint8Array>): DiskMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key),
        encrypter = cipher.encrypt.bind(cipher),
        decrypter = cipher.decrypt.bind(cipher);

    const core = (
        crypter: (msg: TArg<Uint8Array>) => TRet<Uint8Array>,
        msg: TArg<Uint8Array>,
        iv: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        abytes(msg, undefined, "msg");
        abytes(iv, cipher.blockSize, "iv");
        const s = cipher.encrypt(iv),
            s32 = u32(s),
            output = new Uint8Array(msg.length);
        for(let i = 0; i < msg.length; i += cipher.blockSize) {
            mulC(s32);
            const ct = crypter(xorBytes(
                msg.subarray(i, i + cipher.blockSize),
                s
            ));
            output.set(xorBytes(ct, s), i);
        }

        return output;
    }

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(encrypter, plaintext, iv),
        decrypt: (ciphertext: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(decrypter, ciphertext, iv)
    });
}

export const sde = (key: TArg<Uint8Array>): DiskMode => {
    abytes(key, undefined, "key");
    const cipher = new Belt(key),
        mode = wbl(key),
        encrypter = mode.encrypt.bind(mode),
        decrypter = mode.decrypt.bind(mode);

    const core = (
        crypter: (msg: TArg<Uint8Array>) => TRet<Uint8Array>,
        msg: TArg<Uint8Array>,
        iv: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        abytes(msg, undefined, "msg");
        abytes(iv, cipher.blockSize, "iv");
        const s = cipher.encrypt(iv),
            result = copyBytes(msg);
        result.set(xorBytes(result, s));
    
        const encrypted = crypter(result);
        encrypted.set(xorBytes(encrypted, s));

        return encrypted;
    } 

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(encrypter, plaintext, iv),
        decrypt: (ciphertext: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(decrypter, ciphertext, iv)
    });
}