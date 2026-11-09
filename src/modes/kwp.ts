import { abytes, concatBytes, equalBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { wbl } from "./wbl.js";
import type { WrapMode } from "../types.js";

/** Keywrap (KWP) mode */
export const kwp = (key: TArg<Uint8Array>, integrity: TArg<Uint8Array>): WrapMode => {
    abytes(key, undefined, "key");
    abytes(integrity, undefined, "integrity");
    const mode = wbl(key);

    return Object.freeze({
        wrap: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => 
            mode.encrypt(concatBytes(plaintext, integrity)),
        unwrap: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const decrypted = mode.decrypt(ciphertext);
            if(!equalBytes(integrity, decrypted.subarray(-integrity.length)))
                throw new Error("Integrity check failed");
            
            return decrypted.slice(0, -integrity.length);
        }
    });
}