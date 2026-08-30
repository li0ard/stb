import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { wbl } from "./wbl.js";
import { equalBytes } from "@noble/curves/utils.js";
import type { WrapMode } from "../types.js";

export const kwp = (key: TArg<Uint8Array>, integrity: TArg<Uint8Array>): WrapMode => {
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