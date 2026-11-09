import { hmac } from "@noble/hashes/hmac.js";
import type { CHash, Hash, TArg } from "@noble/hashes/utils.js";
import { beltHash } from "./beltHash/index.js";
import { bash128, bash192, bash256 } from "./bash/index.js";
import type { CHmac } from "./types.js";


const createHmac = <T extends Hash<T>>(hash: CHash<T>): CHmac<T> => {
    const hmacC = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>) =>
        hmac(hash, key, msg);
    hmacC.outputLen = hash.outputLen;
    hmacC.blockLen = hash.blockLen;
    hmacC.canXOF = false;
    hmacC.create = (key: TArg<Uint8Array>) => hmac.create(hash, key);

    return Object.freeze(hmacC);
}

/** HMAC over BelT hash function */
export const beltHmac = createHmac(beltHash);

/** HMAC over Bash-128 hash function */
export const bash128Hmac = createHmac(bash128);

/** HMAC over Bash-192 hash function */
export const bash192Hmac = createHmac(bash192);

/** HMAC over Bash-256 hash function */
export const bash256Hmac = createHmac(bash256);