import { _HMAC } from "@noble/hashes/hmac.js";
import type { TArg, TRet } from "@noble/hashes/utils.js";
import { beltHash } from "./beltHash/index.js";
import { bash128, bash192, bash256 } from "./bash/index.js";

/** HMAC over BelT hash function */
export class BeltHMAC extends _HMAC<BeltHMAC> {
    constructor(key: TArg<Uint8Array>) { super(beltHash, key); }
}

/** HMAC over Bash-128 hash function */
export class Bash128HMAC extends _HMAC<Bash128HMAC> {
    constructor(key: TArg<Uint8Array>) { super(bash128, key); }
}

/** HMAC over Bash-192 hash function */
export class Bash192HMAC extends _HMAC<Bash192HMAC> {
    constructor(key: TArg<Uint8Array>) { super(bash192, key); }
}

/** HMAC over Bash-256 hash function */
export class Bash256HMAC extends _HMAC<Bash256HMAC> {
    constructor(key: TArg<Uint8Array>) { super(bash256, key); }
}

/** HMAC over BelT hash function */
export const beltHmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new BeltHMAC(key).update(msg).digest();

/** HMAC over Bash-128 hash function */
export const bash128Hmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Bash128HMAC(key).update(msg).digest();

/** HMAC over Bash-192 hash function */
export const bash192Hmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Bash192HMAC(key).update(msg).digest();

/** HMAC over Bash-256 hash function */
export const bash256Hmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Bash256HMAC(key).update(msg).digest();