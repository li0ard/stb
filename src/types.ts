import type { TArg, TRet } from "@noble/hashes/utils.js";

export type CipherOrHashFunctionWrapper = (msg: TArg<Uint8Array>) => TRet<Uint8Array>;

/** Cipher core */
export type Cipher = {
    /** Block size */
    readonly blockSize: number;
    /** Encrypt block */
    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array>;
    /** Decrypt block */
    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array>;
}

/** Block mode for {@link Cipher} */
export type BlockMode = {
    /** Encrypt plaintext */
    encrypt: (plaintext: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Decrypt ciphertext */
    decrypt: (ciphertext: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Stream-like mode for {@link Cipher} */
export type StreamMode = {
    /** Proceed message */
    crypt: CipherOrHashFunctionWrapper;
}

/** MAC mode for {@link Cipher} */
export type MACMode = {
    /** Compute MAC */
    compute: CipherOrHashFunctionWrapper;
}

/** AEAD mode for {@link Cipher} */
export type AEADMode = {
    /** Seal plaintext and AAD */
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Open ciphertext and AAD */
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Key wrapping mode for {@link Cipher} */
export type WrapMode = {
    /** Wrap encryption key */
    wrap: (key: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Unwrap encryption key */
    unwrap: (wrapped: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Disk encryption mode for {@link Cipher} */
export type DiskMode = {
    /** Encrypt plaintext */
    encrypt: (plaintext: TArg<Uint8Array>, iv: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Decrypt ciphertext */
    decrypt: (ciphertext: TArg<Uint8Array>, iv: TArg<Uint8Array>) => TRet<Uint8Array>;
}
