import type { WeierstrassPointCons } from "@noble/curves/abstract/weierstrass.js";
import type { TArg, TRet } from "@noble/hashes/utils.js";

/** Cipher or hash function wrapper */
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

/** ECDSA signer */
export type ECDSA = {
    /** Point constructor */
    Point: WeierstrassPointCons<bigint>;
    /**
     * Computes public key for a secret key
     * @param isCompressed - Whether to return compact (default), or full key
     * @returns Public key, full when `isCompressed=false`; short when `isCompressed=true`
     */
    getPublicKey: (secretKey: TArg<Uint8Array>, isCompressed?: boolean) =>TRet<Uint8Array>;
    /** 
     * Signs a message hash with a secret key.
     * @param secretKey - Secret key bytes.
     * @param digest - Digest bytes.
     * @param oid - OID of hash algorithm (default - BelT hash)
     * @param rand - Optional parameter for ephemeral key.
     * @returns Encoded signature bytes.
     */
    sign:(secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, oid?: TArg<Uint8Array>, rand?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /**
     * Verifies a signature against message hash and public key.
     * @param publicKey - Public key
     * @param digest - Digest bytes
     * @param signature - Encoded signature bytes.
     * @param oid - OID of hash algorithm (default - BelT hash)
     * @returns Whether the signature is valid.
     */
    verify: (publicKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, signature: TArg<Uint8Array>, oid?: TArg<Uint8Array>) => boolean;
    /**
     * Wraps a secret key with a transport public key.
     * @param publicKey - Transport public key.
     * @param key - Secret key bytes.
     * @param header - Additional key header.
     * @param rand - Optional parameter for ephemeral key
     * @returns Wrapped secret key
     */
    wrapKey: (publicKey: TArg<Uint8Array>, key: TArg<Uint8Array>, header: TArg<Uint8Array>, rand?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /**
     * Unwraps a secret key with a transport secret key 
     * @param privateKey - Transport secret key.
     * @param wrappedKey - Wrapped secret key.
     * @param header - Optional parameter for ephemeral key
     * @returns Unrapped secret key
     */
    unwrapKey: (privateKey: TArg<Uint8Array>, wrappedKey: TArg<Uint8Array>, header: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Result of BMQV protocol */
export type BakeResult = {
    /** Shared key */
    K: TRet<Uint8Array>;
    /** Integrity tag for side A */
    Ta: TRet<Uint8Array>;
    /** Integrity tag for side B */
    Tb: TRet<Uint8Array>;
}

/** ECKE (Elliptic curve key exchange) runner */
export type ECKE = {
    /**
     * Run key exchange as side A
     * @param secretKeyA Secret key of side A
     * @param publicKeyB Public key of side B
     * @param eSecretA Ephemeral secret key of side A
     * @param ePublicB Ephemeral public key of side B
     * @param idA Identifier of side A (optional)
     * @param idB Identifier of side B (optional)
     */
    runA: (
        secretKeyA: TArg<Uint8Array>,
        publicKeyB: TArg<Uint8Array>,
        eSecretA: TArg<Uint8Array>,
        ePublicB: TArg<Uint8Array>,
        idA?: TArg<Uint8Array>,
        idB?: TArg<Uint8Array>,
    ) => BakeResult;
    /**
     * Run key exchange as side B
     * @param secretKeyB Secret key of side B
     * @param publicKeyA Public key of side A
     * @param eSecretB Ephemeral secret key of side B
     * @param ePublicA Ephemeral public key of side A
     * @param idA Identifier of side A (optional)
     * @param idB Identifier of side B (optional)
     */
    runB: (
        secretKeyB: TArg<Uint8Array>,
        publicKeyA: TArg<Uint8Array>,
        eSecretB: TArg<Uint8Array>,
        ePublicA: TArg<Uint8Array>,
        idA?: TArg<Uint8Array>,
        idB?: TArg<Uint8Array>
    ) => BakeResult;
}

export type RNGFunction = (n: number) => TRet<Uint8Array>;
export type OTPGenerator = {
    hotp: (counter: TArg<Uint8Array>) => string;
    totp: (now: number) => string;
}