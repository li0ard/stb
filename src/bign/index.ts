import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { BELTOID, BIGN128, BIGN192, BIGN256, type BignCurveParameters } from "./const.js";
import { randomBytes, bytesToNumberBE, bytesToNumberLE, concatBytes, equalBytes, numberToBytesBE, numberToBytesLE, type TArg, type TRet, copyBytes, abytes } from "@noble/curves/utils.js";
import { beltHash } from "../beltHash/index.js";
import { wbl, kwp } from "../modes/index.js";
import { Field } from "@noble/curves/abstract/modular.js";
import type { ECDSA } from "../types.js";

/** Creates Bign (STB 34.101.45) signing interface */
export const bign = (parameters: BignCurveParameters): ECDSA => {
    const Fp = Field(parameters.p, { isLE: true }),
        Fn = Field(parameters.n, { isLE: true }),
        Point = weierstrass(parameters, { Fp, Fn }),
        { BASE } = Point;
    const { n, a, b } = parameters,
        l = Fn.BYTES / 2,
        _2l = 1n << BigInt(Fn.BYTES * 4);

    /**
     * Computes public key for a secret key. Checks for validity of the secret key.
     * @param isCompressed - whether to return compact (default), or full key
     * @returns Public key, full when `isCompressed=false`; short when `isCompressed=true`
     */
    const getPublicKey = (
        secretKey: TArg<Uint8Array>, 
        isCompressed: boolean = true
    ): TRet<Uint8Array> => BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);

    const drbg = (
        secretKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        oid: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const theta = beltHash.create().update(oid).update(secretKey).digest();
        let kBytes = copyBytes(digest);

        const mode = wbl(theta);
        while (true) {
            kBytes = mode.encrypt(kBytes);
            const k = bytesToNumberBE(kBytes);
            if (k > 0n && k < n)
                return numberToBytesBE(k, Fn.BYTES);
        }
    }

    /** Signs a message hash with a secret key */
    const sign = (
        secretKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        oid?: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        oid ??= BELTOID;
        abytes(secretKey, undefined, "secretKey");
        abytes(digest, undefined, "digest");
        abytes(oid, undefined, "oid");
        const k = bytesToNumberLE(rand ?? drbg(secretKey, digest, oid));
        const R = BASE.multiply(k);

        const S0 = beltHash.create()
            .update(oid)
            .update(Fp.toBytes(R.x))
            .update(digest)
            .digest().subarray(0, l);

        const S1 = Fn.toBytes(
            Fn.sub(
                Fn.sub(k, bytesToNumberLE(digest)),
                Fn.mul(
                    Fn.fromBytes(secretKey),
                    Fn.add(bytesToNumberLE(S0), _2l)
                )
            )
        );

        return concatBytes(S0, S1);
    }

    /** Verifies a signature against message hash and public key */
    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>,
        oid?: TArg<Uint8Array>
    ): boolean => {
        oid ??= BELTOID;
        abytes(publicKey, undefined, "publicKey");
        abytes(digest, undefined, "digest");
        abytes(signature, undefined, "signature");
        abytes(oid, undefined, "oid");
        if (signature.length != 3 * l) return false;

        const S0 = signature.subarray(0, l),
            S1 = bytesToNumberLE(signature.subarray(l));
        if(S1 >= Fn.ORDER) return false;

        const R = BASE.mulAddUnsafe(
            Fn.add(S1, bytesToNumberLE(digest)),
            Point.fromBytes(publicKey),
            Fn.add(bytesToNumberLE(S0), _2l)
        );
        if(R.is0()) return false;

        const t = beltHash.create()
            .update(oid)
            .update(Fp.toBytes(R.x))
            .update(digest)
            .digest().subarray(0, l);

        return equalBytes(S0, t);
    }

    /** Wrap encryption key */
    const wrapKey = (
        publicKey: TArg<Uint8Array>,
        key: TArg<Uint8Array>,
        header: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        abytes(publicKey, undefined, "publicKey");
        abytes(key, undefined, "key");
        abytes(header, undefined, "header");
        const k = Fn.create(bytesToNumberLE(rand ?? randomBytes(Fn.BYTES))),
            R = Fp.toBytes(BASE.multiply(k).x),
            theta = Fp.toBytes(Point.fromBytes(publicKey).multiply(k).x).subarray(0, 32);

        return concatBytes(R, kwp(theta, header).wrap(key));
    }

    /** Unwrap encryption key */
    const unwrapKey = (
        privateKey: TArg<Uint8Array>,
        wrappedKey: TArg<Uint8Array>,
        header: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        abytes(privateKey, undefined, "privateKey");
        abytes(wrappedKey, undefined, "wrappedKey");
        abytes(header, undefined, "header");
        const x = bytesToNumberLE(wrappedKey.subarray(0, Fn.BYTES)),
            ct = wrappedKey.subarray(Fn.BYTES),
            y = Fp.sqrt(Fp.add(
                Fp.add(
                    Fp.pow(x, 3n),
                    Fp.mul(a, x)
                ),
                b
            ));

        const R = Point.fromAffine({ x, y });
        R.assertValidity();

        const theta = Fp.toBytes(R.multiply(Fn.fromBytes(privateKey)).x).subarray(0, 32);

        return kwp(theta, header).unwrap(ct);
    }

    return Object.freeze({
        Point,
        getPublicKey,
        sign, verify,
        wrapKey, unwrapKey
    });
}

/** `Bign128v1` curve */
export const bign128 = bign(BIGN128);
/** `Bign192v1` curve */
export const bign192 = bign(BIGN192);
/** `Bign256v1` curve */
export const bign256 = bign(BIGN256);

export const CURVES = { bign128, bign192, bign256 }

export * from "./const.js";