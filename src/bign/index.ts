import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { BELTOID, BIGN128, BIGN192, BIGN256, type BignCurveParameters } from "./const.js";
import { bytesToNumberBE, bytesToNumberLE, concatBytes, equalBytes, numberToBytesBE, numberToBytesLE, type TArg, type TRet } from "@noble/curves/utils.js";
import { beltHash } from "../beltHash/index.js";
import { wbl } from "../modes/wbl.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { kwp } from "../modes/kwp.js";

export const bign = (parameters: BignCurveParameters) => {
    const Point = weierstrass(parameters);
    const { Fp, Fn, BASE } = Point;
    const { length, n, a, b } = parameters;
    const hlength = parameters.length / 2;

    const _2l = 2n ** BigInt(length * 4);

    const getPublicKey = (
        secretKey: TArg<Uint8Array>, 
        isCompressed: boolean = true
    ): TRet<Uint8Array> => BASE.multiply(bytesToNumberLE(secretKey)).toBytes(isCompressed);

    const drbg = (
        privateKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        oid: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const theta = beltHash(concatBytes(oid, privateKey));
        let kBytes = new Uint8Array(digest);

        const mode = wbl(theta);
        while (true) {
            kBytes = mode.encrypt(kBytes);
        
            const k = bytesToNumberBE(kBytes);
            if (k > 0n && k < n)
                return numberToBytesBE(k, length);
        }
    }

    const sign = (
        privateKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        oid?: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        oid ??= BELTOID;
        const k = bytesToNumberLE(rand ?? drbg(privateKey, digest, oid));
        const R = BASE.multiply(k).x;
        
        const S0 = beltHash(concatBytes(
            oid,
            numberToBytesLE(R, length),
            digest
        )).subarray(0, hlength);

        const S1 = numberToBytesLE(
            Fn.sub(
                Fn.sub(k, bytesToNumberLE(digest)),
                Fn.mul(
                    bytesToNumberLE(privateKey),
                    Fn.add(bytesToNumberLE(S0), _2l)
                )
            ),
            length
        );

        return concatBytes(S0, S1);
    }

    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>,
        oid?: TArg<Uint8Array>
    ): boolean => {
        oid ??= BELTOID;
        if(signature.length != 3 * hlength) return false;

        const S0 = signature.subarray(0, hlength),
            S1 = bytesToNumberLE(signature.subarray(hlength));
        
        if(S1 >= Fn.ORDER) return false;

        const R = BASE.mulAddUnsafe(
            Fn.add(S1, bytesToNumberLE(digest)),
            Point.fromBytes(publicKey),
            Fn.add(bytesToNumberLE(S0), _2l)
        );
        if(R.is0()) return false;

        const t = beltHash(concatBytes(
            oid,
            numberToBytesLE(R.x, length),
            digest
        )).subarray(0, hlength);

        return equalBytes(S0, t);
    }

    const wrapKey = (
        publicKey: TArg<Uint8Array>,
        key: TArg<Uint8Array>,
        header: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const k = Fn.create(bytesToNumberLE(rand ?? randomBytes(Fn.BYTES)));
        const R = numberToBytesLE(BASE.multiply(k).x, length);
        const theta = numberToBytesLE(
            Point.fromBytes(publicKey).multiply(k).x,
            length
        ).subarray(0, 32);

        return concatBytes(R, kwp(theta, header).wrap(key));
    }

    const unwrapKey = (
        privateKey: TArg<Uint8Array>,
        wrappedKey: TArg<Uint8Array>,
        header: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const x = bytesToNumberLE(wrappedKey.subarray(0, length));
        const ct = wrappedKey.subarray(length);

        const y = Fp.sqrt(Fp.add(
            Fp.add(
                Fp.pow(x, 3n),
                Fp.mul(a, x)
            ),
            b
        ));

        const R = Point.fromAffine({ x,y });
        R.assertValidity();

        const theta = numberToBytesLE(
            R.multiply(bytesToNumberLE(privateKey)).x,
            length
        ).subarray(0, 32);

        return kwp(theta, header).unwrap(ct);
    }

    return Object.freeze({
        getPublicKey,
        sign, verify,
        wrapKey, unwrapKey
    });
}

export const bign128 = bign(BIGN128);
export const bign192 = bign(BIGN192);
export const bign256 = bign(BIGN256);
export * from "./const.js";