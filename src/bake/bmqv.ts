import { bytesToNumberLE, concatBytes, type TArg } from "@noble/curves/utils.js";
import { bign128, bign192, bign256 } from "../bign/index.js";
import { beltHash } from "../beltHash/index.js";
import { bake_kdf, EMPTY_ID, ta_pt, tb_pt } from "./utils.js";
import { mac } from "../modes/mac.js";
import type { ECDSA, ECKE } from "../types.js";

const bmqv = (
    signer: ECDSA,
    helloA: TArg<Uint8Array> = EMPTY_ID,
    helloB: TArg<Uint8Array> = EMPTY_ID
): ECKE => {
    const { Fp, Fn, BASE } = signer.Point,
        l = Fn.BYTES / 2,
        _2l = 1n << BigInt(Fn.BYTES * 4);

    const run = (
        ida: TArg<Uint8Array>,
        idb: TArg<Uint8Array>,
        secretKey: TArg<Uint8Array>,
        publicKey: TArg<Uint8Array>,
        eSecret: TArg<Uint8Array>,
        ePublic: TArg<Uint8Array>,
        isA: boolean = false
    ) => {
        const secret_own = bytesToNumberLE(secretKey),
            public_own = BASE.multiply(secret_own),
            eSecret_own = bytesToNumberLE(eSecret),
            ePublic_own = BASE.multiply(eSecret_own),
            ePublic_other = signer.Point.fromBytes(ePublic),
            public_other = signer.Point.fromBytes(publicKey);

        const Qa = isA ? public_own : public_other,
            Qb = isA ? public_other : public_own,
            Va = isA ? ePublic_own : ePublic_other,
            Vb = isA ? ePublic_other : ePublic_own;

        const t = beltHash.create()
            .update(Fp.toBytes(Va.x))
            .update(Fp.toBytes(Vb.x))
            .digest().subarray(0, l);

        const _2lt = Fn.add(_2l, bytesToNumberLE(t));
        const s = Fn.sub(eSecret_own, Fn.mul(_2lt, secret_own));

        let K = ePublic_other.subtract(public_other.multiply(_2lt)).multiply(s);
        if (K.is0()) K = signer.Point.BASE;
        const Kx = Fp.toBytes(K.x);

        const info = concatBytes(
            ida, Fp.toBytes(Qa.x), Fp.toBytes(Qa.y),
            idb, Fp.toBytes(Qb.x), Fp.toBytes(Qb.y),
            helloA, helloB
        );
        const K0 = bake_kdf(Kx, info, 0), K1 = bake_kdf(Kx, info, 1);
        const macMode = mac(K1);

        return {
            K: K0,
            Ta: macMode.compute(ta_pt),
            Tb: macMode.compute(tb_pt)
        }
    }

    return Object.freeze({
        runA: (
            secretKeyA: TArg<Uint8Array>,
            publicKeyB: TArg<Uint8Array>,
            eSecretA: TArg<Uint8Array>,
            ePublicB: TArg<Uint8Array>,
            idA: TArg<Uint8Array> = EMPTY_ID,
            idB: TArg<Uint8Array> = EMPTY_ID,
        ) => run(idA, idB, secretKeyA, publicKeyB, eSecretA, ePublicB, true),
        runB: (
            secretKeyB: TArg<Uint8Array>,
            publicKeyA: TArg<Uint8Array>,
            eSecretB: TArg<Uint8Array>,
            ePublicA: TArg<Uint8Array>,
            idA: TArg<Uint8Array> = EMPTY_ID,
            idB: TArg<Uint8Array> = EMPTY_ID,
        ) => run(idA, idB, secretKeyB, publicKeyA, eSecretB, ePublicA)
    });
}

export const bmqv128 = (helloA?: TArg<Uint8Array>, helloB?: TArg<Uint8Array>) => bmqv(bign128, helloA, helloB);
export const bmqv192 = (helloA?: TArg<Uint8Array>, helloB?: TArg<Uint8Array>) => bmqv(bign192, helloA, helloB);
export const bmqv256 = (helloA?: TArg<Uint8Array>, helloB?: TArg<Uint8Array>) => bmqv(bign256, helloA, helloB);