import type { TArg } from "@noble/hashes/utils.js";
import { bytesToUint64s, uint64sToBytes } from "../utils.js";

const ITER = new BigUint64Array([
    0x3bf5080ac8ba94b1n,
    0xc1d1659c1bbd92f6n,
    0x60e8b2ce0ddec97bn,
    0xec5fb8fe790fbc13n,
    0xaa043de6436706a7n,
    0x8929ff6a5e535bfdn,
    0x98bf1e2c50c97550n,
    0x4c5f8f162864baa8n,
    0x262fc78b14325d54n,
    0x1317e3c58a192eaan,
    0x098bf1e2c50c9755n,
    0xd8ee19681d669304n,
    0x6c770cb40eb34982n,
    0x363b865a0759a4c1n,
    0xc73622b47c4c0acen,
    0x639b115a3e260567n,
    0xede6693460f3da1dn,
    0xaad8d5034f9935a0n,
    0x556c6a81a7cc9ad0n,
    0x2ab63540d3e64d68n,
    0x155b1aa069f326b4n,
    0x0aad8d5034f9935an,
    0x0556c6a81a7cc9adn,
    0xde8082cd72debc78n
]);

const MASK64 = 0xFFFFFFFFFFFFFFFFn;
const _ROTHI_ = (x: bigint, y: bigint): bigint => ((x << y) | (x >> (64n - y))) & MASK64;
const ROTHI = (x: bigint, y: bigint): bigint => (y < 64n && y > 0n) ? _ROTHI_(x, y) : x;

const S = (
    S: TArg<BigUint64Array>,
    i0: number, i1: number, i2: number,
    m1: bigint, n1: bigint,
    m2: bigint, n2: bigint
) => {
    let T0 = ROTHI(S[i0], m1);
    S[i0] ^= S[i1] ^ S[i2];
    let T1 = S[i1] ^ ROTHI(S[i0], n1);
    S[i1] = T0 ^ T1;
    S[i2] ^= ROTHI(S[i2], m2) ^ ROTHI(T1, n2);
    T0 = S[i2] ^ MASK64;
    T1 = S[i0] | S[i2];
    const T2 = S[i0] & S[i1];
    T0 = T0 | S[i1];
    S[i1] ^= T1;
    S[i2] ^= T2;
    S[i0] ^= T0; 
}

const P = (S: TArg<BigUint64Array>) => S.set(new BigUint64Array([
    S[15], S[10], S[9], S[12], S[11], S[14], S[13], S[8],
    S[17], S[16], S[19], S[18], S[21], S[20], S[23], S[22],
    S[6], S[3], S[0], S[5], S[2], S[7], S[4], S[1]
]));

const R = (s: TArg<BigUint64Array>, i: number) => {
    S(s, 0, 8, 16, 8n, 53n, 14n, 1n);
    S(s, 1, 9, 17, 56n, 51n, 34n, 7n);
    S(s, 2, 10, 18, 8n, 37n, 46n, 49n);
    S(s, 3, 11, 19, 56n, 3n, 2n, 23n);
    S(s, 4, 12, 20, 8n, 21n, 14n, 33n);
    S(s, 5, 13, 21, 56n, 19n, 34n, 39n);
    S(s, 6, 14, 22, 8n, 5n, 46n, 17n);
    S(s, 7, 15, 23, 56n, 35n, 2n, 55n);
    P(s);
    s[23] ^= ITER[i];
}

export const F = (s: TArg<BigUint64Array>, bigend = true) => {
    if(bigend) s.set(bytesToUint64s(uint64sToBytes(s).reverse()).reverse());
    for(let i = 0; i < 24; i++) R(s, i);
    if(bigend) s.set(bytesToUint64s(uint64sToBytes(s).reverse()).reverse());
}