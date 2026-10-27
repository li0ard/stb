import { byteSwap, isLE, type TArg } from "@noble/hashes/utils.js";

const ITER_H = new Uint32Array([
    0x3bf5080a, 0xc1d1659c, 0x60e8b2ce, 0xec5fb8fe, 0xaa043de6, 0x8929ff6a, 0x98bf1e2c,
    0x4c5f8f16, 0x262fc78b, 0x1317e3c5, 0x098bf1e2, 0xd8ee1968, 0x6c770cb4, 0x363b865a,
    0xc73622b4, 0x639b115a, 0xede66934, 0xaad8d503, 0x556c6a81, 0x2ab63540, 0x155b1aa0,
    0x0aad8d50, 0x0556c6a8, 0xde8082cd
]);

const ITER_L = new Uint32Array([
  0xc8ba94b1, 0x1bbd92f6, 0x0ddec97b, 0x790fbc13, 0x436706a7, 0x5e535bfd, 0x50c97550,
  0x2864baa8, 0x14325d54, 0x8a192eaa, 0xc50c9755, 0x1d669304, 0x0eb34982, 0x0759a4c1,
  0x7c4c0ace, 0x3e260567, 0x60f3da1d, 0x4f9935a0, 0xa7cc9ad0, 0xd3e64d68, 0x69f326b4,
  0x34f9935a, 0x1a7cc9ad, 0x72debc78
]);

const LO = isLE ? 0 : 1;
const HI = isLE ? 1 : 0;

const rotH = (h: number, l: number, r: number): number => {
    if (r > 32) { 
        const t = h;
        h = l;
        l = t;
        r -= 32;
    }
    return (h << r) | (l >>> (32 - r));
}
const rotL = (h: number, l: number, r: number): number => {
    if (r > 32) {
        const t = h;
        h = l;
        l = t;
        r -= 32;
    }
    return (l << r) | (h >>> (32 - r));
}

const S = (
    u: TArg<Uint32Array>,
    i0: number, i1: number, i2: number,
    m1: number, n1: number,
    m2: number, n2: number
) => {
    const h0 = 2 * i0 + HI, l0 = 2 * i0 + LO;
    const h1 = 2 * i1 + HI, l1 = 2 * i1 + LO;
    const h2 = 2 * i2 + HI, l2 = 2 * i2 + LO;

    let x0h = u[h0], x0l = u[l0];
    let x1h = u[h1], x1l = u[l1];
    let x2h = u[h2], x2l = u[l2];

    const t0h = rotH(x0h, x0l, m1), t0l = rotL(x0h, x0l, m1);

    x0h ^= x1h ^ x2h;
    x0l ^= x1l ^ x2l;

    const t1h = x1h ^ rotH(x0h, x0l, n1),
        t1l = x1l ^ rotL(x0h, x0l, n1);

    x1h = t0h ^ t1h;
    x1l = t0l ^ t1l;

    const r2h = rotH(x2h, x2l, m2) ^ rotH(t1h, t1l, n2),
        r2l = rotL(x2h, x2l, m2) ^ rotL(t1h, t1l, n2);
    x2h ^= r2h;
    x2l ^= r2l;

    const nh = ~x2h | x1h, nl = ~x2l | x1l;
    const oh = x0h | x2h,  ol = x0l | x2l;
    const ah = x0h & x1h,  al = x0l & x1l;

    u[h1] = x1h ^ oh; u[l1] = x1l ^ ol;
    u[h2] = x2h ^ ah; u[l2] = x2l ^ al;
    u[h0] = x0h ^ nh; u[l0] = x0l ^ nl;
}

const PERM = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
    [15, 10, 9, 12, 11, 14, 13, 8, 17, 16, 19, 18, 21, 20, 23, 22, 6, 3, 0, 5, 2, 7, 4, 1],
    [22, 19, 16, 21, 18, 23, 20, 17, 3, 6, 5, 0, 7, 2, 1, 4, 13, 12, 15, 14, 9, 8, 11, 10],
    [4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 20, 21, 22, 23, 16, 17, 18, 19],
    [11, 14, 13, 8, 15, 10, 9, 12, 21, 20, 23, 22, 17, 16, 19, 18, 2, 7, 4, 1, 6, 3, 0, 5],
    [18, 23, 20, 17, 22, 19, 16, 21, 7, 2, 1, 4, 3, 6, 5, 0, 9, 8, 11, 10, 13, 12, 15, 14],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]
];

const CONS: number[][] = [
    [0, 8, 16, 8, 53, 14, 1],
    [1, 9, 17, 56, 51, 34, 7],
    [2, 10, 18, 8, 37, 46, 49],
    [3, 11, 19, 56, 3, 2, 23],
    [4, 12, 20, 8, 21, 14, 33],
    [5, 13, 21, 56, 19, 34, 39],
    [6, 14, 22, 8, 5, 46, 17],
    [7, 15, 23, 56, 35, 2, 55],
];

const bswap64Words = (u: Uint32Array) => {
    for (let i = 0; i < 24; i++) {
        const l = u[2 * i + LO], h = u[2 * i + HI];
        u[2 * i + LO] = byteSwap(h);
        u[2 * i + HI] = byteSwap(l);
    }
}

export const F = (u: TArg<Uint32Array>) => {
    if (!isLE) bswap64Words(u);
    for (let r = 0; r < 24; r++) {
        const m = PERM[r % 6];
        for (let j = 0; j < 8; j++) {
            const c = CONS[j];
            S(u, m[c[0]], m[c[1]], m[c[2]], c[3], c[4], c[5], c[6]);
        }
        const k = PERM[(r + 1) % 6][23];
        u[2 * k + HI] ^= ITER_H[r];
        u[2 * k + LO] ^= ITER_L[r];
    }
    if (!isLE) bswap64Words(u);
}