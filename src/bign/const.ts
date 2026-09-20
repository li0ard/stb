import type { WeierstrassOpts } from "@noble/curves/abstract/weierstrass.js";
import { hexToBytes } from "@noble/curves/utils.js";

export interface BignCurveParameters extends WeierstrassOpts<bigint> {
    /** Curve point length */
    length: number;
    /** Curve OIDs */
    oids?: string[];
}

/** BelT hash OID */
export const BELTOID: Uint8Array = hexToBytes("06092A7000020022651F51");
/** Bash-128 OID*/
export const BASH128OID: Uint8Array = hexToBytes("06092A7000020022654D0B");
/** Bash-192 OID*/
export const BASH192OID: Uint8Array = hexToBytes("06092A7000020022654D0C");
/** Bash-256 OID*/
export const BASH256OID: Uint8Array = hexToBytes("06092A7000020022654D0D");

/** Bign curve 128v1 */
export const BIGN128: Readonly<BignCurveParameters> = {
    p: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43n,
    n: 0xffffffffffffffffffffffffffffffffd95c8ed60dfb4dfc7e5abf99263d6607n,
    a: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40n,
    b: 0x77ce6c1515f3a8edd2c13aabe4d8fbbe4cf55069978b9253b22e7d6bd69c03f1n,
    Gx: 0n,
    Gy: 0x6bf7fc3cfb16d69f5ce4c9a351d6835d78913966c408f6521e29cf1804516a93n,
    h: 1n,
    length: 32,
    oids: ["1.2.112.0.2.0.34.101.45.3.1"]
}

/** Bign curve 192v1 */
export const BIGN192: Readonly<BignCurveParameters> = {
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3n,
    n: 0xfffffffffffffffffffffffffffffffffffffffffffffffe6cccc40373af7bbb8046dae7a6a4ff0a3db7dc3ff30ca7b7n,
    a: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC0n,
    b: 0x3c75dfe1959cef2033075aab655d34d2712748bb0ffbb196a6216af9e9712e3a14bde2f0f3cebd7cbca7fc236873bf64n,
    Gx: 0n,
    Gy: 0x5d438224a82e9e9e6330117e432dbf893a729a11dc86ffa00549e79e66b1d35584403e276b2a42f9ea5ecb31f733c451n,
    h: 1n,
    length: 48,
    oids: ["1.2.112.0.2.0.34.101.45.3.2"]
}

/** Bign curve 256v1 */
export const BIGN256: Readonly<BignCurveParameters> = {
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7n,
    n: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb2c0092c0198004ef26bebb02e2113f4361bcae59556df32dcffad490d068ef1n,
    a: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4n,
    b: 0x6cb45944933b8c43d88c5d6a60fd58895bc6a9eedd5d255117ce13e3daadb0882711dcb5c4245e952933008c87aca243ea8622273a49a27a09346998d6139c90n,
    Gx: 0n,
    Gy: 0xa826ff7ae4037681b182e6f7a0d18fabb0ab41b3b361bce2d2edf81b00cccada6973dde20efa6fd2ff777395eee8226167aa83b9c94c0d04b792ae6fceefedbdn,
    h: 1n,
    length: 64,
    oids: ["1.2.112.0.2.0.34.101.45.3.3"]
}