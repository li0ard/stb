import { numberToBytesLE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { keyTransform } from "../belt/index.js";
import { beltHash } from "../beltHash/index.js";

export const EMPTY_ID = new Uint8Array(),
    ta_pt = new Uint8Array(16),
    tb_pt = new Uint8Array(16).fill(0xFF);

const lvl = new Uint8Array(12).fill(0xFF);

export const bake_kdf = (
    key: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    num: number
): TRet<Uint8Array> => keyTransform(
    beltHash(concatBytes(key, iv)),
    lvl,
    numberToBytesLE(num, 16),
    32
);