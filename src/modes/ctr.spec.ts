import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2, PT1 } from "./_test_utils.spec";
import { ctr } from "./ctr";
import { H } from "../belt/const";

const performTest = (key: Uint8Array, iv: Uint8Array, pt: TRet<Uint8Array>, ct: TRet<Uint8Array>) => {
    const mode = ctr(key, iv);
    expect(mode.crypt(pt)).toStrictEqual(ct);
    expect(mode.crypt(ct)).toStrictEqual(pt);
}

describe("[MODE] CTR", () => {
    test("#1", () => performTest(
        KEY1,
        IV1,
        PT1,
        hexToBytes("52C9AF96FF50F64435FC43DEF56BD797D5B5B1FF79FB41257AB9CDF6E63E81F8F00341473EAE409833622DE05213773A")
    ));

    test("#2", () => performTest(
        KEY2,
        IV2,
        hexToBytes("DF181ED008A20F43DCBBB93650DAD34B389CDEE5826D40E2D4BD80F49A93F5D212F6333166456F169043CC5F"),
        H.subarray(64, 108)
    ));
});