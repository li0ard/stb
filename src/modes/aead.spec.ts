import { describe, test, expect } from "bun:test";
import { concatBytes, hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2 } from "./_test_utils.spec";
import { che, dwp } from "./aead";
import { H } from "../belt/const";

const performTest = (
    key: Uint8Array,
    iv: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = dwp(key, iv);
    expect(mode.seal(pt, aad)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.open(ct, aad)).toStrictEqual(pt as TRet<Uint8Array>);
}

const performTest2 = (
    key: Uint8Array,
    iv: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = che(key, iv);
    expect(mode.seal(pt, aad)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.open(ct, aad)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] DWP", () => {
    const aad = H.subarray(16,48);
    const aad2 = H.subarray(80,112);
    test("#1", () => performTest(
        KEY1,
        IV1,
        aad,
        H.subarray(0,16),
        hexToBytes("52C9AF96FF50F64435FC43DEF56BD7973B2E0AEB2B91854B")
    ));

    test("#2", () => performTest(
        KEY2,
        IV2,
        aad2,
        hexToBytes("DF181ED008A20F43DCBBB93650DAD34B"),
        concatBytes(
            H.subarray(64, 80),
            hexToBytes("6A2C2C94C4150DC0")
        ),
    ));
});

describe("[MODE] CHE", () => {
    const aad = H.subarray(16,48);
    const aad2 = H.subarray(80,112);
    test("#1", () => performTest2(
        KEY1,
        IV1,
        aad,
        H.subarray(0,15),
        hexToBytes("BF3DAEAF5D18D2BCC30EA62D2E70A4548622B844123FF7")
    ));

    test("#2", () => performTest2(
        KEY2,
        IV2,
        aad2,
        hexToBytes("2BABF43EB37B5398A9068F31A3C758B762F44AA9"),
        concatBytes(
            H.subarray(64, 84),
            hexToBytes("7D9D4F59D40D197D")
        ),
    ));
});