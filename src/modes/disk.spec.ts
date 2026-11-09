import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";
import { bde, sde } from "./disk";
import { H } from "../belt/const";

const performTest = (
    key: Uint8Array,
    iv: Uint8Array,
    pt: TRet<Uint8Array>,
    ct: TRet<Uint8Array>
) => {
    const mode = bde(key);
    expect(mode.encrypt(pt, iv)).toStrictEqual(ct);
    expect(mode.decrypt(ct, iv)).toStrictEqual(pt);
}

const performTest2 = (
    key: Uint8Array,
    iv: Uint8Array,
    pt: TRet<Uint8Array>,
    ct: TRet<Uint8Array>
) => {
    const mode = sde(key);
    expect(mode.encrypt(pt, iv)).toStrictEqual(ct);
    expect(mode.decrypt(ct, iv)).toStrictEqual(pt);
}


describe("[MODE] BDE", () => {
    test("#1", () => performTest(
        KEY1,
        IV1,
        PT1,
        hexToBytes("E9CAB32D879CC50C10378EB07C10F26307257E2DBE2B854CBC9F38282D59D6A77F952001C5D1244F53210A27C216D4BB")
    ));

    test("#2", () => performTest(
        KEY2,
        IV2,
        hexToBytes("7041BC226352C706D00EA8EF23CFE46AFAE118577D037FACDC36E4ECC1F6574609F236943FB809E1BEE4A1C686C13ACC"),
        PT2
    ));
});

describe("[MODE] SDE", () => {
    test("#1", () => performTest2(
        KEY1,
        IV1,
        PT1,
        hexToBytes("1FCBB01852003D60B66024C508608BAA2C21AF1E884CF31154D3077D4643CF2249EB2F5A68E4BA019D90211A81D690D9")
    ));

    test("#2", () => performTest2(
        KEY2,
        IV2,
        hexToBytes("E9FDF3F788657332E6C46FCF5251B8A6D43543A93E3233837DB1571183A6EF4D7FEB5CDF999E1A3F51A5A3381BEB7FA5"),
        PT2
    ));
});