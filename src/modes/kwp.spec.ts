import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";
import { kwp } from "./kwp";
import { H } from "../belt/const";

const performTest = (key: Uint8Array, iv: Uint8Array, pt: Uint8Array, ct: Uint8Array) => {
    const mode = kwp(key, iv);
    expect(mode.wrap(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.unwrap(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] KWP", () => {
    test("#1", () => performTest(
        KEY1,
        H.subarray(32,48),
        H.subarray(0,32),
        hexToBytes("49A38EE108D6C742E52B774F00A6EF98B106CBD13EA4FB0680323051BC04DF76E487B055C69BCF541176169F1DC9F6C8")
    ));

    test("#2", () => performTest(
        KEY2,
        hexToBytes("B5EF68D8E4A39E567153DE13D72254EE"),
        hexToBytes("92632EE0C21AD9E09A39343E5C07DAA4889B03F2E6847EB152EC99F7A4D9F154"),
        PT2
    ));
});