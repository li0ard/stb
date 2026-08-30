import { describe, test, expect } from "bun:test";
import { H } from "../belt/const";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";
import { wbl } from "./wbl";

const performTest = (key: Uint8Array, pt: Uint8Array, ct: Uint8Array) => {
    const mode = wbl(key);
    expect(mode.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] WBL", () => {
    test("#1", () => performTest(
        KEY1,
        PT1,
        hexToBytes("49A38EE108D6C742E52B774F00A6EF98B106CBD13EA4FB0680323051BC04DF76E487B055C69BCF541176169F1DC9F6C8")
    ));

    test("#2", () => performTest(
        KEY2,
        hexToBytes("92632EE0C21AD9E09A39343E5C07DAA4889B03F2E6847EB152EC99F7A4D9F154B5EF68D8E4A39E567153DE13D72254EE"),
        PT2
    ));
});