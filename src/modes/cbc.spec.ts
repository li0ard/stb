import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";
import { cbc } from "./cbc";

const performTest = (key: Uint8Array, iv: Uint8Array, pt: Uint8Array, ct: Uint8Array) => {
    const mode = cbc(key, iv);
    expect(mode.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] CBC", () => {
    test("#1", () => performTest(
        KEY1,
        IV1,
        PT1,
        hexToBytes("10116EFAE6AD58EE14852E11DA1B8A745CF2480E8D03F1C19492E53ED3A70F60657C1EE8C0E0AE5B58388BF8A68E3309")
    ));

    test("#2", () => performTest(
        KEY2,
        IV2,
        hexToBytes("730894D6158E17CC1600185A8F411CAB0471FF85C83792398D8924EBD57D03DB95B97A9B7907E4B020960455E46176F8"),
        PT2
    ));
});