import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { ecb } from "./ecb";
import { KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";

const performTest = (key: Uint8Array, pt: TRet<Uint8Array>, ct: TRet<Uint8Array>) => {
    const mode = ecb(key);
    expect(mode.encrypt(pt)).toStrictEqual(ct);
    expect(mode.decrypt(ct)).toStrictEqual(pt);
}

describe("[MODE] ECB", () => {
    test("#1", () => performTest(
        KEY1,
        PT1,
        hexToBytes("69CCA1C93557C9E3D66BC3E0FA88FA6E5F23102EF109710775017F73806DA9DC46FB2ED2CE771F26DCB5E5D1569F9AB0")
    ));

    test("#2", () => performTest(
        KEY2,
        hexToBytes("0DC5300600CAB840B38448E5E993F421E55A239F2AB5C5D5FDB6E81B40938E2A54120CA3E6E19C7AD750FC3531DAEAB7"),
        PT2
    ));
});