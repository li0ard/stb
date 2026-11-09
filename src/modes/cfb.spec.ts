import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV1, IV2, KEY1, KEY2, PT1, PT2 } from "./_test_utils.spec";
import { cfb } from "./cfb";

const performTest = (key: Uint8Array, iv: Uint8Array, pt: TRet<Uint8Array>, ct: TRet<Uint8Array>) => {
    const mode = cfb(key, iv);
    expect(mode.encrypt(pt)).toStrictEqual(ct);
    expect(mode.decrypt(ct)).toStrictEqual(pt);
}

describe("[MODE] CFB", () => {
    test("#1", () => performTest(
        KEY1,
        IV1,
        PT1,
        hexToBytes("C31E490A90EFA374626CC99E4B7B8540A6E48685464A5A06849C9CA769A1B0AE55C2CC5939303EC832DD2FE16C8E5A1B")
    ));

    test("#2", () => performTest(
        KEY2,
        IV2,
        hexToBytes("FA9D107A86F375EE65CD1DB881224BD016AFF814938ED39B3361ABB0BF0851B652244EB06842DD4C94AA4500774E40BB"),
        PT2
    ));
});