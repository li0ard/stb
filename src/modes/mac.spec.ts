import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { KEY1, PT1 } from "./_test_utils.spec";
import { mac } from "./mac";
import { H } from "../belt/const";

const performTest = (key: Uint8Array, pt: Uint8Array, ct: TRet<Uint8Array>) => {
    const mode = mac(key);
    expect(mode.compute(pt)).toStrictEqual(ct);
}

describe("[MODE] MAC", () => {
    test("#1", () => performTest(
        KEY1, 
        PT1,
        hexToBytes("2DAB59771B4B16D0")
    ));

    test("#2", () => performTest(
        KEY1, 
        H.subarray(0, 13),
        hexToBytes("7260DA60138F96C9")
    ));
});