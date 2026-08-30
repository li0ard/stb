import { test, expect } from "bun:test";
import { compress } from "./compress";
import { H } from "../belt/const";
import { hexToBytes } from "@noble/hashes/utils.js";

test("[MODE] Compress", () => {
    const [S, Y] = compress(H.subarray(0,64));
    
    expect(S).toStrictEqual(hexToBytes("46FE7425C9B181EB41DFEE3E72163D5A"));
    expect(Y).toStrictEqual(hexToBytes("ED2F5481D593F40D87FCE37D6BC1A2E1B7D1A2CC975C82D3C0497488C90D99D8"));
});