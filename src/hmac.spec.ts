
import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { beltHmac } from "./hmac";
import { H } from "./belt/const";

const performTest = (
    key: Uint8Array,
    msg: Uint8Array,
    expected: TRet<Uint8Array>
) => expect(beltHmac(key, msg)).toStrictEqual(expected);

describe("[HMAC] BelT hash", () => {
    test("#1", () => performTest(
        H.subarray(128,157),
        H.subarray(192,224),
        hexToBytes("D4828E6312B08BB83C9FA6535A4635549E411FD11C0D8289359A1130E930676B")
    ));
    
    test("#2", () => performTest(
        H.subarray(128,160),
        H.subarray(192,224),
        hexToBytes("41FFE8645AEC0612E952D2CDF8DD508F3E4A1D9B53F6A1DB293B19FE76B1879F")
    ));

    test("#3", () => performTest(
        H.subarray(128,170),
        H.subarray(192,224),
        hexToBytes("7D01B84D2315C332277B3653D7EC64707EBA7CDFF7FF70077B1DECBD68F2A144")
    ));
});