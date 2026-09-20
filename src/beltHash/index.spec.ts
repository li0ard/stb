/**
 * Test vectors from STB 34.101.31 directly and from test procedures
 * "МЕТОДИКА ИСПЫТАНИЙ СРЕДСТВ КРИПТОГРАФИЧЕСКОЙ ЗАЩИТЫ 
 * ИНФОРМАЦИИ НА СООТВЕТСТВИЕ ТРЕБОВАНИЯМ СТБ 34.101.31-2020 МИ.10131.11.01"
 * https://www.oac.gov.by/public/content/files/files/stb/met-10131-11-01.pdf
 */
import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { beltHash } from "./index";
import { H } from "../belt/const";

const performTest = (input: Uint8Array, expected: Uint8Array) =>
    expect(beltHash(input)).toStrictEqual(expected as TRet<Uint8Array>);

describe("[CORE] BelT hash (STB 34.101.31)", () => {
    test("#1", () => performTest(
        H.subarray(0,13),
        hexToBytes("ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75")
    ));

    test("#2", () => performTest(
        H.subarray(0,32),
        hexToBytes("749E4C3653AECE5E48DB4761227742EB6DBE13F4A80F7BEFF1A9CF8D10EE7786")
    ));

    test("#3", () => performTest(
        H.subarray(0,48),
        hexToBytes("9D02EE446FB6A29FE5C982D4B13AF9D3E90861BC4CEF27CF306BFB0B174A154A")
    ));

    test("#4", () => performTest(
        new TextEncoder().encode("Thirty two byte message (test 1)"),
        hexToBytes("7F526F9CE5BBC4B14A8B9F9B45E88CE200CE7ADD6E4AE62DCBB4EFA81EE5FC58")
    ));

    test("#5", () => performTest(
        new TextEncoder().encode("Fifty four byte or four hundred thirty two bit message"),
        hexToBytes("2AB0EF11607723793F9F32D7FDC667813BA7186317BDE4F92854F673C0D04A48")
    ));

    /*test.skipIf(process.env.SKIP_LONG == "1")("#6", () => performTest(
        new Uint8Array(1000000).fill(0x61),
        hexToBytes("98001732AC6BD9A3B03B66886320EC8A3E43825581E10779130B02FBD67E21E5")
    ));*/
});