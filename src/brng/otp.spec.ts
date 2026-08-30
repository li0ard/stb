/**
 * Test vectors from STB 34.101.31 directly and from test procedures
 * "МЕТОДИКА ИСПЫТАНИЙ СРЕДСТВ КРИПТОГРАФИЧЕСКОЙ ЗАЩИТЫ 
 * ИНФОРМАЦИИ НА СООТВЕТСТВИЕ ТРЕБОВАНИЯМ СТБ 34.101.47-2017 МИ.10131.11.01"
 * https://www.oac.gov.by/public/content/files/files/stb/met-10147-11-01.pdf
 */
import { describe, test, expect } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { botp } from ".";
import { KEY1 } from "../modes/_test_utils.spec";

describe("[BRNG] OTP", () => {
    const otp = botp(KEY1, 8);
    const ctr = hexToBytes("BE32971343FC9A48");
    let totp = 1449165288;

    test("#1", () => expect(otp.hotp(ctr)).toStrictEqual("21157984"));

    test("#2", () => {
        ctr[7]++;
        expect(otp.hotp(ctr)).toStrictEqual("17877985");
    });

    test("#3", () => {
        ctr[7]++;
        expect(otp.hotp(ctr)).toStrictEqual("26078636");
    });

    test("#4", () => expect(otp.totp(totp)).toStrictEqual("97660664"));

    test("#5", () => expect(otp.totp(totp += 12)).toStrictEqual("94431522"));

    test("#6", () => expect(otp.totp(totp += 60)).toStrictEqual("55973851"));
});