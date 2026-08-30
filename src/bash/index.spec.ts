/**
 * Test vectors from test procedures
 * "МЕТОДИКА ИСПЫТАНИЙ СРЕДСТВ КРИПТОГРАФИЧЕСКОЙ ЗАЩИТЫ 
 * ИНФОРМАЦИИ НА СООТВЕТСТВИЕ ТРЕБОВАНИЯМ СТБ 34.101.77-2020 МИ.10177.11.01"
 * https://www.oac.gov.by/public/content/files/files/stb/met-10177-11-01.pdf
 */
import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { bash256, bash384, bash512 } from ".";
import { H } from "../belt/const";

const vec1 = new TextEncoder().encode("Fifty four byte or four hundred thirty two bit message");
const vec2 = new Uint8Array([]);

describe("[CORE] Bash (STB 34.101.77)", () => {
    test("#1", () => {
        const expected = hexToBytes("114C3DFAE373D9BCBC3602D6386F2D6A2059BA1BF9048DBAA5146A6CB775709D");
        expect(bash256(vec2)).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("3D7F4EFA00E9BA33FEED259986567DCF5C6D12D51057A968F14F06CC0F905961");
        expect(bash256(H.subarray(0, 127))).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("8F866380A7714B539DBC9F3D18020BCAEDBD428AECC69F1405699BE12C19ED02");
        expect(bash256(vec1)).toStrictEqual(expected);
    });

    test("#4", () => {
        const expected = hexToBytes("296F63CDDF8E4963A657A8861FAD1D9D75BAF67E747B7E00AF8E55BAB9E2627BB0E2B752D867E70BEB88D13D495A4ECB");
        expect(bash384(vec2)).toStrictEqual(expected);
    });

    test("#5", () => {
        const expected = hexToBytes("64334AF830D33F63E9ACDFA184E32522103FFF5C6860110A2CD369EDBC04387C501D8F92F749AE4DE15A8305C353D64D");
        expect(bash384(H.subarray(0, 95))).toStrictEqual(expected);
    });

    test("#6", () => {
        const expected = hexToBytes("0CC67F5E0D51D7D174146E85393C171F3E7B76456589653ED19025C4B2A69601B685F4EC7D8CCB6EE1E7EC8793A82D55");
        expect(bash384(vec1)).toStrictEqual(expected);
    });

    test("#7", () => {
        const expected = hexToBytes("D3A5F9B655CE3EFC1C3E6F2FA1E10F39EC1C3950462097CED1130814868E49E3887581066CD78A97B6685A410E239D12A357FAFF1B252D6310AA1F95FD4A0283");
        expect(bash512(vec2)).toStrictEqual(expected);
    });

    test("#8", () => {
        const expected = hexToBytes("2A66C87C189C12E255239406123BDEDBF19955EAF0808B2AD705E249220845E20F4786FB6765D0B5C48984B1B16556EF19EA8192B985E4233D9C09508D6339E7");
        expect(bash512(H.subarray(0, 63))).toStrictEqual(expected);
    });

    test("#9", () => {
        const expected = hexToBytes("38FBE3C7A8F85A6416E876EF884F68886336E5214BC189D5B30079211861B4C8846012005C4316313B31CB0B1FB5011E1FDADF7E48061283BCCBD67DE9131DDA");
        expect(bash512(vec1)).toStrictEqual(expected);
    });


});

describe.skipIf(process.env.SKIP_LONG == "1")("[CORE] Bash (STB 34.101.77)", () => {
    const _1mb = new Uint8Array(1000000).fill(0x61);
    test("#10", () => {
        const expected = hexToBytes("F8812E85897421D48D56C600D8F76F24F2E0FFC6F879DB8F3279B4F6C53529FA");
        expect(bash256(_1mb)).toStrictEqual(expected);
    }, 20000);

    test("#11", () => {
        const expected = hexToBytes("FE74AC72B33B7306498393E898D1CAED783276083EA3052F7897BF9B681B8DC1A9112418133C016579F93B22DBAF2977");
        expect(bash384(_1mb)).toStrictEqual(expected);
    }, 20000);

    test("#12", () => {
        const expected = hexToBytes("E3E32CD6E7AB56FD4BB7D654B93C8325DD7F130ABB99B3B8DC8AC2BF604D51D07DD94DB483451D6433739AE775E4DDF35154E70E1812A4E06EE46E6F02323E41");
        expect(bash512(_1mb)).toStrictEqual(expected);
    }, 20000);
});