/**
 * Test vectors from test procedures
 * "МЕТОДИКА ИСПЫТАНИЙ СРЕДСТВ КРИПТОГРАФИЧЕСКОЙ ЗАЩИТЫ 
 * ИНФОРМАЦИИ НА СООТВЕТСТВИЕ ТРЕБОВАНИЯМ СТБ 34.101.77-2020 МИ.10177.11.01"
 * https://www.oac.gov.by/public/content/files/files/stb/met-10177-11-01.pdf
 */
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { prgAead, prgHash } from ".";
import { H } from "../belt/const";

const ann1 = hexToBytes("06075316");
const vec1 = new Uint8Array();
const vec2 = H.subarray(0, 127);
const vec3 = H.subarray(0, 143);
const vec4 = new TextEncoder().encode("Fifty four byte or four hundred thirty two bit message");
describe("[CORE] Bash-PRG-HASH (STB 34.101.77)", () => {
    test("#1", () => {
        const expected = hexToBytes("36FA075EC15721F250B9A641A8CB99A333A9EE7BA8586D0646CBAC3686C03DF3");
        expect(prgHash(128, 2, vec1)).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("C930FF427307420DA6E4182969AA1FFC3310179B8A0EDB3E20BEC285B568BA17");
        expect(prgHash(128, 2, vec2)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("D451F9126ADC04670441BE01D589809B9717FCF77EE5339E8318D2CE86A9C390");
        expect(prgHash(128, 1, vec3)).toStrictEqual(expected);
    });

    test("#4", () => {
        const expected = hexToBytes("B8C6742CAE437564074564BD3B99112E8399CE81E66E7B9AFF7B59ECE5BA2009");
        expect(prgHash(128, 1, vec4, ann1)).toStrictEqual(expected);
    });

    test("#5", () => {
        const expected = hexToBytes("39E58343BA9E2B94D70D447425CE8AFEB6E019033583B2A013687D275E0515986E8408DA9E0C0C0802111209AA9E1E70");
        expect(prgHash(192, 2, vec1)).toStrictEqual(expected);
    });

    test("#6", () => {
        const expected = hexToBytes("40091E6FE851F45AF77AF952FD42E1B5860B5BB3DE6A84482D2EF98642ED0788CB3629472CDCBE2D3188074515E08B58");
        expect(prgHash(192, 2, vec2)).toStrictEqual(expected);
    });

    test("#7", () => {
        const expected = hexToBytes("6166032D6713D401A6BC687CCFFF2E603287143A84C78D2C62C71551E0E2FB2AF6B799EE33B5DECD7F62F190B1FBB052");
        expect(prgHash(192, 1, vec3)).toStrictEqual(expected);
    });

    test("#8", () => {
        const expected = hexToBytes("703DFC9C79A70E39F75EFC8A9E54AAE6604F21C928A335C4B5E1B1BC6C252F8BF677302BF6702C19BC9832E3A237113E");
        expect(prgHash(192, 1, vec4, ann1)).toStrictEqual(expected);
    });

    test("#9", () => {
        const expected = hexToBytes("5FBDF97C622FBB36F5EE30639C03EF2600105578613401D8C0877BF38E726845E153094492D13865CD9527E6B42E2FFA590EE19DB971C32749A3386D3EC5263B");
        expect(prgHash(256, 2, vec1)).toStrictEqual(expected);
    });

    test("#10", () => {
        const expected = hexToBytes("6326B650058B5954C799BF76810A0E6E1DD0900BFA04C2D527CC64CD7CE208BA4C7893EAACDC503EF27A5BB052EB10116E29BA80BCA023FB28C7808411411865");
        expect(prgHash(256, 2, vec2)).toStrictEqual(expected);
    });

    test("#11", () => {
        const expected = hexToBytes("9E5CBDD50DDC71E37482784AAB3BBC1D5E7DC3DF4D2018642BB98A9583BCF2883B06CCDF5D201C86CC0564660614CE3CED90E53C4B2B87B23C0B60994FEFE9D6");
        expect(prgHash(256, 1, vec3)).toStrictEqual(expected);
    });

    test("#12", () => {
        const expected = hexToBytes("8F0B8A3A11505F7CDFD7EE033434B84778BA638561D7AB47568C868AE9FC6496A5E74E8B3C8576F12C128181DB4DBDF915B8D5CE87F8D71F86DC4A55D7E7DC3B");
        expect(prgHash(256, 1, vec4, ann1)).toStrictEqual(expected);
    });
});

describe.skipIf(process.env.SKIP_LONG == "1")("[CORE] Bash-PRG-HASH (STB 34.101.77)", () => {
    const _1mb = new Uint8Array(1000000).fill(0x61);
    test("#13", () => {
        const expected = hexToBytes("F84CA85F610711674BB8ADDB87B747C6000A6B6735664687854052C60CE0F7B0");
        expect(prgHash(128, 2, _1mb)).toStrictEqual(expected);
    }, 20000);

    test("#14", () => {
        const expected = hexToBytes("C9B4ABF055F1A2ED025385AA5480BA9ADFB1608409D3102BCC557C41B22C2866233212327DF735BE22D85DE44CB48C2E");
        expect(prgHash(192, 2, _1mb)).toStrictEqual(expected);
    }, 20000);

    test("#15", () => {
        const expected = hexToBytes("45911D1B40F84E5D53C3B27FBB91D696E96924C5F3BD61CC589F26FA9502F3F5847DF96A5D6B44D17388DFF413D0B8AE0D81073D010F1637A20892E06DAB1AF0");
        expect(prgHash(256, 2, _1mb)).toStrictEqual(expected);
    }, 20000);
});

const proceedTest = (
    l: number, d: number,
    key: Uint8Array,
    ann: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = prgAead(l, d, key, ann);
    expect(mode.seal(pt, aad)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.open(ct, aad)).toStrictEqual(pt as TRet<Uint8Array>);
}

const EMPTY = new Uint8Array(0);
const aad1 = new TextEncoder().encode("Thirty two byte message (test 1)");
const key1 = hexToBytes("2033394D6C320D0965201A166E62001D");
const key2 = hexToBytes("2033394D6C320D0965201A166E62001D6779410674740E13");
const key3 = hexToBytes("2033394D6C320D0965201A166E62001D6779410674740E136865160D3D730C11");

describe("[CORE] Bash-PRG-AEAD (STB 34.101.77)", () => {
    test("#1", () => proceedTest(
        128, 2,
        key1,
        EMPTY,
        aad1,
        vec4,
        hexToBytes("3DC15B5B5C44352D9DD48EB6AF1C7F25AC47F495E2F95DC98A395C88FC7BC0FE8D2274F248B34183F7A19FD3EDF141B8130D3EDF3F132091C633C522E51B1EFF3D704BDFA289")
    ));

    test("#2", () => proceedTest(
        128, 2,
        H.subarray(32, 48),
        hexToBytes("9DEADEC2621747A6"),
        EMPTY,
        aad1,
        hexToBytes("85E004B72641B56795B8DA31BEE91AD7F82BB6DC05FE9216A4A71312885FFFB22B4C6067265F837A678EE9803F578817")
    ));

    test("#3", () => proceedTest(
        128, 1,
        key1,
        EMPTY,
        aad1,
        EMPTY,
        hexToBytes("3501E8ADA1D710A5986175B5916B0B77")
    ));

    test("#4", () => proceedTest(
        192, 2,
        key2,
        EMPTY,
        aad1,
        vec4,
        hexToBytes("7BFC37CEEA096D4B1A611B92219CCEABCF5B997ABFE1533C4CFBF4EB866E5A09991C98C73B04A614BE45E471E9287E2D2A1D7C43C8DDB7C89033F37FF0A501368542027AF891DAEC399D9B5A2AB8")
    ));

    test("#5", () => proceedTest(
        192, 2,
        H.subarray(32, 56),
        hexToBytes("9DEADEC2621747A62A80A7C3"),
        EMPTY,
        aad1,
        hexToBytes("EC10AB97D0EB88F2FA32EBB780B2FD9C3E011523E53B07C4D603501D6D3D416A2EA75655204A58F7E7E1AB46974692BC9BD2B8E3C00DF8A3")
    ));

    test("#6", () => proceedTest(
        192, 1,
        key2,
        EMPTY,
        aad1,
        EMPTY,
        hexToBytes("D140D605C4F6BE6881E9A32766ED2869C6F89F35E3B00542")
    ));

    test("#7", () => proceedTest(
        256, 2,
        key3,
        EMPTY,
        aad1,
        vec4,
        hexToBytes("1DA58141375539D1903E4C06AB373859779355B3C30031A8918A9D6F97624BA4ABAE88F2335378B0FD63295D1E32FCB72DF068130A9B3DF50074177D5EFAE170E621E68029166E3EDC7B6A1DB888394F2C335211BC6C")
    ));

    test("#8", () => proceedTest(
        256, 2,
        H.subarray(32, 64),
        hexToBytes("9DEADEC2621747A62A80A7C3FFA8E347"),
        EMPTY,
        aad1,
        hexToBytes("94E1191BACD0D021EA896457DA109A7FBF10576FAAC3675BBD242AED036397A2409BF97685E03A99EE832042ECCBE9BA370774DE1CBFB84BC7218B83A99EB846")
    ));

    test("#9", () => proceedTest(
        256, 1,
        key3,
        EMPTY,
        aad1,
        EMPTY,
        hexToBytes("839A7287D0BBEE0231BB909AC24C3FDAFC9EA34921D29CBF97CCFD0902EC37ED")
    ));
});