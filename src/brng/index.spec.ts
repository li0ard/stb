/**
 * Test vectors from STB 34.101.31 directly and from test procedures
 * "МЕТОДИКА ИСПЫТАНИЙ СРЕДСТВ КРИПТОГРАФИЧЕСКОЙ ЗАЩИТЫ 
 * ИНФОРМАЦИИ НА СООТВЕТСТВИЕ ТРЕБОВАНИЯМ СТБ 34.101.47-2017 МИ.10131.11.01"
 * https://www.oac.gov.by/public/content/files/files/stb/met-10147-11-01.pdf
 */
import { describe, test, expect } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { brngCtr, brngHmac } from ".";
import { H } from "../belt/const";
import { KEY1 } from "../modes/_test_utils.spec";

describe("[CORE] BRNG (STB 34.101.47-2017)", () => {
    test("#1", () => {
        const expected = hexToBytes("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E2694C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D20F51D91347617C20BD4AB07AEF4F26A1AD1362A8F9A3D42FBE1B8E6F1C88AAD5");
        expect(brngCtr(
            KEY1,
            H.subarray(192, 224)
        )(3, H.subarray(0, 192))).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("B010347E3EDCE94B241C866C56BB537071296A2420F30977678FBD8D858593DF39483C678B38A03268D2B317EBAB3D18A67BDF5254B2E7E5EF13C8137E447C6C");
        expect(brngCtr(
            hexToBytes("15987DAD8FC01133C1210F9F1661D14AF9D54F6823C954F19E0212E004E78CF5"),
            hexToBytes("FFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000")
        )(2)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("AF907A0E470A3A1B268ECCCCC0B90F239FE94A2DC6E014179FC789CB3C3887E4695C6B96B84948F8D76924E22260859DB9B5FE757BEDA2E17103EE44655A9FEF648077CCC5002E0561C6EF512C513B8C24B4F3A157221CFBC1597E969778C1E4");
        expect(brngHmac(
            KEY1,
            H.subarray(192, 224)
        )(3)).toStrictEqual(expected);
    });

    test("#4", () => {
        const expected = hexToBytes("6D935875397CABE7D4D32340943A65312E27CC4F692085BE19D9420F165D7E84C234B74689DE8AFB82D6CEE53C508B76B7759E8FF02C2C6DB5492C79FC813CA270C4FBD6D58B158561FB583C72C5069CCBD45798769C1D1F46C092BB7F5CFCB6");
        expect(brngHmac(
            H.subarray(128, 157),
            H.subarray(192, 228)
        )(3)).toStrictEqual(expected);
    });


    test("#5", () => {
        const expected = hexToBytes("92D109E9ABB13DCA7B0403259F2DBD21DA37C38A1B6CACAA6D252A0E6F1E6DD31C45D7D4A483279F35B7BBE23A4C820F5E1CFB842634F429E7E994D1AD3F5B3F164AD1C140351BAE86C320917CC7A00A8EB07D63C49E99FCC52D663570AAC0C6");
        expect(brngHmac(
            KEY1,
            H.subarray(192, 204)
        )(3)).toStrictEqual(expected);
    });

    test("#6", () => {
        const expected = hexToBytes("2AA6EDF29402B9BA0AC87FEC0F55C73AF595B2E6EB93765C5684A75DB012A9921D95B744F8B213F4332852AD3041A61540BE492E4592BD6F68A4EF82E642D9358230CD1D96770EB344E0D2FDE14E2232B3159C655E58D213045BC986BC431B18");
        expect(brngHmac(
            H.subarray(128, 176),
            H.subarray(192)
        )(3)).toStrictEqual(expected);
    });
});