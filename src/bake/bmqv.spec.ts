import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { bmqv128, bmqv192, bmqv256 } from "./bmqv";
import { bign128, bign192, bign256 } from "../bign";
import type { ECDSA, ECKE } from "../types";

type Side = {
    secretKey: Uint8Array,
    eSecret: Uint8Array,
    id?: Uint8Array
}

const performTest = (
    bake: ECKE,
    signer: ECDSA,
    sideA: Side,
    sideB: Side,
    expectedK: TRet<Uint8Array>,
    expectedTa: TRet<Uint8Array>,
    expectedTb: TRet<Uint8Array>
) => {
    const pubA = signer.getPublicKey(sideA.secretKey),
        pubB = signer.getPublicKey(sideB.secretKey),
        ePublicA = signer.getPublicKey(sideA.eSecret),
        ePublicB = signer.getPublicKey(sideB.eSecret);
    
    const resultA = bake.runA(sideA.secretKey, pubB, sideA.eSecret, ePublicB, sideA.id, sideB.id);
    const resultB = bake.runB(sideB.secretKey, pubA, sideB.eSecret, ePublicA, sideA.id, sideB.id);

    expect(resultA.K).toStrictEqual(resultB.K);
    expect(resultA.Ta).toStrictEqual(resultB.Ta);
    expect(resultA.Tb).toStrictEqual(resultB.Tb);

    expect(resultA.K).toStrictEqual(expectedK);
    expect(resultA.Ta).toStrictEqual(expectedTa);
    expect(resultA.Tb).toStrictEqual(expectedTb);
}

const IDA = hexToBytes("416C696365"), IDB = hexToBytes("426F62"),
    HELLOA = hexToBytes("01000000"), HELLOB = hexToBytes("02000000");

describe("[BAKE] BMQV", () => {
    test("#1", () => performTest(
        bmqv128(),
        bign128,
        {
            secretKey: hexToBytes("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269"),
            eSecret: hexToBytes("0A4E8298BE0839E46F19409F637F4415572251DD0D39284F0F0390D93BBCE9EC"),
            id: IDA
        },
        {
            secretKey: hexToBytes("4C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D2"),
            eSecret: hexToBytes("0F51D91347617C20BD4AB07AEF4F26A1AD1362A8F9A3D42FBE1B8E6F1C88AAD5"),
            id: IDB
        },
        hexToBytes("C6F86D0E468D5EF1A9955B2EE0CF0581050C81D1B47727092408E863C7EEB48C"),
        hexToBytes("413B7E181BAFB337"),
        hexToBytes("B800A2033AC7591B")
    ));

    test("#2", () => performTest(
        bmqv128(HELLOA, HELLOB),
        bign128,
        {
            secretKey: hexToBytes("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269"),
            eSecret: hexToBytes("03A9C8924C62F55AE5B35AF26DCCFCFAAAB463E48240361B9A222D58AEA41C59"),
            id: IDA
        },
        {
            secretKey: hexToBytes("4C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D2"),
            eSecret: hexToBytes("74106FD8BF66153575B6A66125D95D5775299C1CB2C84B6C71E581F36FD72C6E"),
            id: IDB
        },
        hexToBytes("67EFDF3CB438BCABE5A6CE9CB070E7B38FCA42625D12A6175E94E56CD98E4964"),
        hexToBytes("36C3AAA6B89104D9"),
        hexToBytes("13A60B900787F545")
    ));

    test("#3", () => performTest(
        bmqv192(),
        bign192,
        {
            secretKey: hexToBytes("84C21DBF7B3C2372DC21386C216FA16C9EF10AEAF9F96A872FD8058F2780BA930F08BE3BEC80416137E11A232D93B50E"),
            eSecret: hexToBytes("CEDE358DF0C77FC065235DDFF9AA1B81CECE89D9ECBFF573323A7BDEDB9E0EBE61F342A9229DF1E172DA68C576360070"),
            id: IDA
        },
        {
            secretKey: hexToBytes("5DBFB5CCE18A214E66D2ED80E966F8D961B3924EFB8E2DD9A4881E0F8630D9693A80338931CC9F6665453BE824ACBDD6"),
            eSecret: hexToBytes("93FC994C1622E4784B211FD9460746F9888FDB486D6CD8DCF1F199BD25A359FB03CD9C9354C613BD39167391D17AE5C3"),
            id: IDB
        },
        hexToBytes("B3DEC2C2A4227AF7FAC14C53A11CA5330698DC5C502A7464431D265BC3DA77E8"),
        hexToBytes("CF5CB42C5A3D0045"),
        hexToBytes("89D237306949A4AF")
    ));

    test("#4", () => performTest(
        bmqv192(HELLOA, HELLOB),
        bign192,
        {
            secretKey: hexToBytes("84C21DBF7B3C2372DC21386C216FA16C9EF10AEAF9F96A872FD8058F2780BA930F08BE3BEC80416137E11A232D93B50E"),
            eSecret: hexToBytes("E5A8A315D5FC929BC85D86CD51382970C67CCDEC2F1ECFE72DB0D3A98EE7032887EA9CFAE93EE1EB5150C894843D146D"),
            id: IDA
        },
        {
            secretKey: hexToBytes("5DBFB5CCE18A214E66D2ED80E966F8D961B3924EFB8E2DD9A4881E0F8630D9693A80338931CC9F6665453BE824ACBDD6"),
            eSecret: hexToBytes("D20C31AF7B69378D263B8B8A01FAEB877FDD1FE7697797D2BBF3ED15D057D951EBBE8AB848B3E582A2FDEE9CAEE02D87"),
            id: IDB
        },
        hexToBytes("8675155791D2B9E3378A4BAD59B7EB94C500774D2DD260A87EF9D90F7909BBF3"),
        hexToBytes("A0DB12F215221635"),
        hexToBytes("3AD2F00C10890981")
    ));

    test("#5", () => performTest(
        bmqv256(),
        bign256,
        {
            secretKey: hexToBytes("BEC096353EF4568AA417622A95F2B56333BF3A02040B31372FD5737DE0F1A2BA6090C1D1A27155D8711FFE5B310278471B0B97CF1B8FE821C50205E5D24AB9B8"),
            eSecret: hexToBytes("F5EEE4391975B857A7B32632739E177BD4B0EF10E88CF83A39757B6D5589AB94CBECDEBE55D80F294B873426603DCC4D3789FB7118981A907296E352B1704B6C"),
            id: IDA
        },
        {
            secretKey: hexToBytes("213B96E9F90CDFD4BC21DB8B59879176D7347248107E66C71438B14FFFB692B8637E5B6E04C41DF55868299D811F4381BE31657ACF601BDDAE57AB5B238CA112"),
            eSecret: hexToBytes("1D3B400CA3C39E7B5E592AABF224C1FDDFAEA9F95CF1844A2A31B095027E498770E70190A97B1CC063F396A6F2A0BDA1F0CCED0CAF5BD4BE219C1E8831AA3E50"),
            id: IDB
        },
        hexToBytes("CEEB4010317F302FDA4D19BD5E5D1B75D36EA0809F2F260771B0BEE31F84641A"),
        hexToBytes("43949C4B768906F4"),
        hexToBytes("BD71BC3439F57A26")
    ));

    test("#6", () => performTest(
        bmqv256(HELLOA, HELLOB),
        bign256,
        {
            secretKey: hexToBytes("BEC096353EF4568AA417622A95F2B56333BF3A02040B31372FD5737DE0F1A2BA6090C1D1A27155D8711FFE5B310278471B0B97CF1B8FE821C50205E5D24AB9B8"),
            eSecret: hexToBytes("B445E147A6CFB36B20BBFC60CE47DDC8384EA56F63CB05FDB6201CD6FC4ADAA9C02B61ABA5EC0FBCEA27C0A9C4ABB182B76CD73DD54D3E601036165917AF5AF9"),
            id: IDA
        },
        {
            secretKey: hexToBytes("213B96E9F90CDFD4BC21DB8B59879176D7347248107E66C71438B14FFFB692B8637E5B6E04C41DF55868299D811F4381BE31657ACF601BDDAE57AB5B238CA112"),
            eSecret: hexToBytes("E589556153013331FACF526CCF4C4ED822325841CA78A2268DF6462257607E36F35917EA75245A934208795D83991372CBDDE69996727E0ABBFDB33F1C600537"),
            id: IDB
        },
        hexToBytes("31972DA71DEF23AD37766963A329DB54DE2368A70E3B43F2B1BB7332224323FD"),
        hexToBytes("B8F3A0C2F4EBB6D0"),
        hexToBytes("A637885C00AF7713")
    ));
});