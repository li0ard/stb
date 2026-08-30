import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Belt, keyExpand, keyTransform } from ".";
import { KEY1, KEY2 } from "../modes/_test_utils.spec";
import { H } from "./const";

describe("[CORE] BelT (STB 34.101.31)", () => {
    test("#1", () => {
        const key = KEY1;
        const pt = H.subarray(0,16);
        const ct = hexToBytes("69CCA1C93557C9E3D66BC3E0FA88FA6E");
        const cipher = new Belt(key);

        expect(cipher.encrypt(pt)).toStrictEqual(ct);
        expect(cipher.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2", () => {
        const key = KEY2;
        const pt = hexToBytes("0DC5300600CAB840B38448E5E993F421");
        const ct = H.subarray(64,80);
        const cipher = new Belt(key);

        expect(cipher.encrypt(pt)).toStrictEqual(ct);
        expect(cipher.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[BelT] Key expand", () => {
    test("#1", () => {
        const key = hexToBytes("2033394D6C320D0965201A166E62001D6779410674740E136865160D3D730C11");
        const expected = hexToBytes("2033394D6C320D0965201A166E62001D6779410674740E136865160D3D730C11");

        expect(keyExpand(key)).toStrictEqual(expected);
    });

    test("#2", () => {
        const key = hexToBytes("348724A4C1A67667153DDE5933884250E3248C657D413B8C");
        const expected = hexToBytes("348724A4C1A67667153DDE5933884250E3248C657D413B8CE01C8C9AADEDF5B9");

        expect(keyExpand(key)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("E9DEE72C8F0C0FA62DDB49F46F739647E9DEE72C8F0C0FA62DDB49F46F739647");

        expect(keyExpand(H.subarray(128, 144))).toStrictEqual(expected);
    });
});

describe("[BelT] Key transform", () => {
    const lvl = hexToBytes("010000000000000000000000");
    const iv1 = hexToBytes("919ADA9067B9279EB514BEA13F8F2CA8");
    const iv2 = hexToBytes("9DEADEC2621747A62A80A7C3FFA8E347");
    const iv3 = hexToBytes("D097E3AF21DC4B8891688A84E9A05C51");
    const key1 = hexToBytes("2033394D6C320D0965201A166E62001D6779410674740E136865160D3D730C11");
    const key2 = hexToBytes("348724A4C1A67667153DDE5933884250E3248C657D413B8C");

    test("#1", () => {
        const expected = hexToBytes("39B22F1AEB3BDA3AF2D15C9EF4D7E1B9E04CBB98FEE03A03E521CE4BDA191B38");
        expect(keyTransform(key1, lvl, iv1, 32)).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("59A50D2BEA321BCE681B21B3B745345A2F642D5A7C68C4DC");
        expect(keyTransform(key1, lvl, iv2, 24)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("88743329791EE70CBE6B3438FEAC2FB4");
        expect(keyTransform(key1, lvl, iv3, 16)).toStrictEqual(expected);
    });

    test("#4", () => {
        const expected = hexToBytes("BFCBEAA05620BA4FA04AE7CD482F7B9715FBBF63459B1C66");
        expect(keyTransform(key2, lvl, iv1, 24)).toStrictEqual(expected);
    });

    test("#5", () => {
        const expected = hexToBytes("9D8152A7EE9DDDC9B42161FE1FFB8C84");
        expect(keyTransform(key2, lvl, iv2, 16)).toStrictEqual(expected);
    });

    test("#6", () => {
        const expected = hexToBytes("5285AB0AEE08A2A54AF512332E04C8B2");
        expect(keyTransform(H.subarray(128, 144), lvl, iv3, 16)).toStrictEqual(expected);
    });
});