import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import type { TArg, TRet } from "@noble/hashes/utils.js";

export const bytesToUint64sBE = (b: TArg<Uint8Array>): TRet<BigUint64Array> => {
    const size = Math.floor(b.length / 8);
    const result = new BigUint64Array(size);
    
    for (let i = 0; i < size; i++) result[i] = bytesToNumberBE(b.subarray(i * 8, i * 8 + 8));
    return result;
}

export const uint64sToBytesBE = (w: TArg<BigUint64Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(w.length * 8);
    for (let i = 0; i < w.length; i++) result.set(numberToBytesBE(w[i], 8), i * 8);
    return result;
}

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const getPadLength = (dataLength: number, blockSize: number): number => {
    if(dataLength < blockSize) return blockSize - dataLength;
    if(dataLength % blockSize == 0) return 0;
    return blockSize - dataLength % blockSize;
}

export const mulC = (block: TArg<Uint32Array>) => {
    const msb = block[3] >>> 31;
    const t = (~((msb - 1) >>> 0) & 0x87) >>> 0;
    
    block[3] = ((block[3] << 1) ^ (block[2] >>> 31)) >>> 0;
    block[2] = ((block[2] << 1) ^ (block[1] >>> 31)) >>> 0;
    block[1] = ((block[1] << 1) ^ (block[0] >>> 31)) >>> 0;
    block[0] = ((block[0] << 1) ^ t) >>> 0;
}

export const negBlock = (block: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(block.length);
    for (let i = 0; i < block.length; i++) result[i] = ~block[i] & 0xFF;

    return result;
}