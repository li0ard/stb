import { abytes, anumber, type TArg, type TRet } from "@noble/hashes/utils.js";

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length),
        result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const xorBytesInPlace = (
    dst: TArg<Uint8Array>,
    src: TArg<Uint8Array>,
    off = 0,
    len = dst.length
) => {
    if(len + off > src.length) throw new Error("Uint8Array's must have same length or dst < src");
    for(let i = 0; i < len; i++) dst[i] ^= src[off + i];
}

export const mulC = (block: TArg<Uint32Array>) => {
    const msb = block[3] >>> 31,
        t = (~((msb - 1) >>> 0) & 0x87) >>> 0;
    
    block[3] = ((block[3] << 1) ^ (block[2] >>> 31)) >>> 0;
    block[2] = ((block[2] << 1) ^ (block[1] >>> 31)) >>> 0;
    block[1] = ((block[1] << 1) ^ (block[0] >>> 31)) >>> 0;
    block[0] = ((block[0] << 1) ^ t) >>> 0;
}

export const negBlock = (block: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(block.length);
    for (let i = 0; i < block.length; i++) result[i] = ~block[i];

    return result;
}

const atitle = (title: string): string => title ? `"${title}" ` : '';

export const abytesAligned = (
    value: TArg<Uint8Array>,
    blockSize: number,
    title: string = ""
): TRet<Uint8Array> => {
    abytes(value, undefined, title);
    anumber(blockSize);
    if (value.length !== 0 && value.length % blockSize === 0) return value as TRet<Uint8Array>;
    
    const ofLen = ` of length aligned to ${blockSize}`;
    const got = `length=${value.length}`;
    const message = atitle(title) + 'expected Uint8Array' + ofLen + ', got ' + got;
    throw new RangeError(message);
}

export const splitBlocks = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array[]> => {
    const blocks = [];
    for (let i = 0; i < data.length; i += blockSize) blocks.push(data.subarray(i, i + blockSize));
    return blocks as TRet<Uint8Array[]>;
}