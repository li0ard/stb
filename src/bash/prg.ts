import { equalBytes, concatBytes, copyBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { F } from "./bashf.js";
import { bytesToUint64sBE, uint64sToBytesBE } from "../utils.js";
import type { AEADMode } from "../types.js";

const BASH_PRG_NULL = 0x01, // 000000 01
    BASH_PRG_KEY  = 0x05, // 000001 01
    BASH_PRG_DATA = 0x09, // 000010 01
    BASH_PRG_TEXT = 0x0D, // 000011 01
    BASH_PRG_OUT  = 0x11; // 000100 01

const xorInPlace = (dst: TArg<Uint8Array>, src: TArg<Uint8Array>, len: number) => {
    for (let i = 0; i < len; i++) dst[i] ^= src[i];
}

const EMPTY = new Uint8Array(0);

/** Programmable automaton */
export class BashPrg {
    private l = 0;
    private d = 0;
    private s: Uint8Array;
    private pos = 0;
    private buf_len = 0;
    private started = false;

    constructor() {
        this.s = new Uint8Array(192);
    }

    get isKeymode(): boolean {
        return 16 * (192 - this.buf_len) === this.l * (2 + this.d);
    }

    clone(): BashPrg {
        const to = new BashPrg();
        to.l = this.l;
        to.d = this.d;
        to.s.set(this.s);
        to.pos = this.pos;
        to.buf_len = this.buf_len;
        to.started = this.started;

        return to;
    }

    private process() {
        const words = bytesToUint64sBE(this.s);
        F(words);
        this.s.set(uint64sToBytesBE(words));
    }

    private commit(code: number) {
        if (!this.started)
            throw new Error("prg: Automaton isn't initialized");
        if (this.pos >= this.buf_len)
            throw new Error("prg: pos >= buf_len");
        this.s[this.pos] ^= code;
        this.s[this.buf_len] ^= 0x80;
        this.process();
        this.pos = 0;
    }

    start(
        l: number, d: number, 
        ann: TArg<Uint8Array> = EMPTY,
        key: TArg<Uint8Array> = EMPTY
    ): this {
        if (l !== 128 && l !== 192 && l !== 256)
            throw new Error("prg: l must be 128, 192 or 256");
        if (d !== 1 && d !== 2)
            throw new Error("prg: d must be 1 or 2");
        if (ann.length % 4 !== 0 || ann.length > 60)
            throw new Error("prg: Incorrect announcement length");
        if (key.length % 4 !== 0 || key.length > 60)
            throw new Error("prg: Incorrect key length");
        if (key.length !== 0 && key.length < l / 8)
            throw new Error("prg: Incorrect key length");
 
        this.pos = 1 + ann.length + key.length;
 
        this.s = new Uint8Array(192);
        this.s[0] = (ann.length * 4 + key.length / 4) & 0xff;
        this.s.set(ann, 1);
        this.s.set(key, 1 + ann.length);
        this.s[184] = (l / 4 + d) & 0xff;
 
        this.buf_len = key.length
            ? 192 - (l * (2 + d)) / 16
            : 192 - (d * l) / 4;
 
        this.l = l;
        this.d = d;
        this.started = true;
        return this;
    }

    restart(
        ann: TArg<Uint8Array> = EMPTY,
        key: TArg<Uint8Array> = EMPTY
    ): this { 
        if (!this.started)
            throw new Error("prg: Automaton isn't initialized");
        if (ann.length % 4 !== 0 || ann.length > 60)
            throw new Error("prg: Incorrect announcement length");
        if (key.length % 4 !== 0 || key.length > 60)
            throw new Error("prg: Incorrect key length");
        if (key.length !== 0 && key.length < this.l / 8)
            throw new Error("prg: Incorrect key length");
 
        if (key.length) {
            this.commit(BASH_PRG_KEY);
            this.buf_len = 192 - (this.l * (2 + this.d)) / 16;
        }
        else this.commit(BASH_PRG_NULL);
 
        this.pos = 1 + ann.length + key.length;
        this.s[0] ^= (ann.length * 4 + key.length / 4) & 0xff;
        xorInPlace(this.s.subarray(1), ann, ann.length);
        xorInPlace(this.s.subarray(1 + ann.length), key, key.length);
        return this;
    }

    absorb(buf: TArg<Uint8Array>): this {
        this.commit(BASH_PRG_DATA);
        let off = 0, count = buf.length;
 
        if (count < this.buf_len - this.pos) {
            xorInPlace(this.s.subarray(this.pos), buf, count);
            this.pos += count;
            return this;
        }
        xorInPlace(
            this.s.subarray(this.pos),
            buf.subarray(0, this.buf_len - this.pos),
            this.buf_len - this.pos
        );
        off += this.buf_len - this.pos;
        count -= this.buf_len - this.pos;
        this.process();
 
        while (count >= this.buf_len) {
            xorInPlace(this.s, buf.subarray(off, off + this.buf_len), this.buf_len);
            off += this.buf_len;
            count -= this.buf_len;
            this.process();
        }
 
        this.pos = count;
        if (count) xorInPlace(this.s, buf.subarray(off, off + count), count);
        return this;
    }

    // count in bytes
    squeeze(count: number): TRet<Uint8Array> {
        this.commit(BASH_PRG_OUT);
        const out = new Uint8Array(count);
        let off = 0, remaining = count;
 
        if (remaining < this.buf_len - this.pos) {
            out.set(this.s.subarray(this.pos, this.pos + remaining));
            this.pos += remaining;
            return out;
        }
        out.set(this.s.subarray(this.pos, this.buf_len), 0);
        off += this.buf_len - this.pos;
        remaining -= this.buf_len - this.pos;
        this.process();
 
        while (remaining >= this.buf_len) {
            out.set(this.s.subarray(0, this.buf_len), off);
            off += this.buf_len;
            remaining -= this.buf_len;
            this.process();
        }
 
        this.pos = remaining;
        if (remaining) out.set(this.s.subarray(0, remaining), off);
        return out;
    }

    encrypt(buf: TArg<Uint8Array>): TRet<Uint8Array> {
        if(buf.length == 0) return EMPTY;
        if (!this.isKeymode)
            throw new Error("prg: encrypt is for key-mode only");
        this.commit(BASH_PRG_TEXT);
        const out = new Uint8Array(buf.length);
        let off = 0, count = buf.length;
 
        if (count < this.buf_len - this.pos) {
            xorInPlace(this.s.subarray(this.pos), buf, count);
            out.set(this.s.subarray(this.pos, this.pos + count));
            this.pos += count;
            return out;
        }

        xorInPlace(
            this.s.subarray(this.pos), 
            buf.subarray(0, this.buf_len - this.pos), 
            this.buf_len - this.pos
        );
        out.set(this.s.subarray(this.pos, this.buf_len), 0);

        off += this.buf_len - this.pos;
        count -= this.buf_len - this.pos;
        this.process();
 
        while (count >= this.buf_len) {
            xorInPlace(this.s, buf.subarray(off, off + this.buf_len), this.buf_len);
            out.set(this.s.subarray(0, this.buf_len), off);
            off += this.buf_len;
            count -= this.buf_len;
            this.process();
        }
 
        this.pos = count;
        if (count) {
            xorInPlace(this.s, buf.subarray(off, off + count), count);
            out.set(this.s.subarray(0, count), off);
        }
        return out;
    }

    decrypt(buf: TArg<Uint8Array>): TRet<Uint8Array> {
        if(buf.length == 0) return EMPTY;
        if (!this.isKeymode)
            throw new Error("prg: decrypt is for key-mode only");
        this.commit(BASH_PRG_TEXT);
        const out = new Uint8Array(buf.length);
        let off = 0, count = buf.length;
 
        if (count < this.buf_len - this.pos) {
            for (let i = 0; i < count; i++) out[i] = buf[i] ^ this.s[this.pos + i];
            this.s.set(buf.subarray(0, count), this.pos);
            this.pos += count;
            return out;
        }

        for (let i = 0; i < this.buf_len - this.pos; i++)
            out[i] = buf[i] ^ this.s[this.pos + i];
        this.s.set(buf.subarray(0, this.buf_len - this.pos), this.pos);

        off += this.buf_len - this.pos;
        count -= this.buf_len - this.pos;
        this.process();
 
        while (count >= this.buf_len) {
            for (let i = 0; i < this.buf_len; i++) out[off + i] = buf[off + i] ^ this.s[i];
            this.s.set(buf.subarray(off, off + this.buf_len), 0);
            off += this.buf_len;
            count -= this.buf_len;
            this.process();
        }
 
        this.pos = count;
        if (count) {
            for (let i = 0; i < count; i++) out[off + i] = buf[off + i] ^ this.s[i];
            this.s.set(buf.subarray(off, off + count), 0);
        }
        return out;
    }

    ratchet(): this {
        const t = copyBytes(this.s);
        this.commit(BASH_PRG_NULL);
        xorInPlace(this.s, t, this.s.length);

        return this;
    }
 
    destroy() {
        this.s.fill(0);
        this.started = false;
    }
}

export const prgHash = (
    l: number, d: number,
    msg: TArg<Uint8Array>,
    ann?: TArg<Uint8Array>
): TRet<Uint8Array> => new BashPrg().start(l, d, ann).absorb(msg).squeeze(l / 4);

export const prgAead = (
    l: number, d: number,
    key: TArg<Uint8Array>,
    ann?: TArg<Uint8Array>
): AEADMode => Object.freeze({
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
        const prg = new BashPrg().start(l, d, ann, key);
        if(aad && aad.length > 0) prg.absorb(aad);

        return concatBytes(prg.encrypt(plaintext), prg.squeeze(l / 8));
    },
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
        const prg = new BashPrg().start(l, d, ann, key);
        if(aad && aad.length > 0) prg.absorb(aad);

        const plaintext = prg.decrypt(ciphertext.subarray(0, -l / 8));
        if(!equalBytes(ciphertext.subarray(-l / 8), prg.squeeze(l / 8)))
            throw new Error("Invalid MAC");

        return plaintext;
    }
});