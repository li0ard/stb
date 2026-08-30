<p align="center">
    <b>@li0ard/stb</b><br>
    <b>STB cryptography algorithms in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/stb">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/stb/actions/workflows/test.yml"><img src="https://github.com/li0ard/stb/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/stb/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/stb" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/stb"><img src="https://img.shields.io/npm/v/@li0ard/stb" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
npm i @li0ard/stb
```

## Supported algorithms

- Curves and ECDSA (STB 34.101.45)
    - Determenistic signatures
    - Key transport algorithm
- Bash hash function (STB 34.101.77)
    - Supports programmable automatons (hashing, AEAD encryption)
- BelT cipher (STB 34.101.31)
    - Supports hash function over BelT (with HMAC)
- Brng pseudorandom number generator (STB 34.101.47)
    - Supports HOTP/TOTP generator

## Supported cipher modes

- AEAD modes (DWP/CHE)
- Cipher Block Chaining mode (CBC)
- Cipher Feedback mode (CFB)
- Compress function
- Counter mode (CTR)
- Disk encryption (BDE/SDE)
- Electronic Codebook mode (ECB)
- Keywrap (KWP)
- Message Authentication Code mode (MAC)
- Wideblock encryption (WBL)