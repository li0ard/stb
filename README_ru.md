<p align="center">
    <b>@li0ard/stb</b><br>
    <b>Алгоритмы СТБ на чистом TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/stb">документация</a>
    <br><br>
    <a href="https://github.com/li0ard/stb/actions/workflows/test.yml"><img src="https://github.com/li0ard/stb/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/stb/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/stb" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/stb"><img src="https://img.shields.io/npm/v/@li0ard/stb" /></a>
    <br>
    <hr>
</p>

## Установка

```bash
npm i @li0ard/stb
```

## Поддерживаемые алгоритмы

- Протокол выработки общего секрета "BMQV" (СТБ 34.101.66)
- Эллиптические кривые и ЭП "Bign" (СТБ 34.101.45)
    - Детерминированные подписи
    - Транспорт ключа
- Хэш-функция "Bash" (СТБ 34.101.77)
    - Поддерживает программируемые автоматы (хэширование, AEAD-шифрование)
- Шифр "BelT" (СТБ 34.101.31)
    - Поддерживает хэш-функцию (а также HMAC)
- Генератор псевдослучайных чисел "Brng" (СТБ 34.101.47)
    - Поддерживает HOTP/TOTP генератор

## Поддерживаемые режимы шифров

- AEAD-шифрование (DWP/CHE)
- Режим сцепления блока (CBC)
- Режим гаммирования с обратной связью (CFB)
- Функция сжатия
- Режим счётчика (CTR)
- Режим дискового шифрования (BDE/SDE)
- Режим простой замены (ECB)
- Режим шифрования ключа (KWP)
- Режим выработки имитовставки (MAC)
- Режим шифрования широкого блока (WBL)