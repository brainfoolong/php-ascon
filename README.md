# PHP Implementation of Ascon

[![Tests](https://github.com/brainfoolong/php-ascon/actions/workflows/tests.yml/badge.svg)](https://github.com/brainfoolong/php-ascon/actions/workflows/tests.yml)

This is a PHP implementation of Ascon v1.3, an authenticated cipher and hash function.
It allows to encrypt and decrypt any kind of message. Includes the authenticated encryption and hash function variants as specified in [NIST SP 800-232 (initial public draft)](https://csrc.nist.gov/pubs/sp/800/232/ipd).
Heavily inspired by the python implementation of Ascon by https://github.com/meichlseder/pyascon

> Notice: This library does contain the version 1.3 of Ascon. v1.2 was a draft version and there are already newer versions of ascon. See https://github.com/ascon/ascon-c . Version 1.2 is not compatible with 1.3

## About Ascon

Ascon is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AEAD)
and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy
to implement, even with added countermeasures against side-channel attacks.
It was designed by a team of cryptographers from Graz University of Technology, Infineon Technologies, and Radboud
University: Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer.

Ascon has been selected as the standard for lightweight cryptography in
the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography) and
as the primary choice for lightweight authenticated encryption in the final portfolio of
the [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html).

Find more information, including the specification and more implementations here:

https://ascon.iaik.tugraz.at/

## About me

I have made library for AES PHP/JS encryption already in the past. Bit juggling is somewhat cool, in a really nerdy way.
I like the Ascon implementation and it at the time of writing, a PHP implementation was missing. So i made one. Would be
cool if you leave a follow or spend some virtual coffee.
s
## Javascript/Typescript Implementation
Chances are high that you probably need a Javascript/Typescript (For your frontend) implementation too. I've made one here -> https://github.com/brainfoolong/js-ascon

## Installation

    # via composer
    composer require brainfoolong/php-ascon

## Performance
As [PHP do not support unsigned integers](https://www.php.net/manual/en/language.types.integer.php), there is no chance to directly work with 64bit unsigned integers. This library use 2x 32bit integers for all bit operations, which have performance penalties (almost half as fast as the typescript implementation). Without requiring specials php extensions which can handle 64bit unsigned integers, there is no way to improve the performance for now.

## Usage

For more demos see in folder `demo`.

```php
use Nullix\Ascon\Ascon;
// convenient usage (generating random nonce and hashing keys for you)
$key = "mypassword";
$message = ["this can be any data type 😎 文 or encoding", 123];
$associatedData = "Some data 😋 文 This data is not contained in the encrypt output but must be passed to both encrypt and decrypt.";
$encrypted = Ascon::encryptToHex($key, $message, $associatedData);
$decrypted = Ascon::decryptFromHex($key, $encrypted, $associatedData);

// raw usage of basic methods
// key must be 16 bytes or 20 bytes, depending on variant
$key = [0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xEF];
// nonce must be 16 bytes and should always be random bytes, you must use same nonce for encrypt and decrypt the same message
$nonce = random_bytes(16);
// this is the text you want to encrypt
$plaintext = "Hi, i am a secret message!";
// associated data is not being encrypted, but is taken into account in the ciphertext
// this means, you can only decrypt when you pass the exact same associated data to the decrypt function as well
// so you can make sure that associated data and plaintext is not manipulated for given encrypted message
// this is optional and can be an empty string
$associatedData = "Some data to pass to encryption and decryption - This data is not contained in the ciphertext output.";
$ciphertextByteArray = Ascon::encrypt($key, $nonce, $associatedData, $plaintext);
$plaintextDecrypted = Ascon::decrypt($key, $nonce, $associatedData, $ciphertextByteArray);

var_dump(Ascon::hash('Testmessage'));
var_dump(Ascon::mac($key, 'Testmessage'));
```

## Development
Change code in `src/Ascon.php`. Test changes with `php tests/tests.php`.

## Algorithms

This is a simple reference implementation of Ascon as specified in NIST's draft standard, NIST SP 800-232, which includes

* Authenticated encryption `Ascon::encrypt` and `Ascon::decrypt`

  - `Ascon-AEAD128`

* Hashing algorithms `Ascon::hash` including 3 hash function variants with slightly different interfaces:

  - `Ascon-Hash256` with fixed 256-bit output
  - `Ascon-XOF128` with variable output lengths (specified with `hashlength`)
  - `Ascon-CXOF128` with variable output lengths (`hashlength`) and supporting a customization string as an additional input (to be implemented)

* Message Authentication Code `Ascon::mac`

  - `Ascon-Mac` (128-bit output, arbitrarily long input),
  - `Ascon-Prf` (arbitrarily long input and output),
  - `Ascon-PrfShort` (t-bit output for t<=128, m-bit input for m<=128)


## Older Algorithm Variants

Older versions implement Ascon v1.2 as submitted to the NIST LWC competition and published in the Journal of Cryptology, as well as additional functionality for message authentication. These versions can be found in at https://github.com/brainfoolong/php-ascon/tree/412dd162b737c212829c95787e7a4801fec7629e, including

* Authenticated encryption:

  - `Ascon-128`
  - `Ascon-128a`
  - `Ascon-80pq`

* Hashing algorithms:

  - `Ascon-Hash`
  - `Ascon-Hasha`
  - `Ascon-Xof`
  - `Ascon-Xofa`

* Message authentication codes `ascon_mac(key, message, variant="Ascon-Mac", taglength=16)` for 5 MAC variants (from https://eprint.iacr.org/2021/1574, not part of the LWC proposal) with fixed 128-bit (`Mac`) or variable (`Prf`) output lengths, including a variant for short messages of up to 128 bits (`PrfShort`).

  - `Ascon-Mac`
  - `Ascon-Maca`
  - `Ascon-Prf`
  - `Ascon-Prfa`
  - `Ascon-PrfShort`ort`