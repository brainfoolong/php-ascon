# PHP Implementation of Ascon

[![Tests](https://github.com/brainfoolong/php-ascon/actions/workflows/tests.yml/badge.svg)](https://github.com/brainfoolong/php-ascon/actions/workflows/tests.yml)

This is a PHP 8+ implementation of Ascon v1.2, an authenticated cipher and hash function.
It allows to encrypt and decrypt any kind of message. At kind be somewhat seen as the successor to AES encryption.
Heavily inspired by the python implementation of Ascon by https://github.com/meichlseder/pyascon

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

I have made library for AES PHP/JS encryption already in the past. Bit juggling is somewhat cool, i a really nerdy way.
I like the Ascon implementation and it at the time of writing, a PHP implementation was missing. So i made one. Would be
cool if you leave a follow or spend some virtual coffee.

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

// raw usage (the original implementation with raw values)
$key = [0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xEF];
$nonce = [0x50, 0x10, 0x30, 0x70, 0x90, 0x60, 0x40, 0x30, 0xEF, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0xCC];
$plaintext = "Hi, i am a secret message!";
$associatedData = "Some data the will not be encrypted but verified along the plaintext (Decryption will fail if you not provide the exact same data)";
$ciphertextByteArray = Ascon::encrypt($key, $nonce, $associatedData, $plaintext);
$plaintextDecrypted = Ascon::decrypt($key, $nonce, $associatedData, $ciphertextByteArray);
```

## Performance and PHP limitations (No showstopper, but you should take notice)

Ascon requires 64bit unsigned integers. PHP does NOT have 64bit unsigned integers, it only have signed 64bit integers.
So, by default we miss one bit for a full unsigned 64bit number (Because the 64th bit is used for the sign instead of
the last number bit). Php internally translates a full used 64bit number to float, which is a mess and don't work
because you loose data because of floating point precision limitation.

But no fear, in this implementation i have used 2x 32bit integers internally. This have some performance impact, because
more operations need to be done to get the same result as with uint 64 bit.
If you need top notch performance for a lot of encrypt/decrypt, i always recommend that you not use PHP for such jobs.
Use the native C implementation, which is a lot faster. You can embed that with FFI as of PHP 8.2.

However, you are probably here because you need it to integrate it in your webservice application.
For this cases, the performance should be fine.

See `tests/performance.php` for some tests with various message data size.

```
# no scientific tests, just executed on my local machine, results depend on your machine
# a "cycle" is one encryption and one decryption 

### 10 cycles with 64 byte message data and 256 byte associated data ###
Total Time: 0.07 seconds
Memory Usage: 2MB

### 10 cycles with 256 byte message data and 1024 byte associated data ###
Total Time: 0.21 seconds
Memory Usage: 2MB

### 10 cycles with 2048 byte message data and 4096 byte associated data ###
Total Time: 0.92 seconds
Memory Usage: 2MB

### 10 cycles with 8192 byte message data and 0 byte associated data ###
Total Time: 1.34 seconds
Memory Usage: 4MB
```

## Implemented Algorithms

This is a simple reference implementation of Ascon v1.2 as submitted to the NIST LWC competition that includes

* Authenticated encryption/decryption with the following 3 variants:

    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`

* Hashing algorithms including 4 hash function variants with fixed 256-bit (`Hash`) or variable (`Xof`) output lengths:

    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`

* Message authentication codes including 5 MAC variants (from https://eprint.iacr.org/2021/1574, not part of the LWC
  proposal) with fixed 128-bit (`Mac`) or variable (`Prf`) output lengths, including a variant for short messages of up
  to 128 bits (`PrfShort`).

    - `Ascon-Mac`
    - `Ascon-Maca`
    - `Ascon-Prf`
    - `Ascon-Prfa`
    - `Ascon-PrfShort`