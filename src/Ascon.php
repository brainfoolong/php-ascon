<?php

namespace Nullix\Ascon;

use Exception;

use function array_fill;
use function array_map;
use function array_merge;
use function array_slice;
use function bin2hex;
use function dechex;
use function hex2bin;
use function implode;
use function in_array;
use function is_array;
use function is_bool;
use function json_decode;
use function json_encode;
use function pack;
use function random_bytes;
use function str_pad;
use function substr;
use function var_export;

use const STR_PAD_LEFT;

/**
 * PHP 8+ implementation of Ascon v1.3
 * If you need very good performance, you should consider embed a C module via FFI in PHP
 * I've aimed to provide a library that works out of the box, without modifying php.ini configs
 * Heavily inspired by the python implementation of https://github.com/meichlseder/pyascon
 * @link https://github.com/brainfoolong/php-ascon
 * @author BrainFooLong (Roland Eigelsreiter)
 */
class Ascon
{

    public static bool $debug = false;

    public static bool $debugPermutation = false;

    /**
     * Encrypt any message to a hex string
     * @param string $secretKey Your "password", so to say
     * @param mixed $messageToEncrypt Any type of message, must contain valid utf-8 strings
     * @param mixed|null $associatedData Any type of associated ddata
     * @param string $cipherVariant See self::encrypt()
     * @return string
     */
    public static function encryptToHex(
        string $secretKey,
        mixed $messageToEncrypt,
        mixed $associatedData = null,
        string $cipherVariant = "Ascon-AEAD128"
    ): string {
        $key = self::hash($secretKey, "Ascon-XOF128", 16);
        $nonce = random_bytes(16);
        $ciphertext = self::encrypt(
            $key,
            $nonce,
            $associatedData !== null ? json_encode($associatedData, JSON_THROW_ON_ERROR) : "",
            json_encode($messageToEncrypt, JSON_THROW_ON_ERROR),
            $cipherVariant
        );
        return bin2hex(self::byteArrayToStr($ciphertext)) . bin2hex($nonce);
    }

    /**
     * Decrypt any message from a hex string previously generated with encryptToHex
     * @param string $secretKey Your "password", so to say
     * @param string $hexStr Encrypted output from self::encryptToHex()
     * @param mixed|null $associatedData Any type of associated ddata
     * @param string $cipherVariant See self::decrypt()
     * @return mixed Null indicate unsuccessfull decrypt
     */
    public static function decryptFromHex(
        string $secretKey,
        string $hexStr,
        mixed $associatedData = null,
        string $cipherVariant = "Ascon-AEAD128"
    ): mixed {
        $key = self::hash($secretKey, "Ascon-XOF128", 16);
        $plaintextMessage = self::decrypt(
            $key,
            hex2bin(substr($hexStr, -32)),
            $associatedData !== null ? json_encode($associatedData, JSON_THROW_ON_ERROR) : "",
            hex2bin(substr($hexStr, 0, -32)),
            $cipherVariant
        );
        return $plaintextMessage !== null ? json_decode(self::byteArrayToStr($plaintextMessage), true) : null;
    }

    /**
     * Ascon encryption
     * @param string|array $key A string or byte array of a length 16
     * @param string|array $nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
     * @param string|array $associatedData A string or byte array of any length
     * @param string|array $plaintext A string or byte array of any length
     * @param string $variant "Ascon-AEAD128"
     *   rounds)
     * @return int[] Return encrypted ciphertext and tag as byte array
     */
    public static function encrypt(
        string|array $key,
        string|array $nonce,
        string|array $associatedData,
        string|array $plaintext,
        string $variant = "Ascon-AEAD128"
    ): array {
        $versions = ['Ascon-AEAD128' => 1];
        if (!isset($versions[$variant])) {
            throw new Exception('Unsupported variant');
        }
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $nonce = !is_array($nonce) ? self::strToByteArray($nonce) : $nonce;
        $nonceLength = count($nonce);
        self::assert(
            $keyLength === 16 && $nonceLength === 16,
            'Incorrect key (' . $keyLength . ') or nonce(' . $nonceLength . ') length'
        );
        $data = [];
        $permutationRoundsA = 12;
        $permutationRoundsB = 8;
        $rate = 16;
        self::initialize(
            $data,
            $rate,
            $permutationRoundsA,
            $permutationRoundsB,
            $versions[$variant],
            $key,
            $nonce
        );
        $associatedData = !is_array($associatedData) ? self::strToByteArray($associatedData) : $associatedData;
        self::processAssociatedData($data, $permutationRoundsB, $rate, $associatedData);
        $plaintext = !is_array($plaintext) ? self::strToByteArray($plaintext) : $plaintext;
        $ciphertext = self::processPlaintext($data, $permutationRoundsB, $rate, $plaintext);
        $tag = self::finalize($data, $permutationRoundsA, $rate, $key);
        return array_merge($ciphertext, $tag);
    }

    /**
     * Ascon decryption
     * @param string|array $key A string or byte array of a length of 16 bytes
     * @param string|array $nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
     * @param string|array $associatedData A string or byte array of any length
     * @param string|array $ciphertextAndTag A string or byte array of any length including the tag
     * @param string $variant "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of rounds)
     * @return int[]|null Returns plaintext as byte array or NULL when cannot decrypt
     */
    public static function decrypt(
        string|array $key,
        string|array $nonce,
        string|array $associatedData,
        string|array $ciphertextAndTag,
        string $variant = "Ascon-128"
    ): ?array {
        $versions = ['Ascon-AEAD128' => 1];
        if (!isset($versions[$variant])) {
            throw new Exception('Unsupported variant');
        }
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $nonce = !is_array($nonce) ? self::strToByteArray($nonce) : $nonce;
        $nonceLength = count($nonce);
        self::assert(
            $keyLength === 16 && $nonceLength === 16,
            'Incorrect key (' . $keyLength . ') or nonce(' . $nonceLength . ') length'
        );

        $data = [];
        $permutationRoundsA = 12;
        $permutationRoundsB = 8;
        $rate = 16;
        self::initialize(
            $data,
            $rate,
            $permutationRoundsA,
            $permutationRoundsB,
            $versions[$variant],
            $key,
            $nonce
        );
        $associatedData = !is_array($associatedData) ? self::strToByteArray($associatedData) : $associatedData;
        self::processAssociatedData($data, $permutationRoundsB, $rate, $associatedData);
        $ciphertextAndTag = !is_array($ciphertextAndTag) ? self::strToByteArray($ciphertextAndTag) : $ciphertextAndTag;
        $ciphertext = array_slice($ciphertextAndTag, 0, -16);
        $ciphertextTag = array_slice($ciphertextAndTag, -16);
        $plaintext = self::processCiphertext($data, $permutationRoundsB, $rate, $ciphertext);
        $tag = self::finalize($data, $permutationRoundsA, $rate, $key);
        if ($ciphertextTag === $tag) {
            return $plaintext;
        }
        return null;
    }

    /**
     * Ascon message authentication code (MAC) and pseudorandom function (PRF)
     * @param string|array $key A string or byte array of a length of 16 bytes
     * @param string|array $message A string or byte array (<= 16 for "Ascon-PrfShort")
     * @param string $variant "Ascon-Mac" (128-bit output, arbitrarily long input), "Ascon-Prf" (arbitrarily long input
     *     and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit input for m<=128)
     * @param int $tagLength the requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac" and
     *     "Ascon-PrfShort", arbitrary for "Ascon-Prf"; should be >= 16 for 128-bit security)
     * @return array The byte array representing the authentication tag
     */
    public static function mac(
        string|array $key,
        string|array $message,
        string $variant = "Ascon-Mac",
        int $tagLength = 16
    ): array {
        self::assertInArray(
            $variant,
            ['Ascon-Mac', 'Ascon-Prf', 'Ascon-PrfShort'],
            'Mac variant'
        );
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $message = !is_array($message) ? self::strToByteArray($message) : $message;
        $messageLength = count($message);
        if ($variant === "Ascon-Mac") {
            self::assert($keyLength === 16 && $tagLength <= 16, 'Incorrect key length');
        } elseif ($variant === "Ascon-Prf") {
            self::assert($keyLength === 16, 'Incorrect key length');
        } elseif ($variant === "Ascon-PrfShort") {
            self::assert($messageLength <= 16, 'Message to long for variant ' . $variant);
            self::assert($keyLength === 16 && $tagLength <= 16 && $messageLength <= 16, 'Incorrect key length');
        }
        $permutationRoundsA = 12;
        $permutationRoundsB = 12;
        $messageBlockSize = 32;
        $rate = 16;
        // TODO update IVs to be consistent with NIST format
        if ($variant === 'Ascon-PrfShort') {
            $tmp = array_merge(
                [$keyLength * 8, $messageLength * 8, $permutationRoundsA + 64, $tagLength * 8, 0, 0, 0, 0],
                $key,
                $message,
                array_fill(0, 16 - $messageLength, 0)
            );
            $data = self::byteArrayToStateArray($tmp);
            self::debug("initial value", $data);
            self::permutation($data, $permutationRoundsA);
            self::debug("process message", $data);
            $data[3] = self::bitOperation($data[3], self::byteArrayToIntArray($key, 0), "^");
            $data[4] = self::bitOperation($data[4], self::byteArrayToIntArray($key, 8), "^");
            return array_merge(
                self::intArrayToByteArray($data[3]),
                self::intArrayToByteArray($data[4])
            );
        }
        $tmp = array_merge(
            [$keyLength * 8, $rate * 8, $permutationRoundsA + 128, $permutationRoundsA - $permutationRoundsB],
            self::intToByteArray($variant === 'Ascon-Mac' ? 128 : 0, 4), // tagspec
            $key,
            array_fill(0, 16, 0)
        );
        $data = self::byteArrayToStateArray($tmp);
        self::debug("initial value", $data);
        self::permutation($data, $permutationRoundsA);
        self::debug("initialization", $data);
        // message processing (absorbing)
        $messagePadded = array_merge(
            $message,
            [0x01],
            array_fill(0, $messageBlockSize - ($messageLength % $messageBlockSize) - 1, 0)
        );
        $messagePaddedLength = count($messagePadded);
        // first s-1 blocks
        for ($block = 0; $block < $messagePaddedLength - $messageBlockSize; $block += $messageBlockSize) {
            for ($i = 0; $i < 4; $i++) {
                $data[$i] = self::bitOperation(
                    $data[$i],
                    self::byteArrayToIntArray($messagePadded, $block + ($i * 8)),
                    "^"
                );
            }
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messagePaddedLength - $messageBlockSize;
        for ($i = 0; $i < 4; $i++) {
            $data[$i] = self::bitOperation(
                $data[$i],
                self::byteArrayToIntArray($messagePadded, $block + ($i * 8)),
                "^"
            );
        }
        $data[4] = self::bitOperation(
            $data[4],
            [0x00, 0x01],
            "^"
        );
        self::debug("process message", $data);
        // finalization (squeezing)
        $tag = [];
        self::permutation($data, $permutationRoundsA);
        while (count($tag) < $tagLength) {
            $tag = array_merge(self::intArrayToByteArray($data[0]), self::intArrayToByteArray($data[1]));
            self::permutation($data, $permutationRoundsB);
        }
        self::debug("finalization", $data);
        return $tag;
    }

    /**
     * Ascon hash function and extendable-output function
     * @param string|array $message A string or byte array
     * @param string $variant "Ascon-Hash256" (with 256-bit output for 128-bit security), "Ascon-XOF128", or
     *     "Ascon-CXOF128" (both with arbitrary output length, security=min(128, bitlen/2))
     * @param int $hashLength The requested output bytelength (must be 32 for variant "Ascon-Hash"; can be arbitrary
     *   for Ascon-Xof, but should be >= 32 for 128-bit security)
     * @param array $customization A bytes array of at most 256 bytes specifying the customization string
     *     (only for Ascon-CXOF128)
     * @return array The byte array representing the hash tag
     */
    public static function hash(
        string|array $message,
        string $variant = "Ascon-Hash256",
        int $hashLength = 32,
        array $customization = []
    ): array {
        $versions = [
            'Ascon-Hash256' => 2,
            'Ascon-XOF128' => 3,
            'Ascon-CXOF128' => 4,
        ];
        if (!isset($versions[$variant])) {
            throw new Exception('Unsupported hash variant');
        }
        $tagLength = 0;
        $customize = false;
        if ($variant === 'Ascon-Hash256') {
            self::assert($hashLength === 32, 'Incorrect hash length');
            $tagLength = 256;
        }
        if ($variant === 'Ascon-CXOF128') {
            self::assert(count($customization) <= 256, 'Incorrect customization length');
            $customize = true;
        }
        $permutationRoundsA = 12;
        $permutationRoundsB = 12;
        $rate = 8;
        $iv = array_merge(
            [$versions[$variant], 0, ($permutationRoundsB << 4) + $permutationRoundsA],
            self::intToByteArray($tagLength, 2),
            [$rate, 0, 0]
        );
        $message = !is_array($message) ? self::strToByteArray($message) : $message;
        $messageLength = count($message);
        $data = self::byteArrayToStateArray(
            array_merge(
                $iv,
                array_fill(0, 32, 0)
            )
        );
        self::debug('initial value', $data);
        self::permutation($data, $permutationRoundsA);
        self::debug('initialization', $data);

        // Customization
        if ($customize) {
            $zPadding = array_merge(
                [0x01],
                array_fill(0, $rate - (count($customization) % $rate) - 1, 0)
            );
            $zLength = self::intToByteArray(count($customization) * 8);
            $zPadded = array_merge($zLength, $customization, $zPadding);

            // customization blocks 0,...,m
            for ($block = 0; $block < count($zPadded); $block += $rate) {
                $data[0] = self::bitOperation(
                    $data[0],
                    self::byteArrayToIntArray($zPadded, $block),
                    "^"
                );
                self::permutation($data, $permutationRoundsB);
            }
        }

        // message processing (absorbing)
        $messagePadded = array_merge(
            $message,
            [0x01],
            array_fill(0, $rate - ($messageLength % $rate) - 1, 0)
        );

        $messagePaddedLength = count($messagePadded);
        // message blocks 0,...,n
        for ($block = 0; $block < $messagePaddedLength; $block += $rate) {
            $data[0] = self::bitOperation(
                $data[0],
                self::byteArrayToIntArray($messagePadded, $block),
                "^"
            );
            self::permutation($data, $permutationRoundsB);
        }
        self::debug("process message", $data);
        // finalization (squeezing)
        $hash = [];
        while (count($hash) < $hashLength) {
            $hash = array_merge($hash, self::intArrayToByteArray($data[0]));
            self::permutation($data, $permutationRoundsB);
        }
        self::debug("finalization", $data);
        return array_slice($hash, 0, $hashLength);
    }

    /**
     * Ascon initialization phase - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param int $permutationRoundsA Number of initialization/finalization rounds for permutation
     * @param int $permutationRoundsB Number of intermediate rounds for permutation
     * @param int $version 1 (for Ascon-AEAD128)
     * @param array $key A bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq;
     *   128-bit security)
     * @param array $nonce A bytes object of size 16
     */
    public static function initialize(
        array &$data,
        int $rate,
        int $permutationRoundsA,
        int $permutationRoundsB,
        int $version,
        array $key,
        array $nonce
    ): void {
        $tagLength = 128;
        $iv = array_merge(
            [$version, 0, ($permutationRoundsB << 4) + $permutationRoundsA],
            self::intToByteArray($tagLength, 2),
            [$rate, 0, 0]
        );
        $data = self::byteArrayToStateArray(array_merge($iv, $key, $nonce));
        self::debug('initial value', $data);
        self::permutation($data, $permutationRoundsA);
        $zeroKey = self::byteArrayToStateArray(
            array_merge(
                array_fill(0, 40 - count($key), 0),
                $key
            )
        );
        for ($i = 0; $i <= 4; $i++) {
            $data[$i] = self::bitOperation($data[$i], $zeroKey[$i], "^");
        }
        self::debug('initialization', $data);
    }

    /**
     * Ascon associated data processing phase - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $permutationRoundsB Number of intermediate rounds for permutation
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param array $associatedData A byte array of any length
     * @return void
     */
    public static function processAssociatedData(
        array &$data,
        int $permutationRoundsB,
        int $rate,
        array $associatedData
    ): void {
        if ($associatedData) {
            $messagePadded = array_merge(
                $associatedData,
                [0x01],
                array_fill(0, $rate - (count($associatedData) % $rate) - 1, 0)
            );
            $messagePaddedLength = count($messagePadded);
            for ($block = 0; $block < $messagePaddedLength; $block += $rate) {
                $data[0] = self::bitOperation(
                    $data[0],
                    self::byteArrayToIntArray($messagePadded, $block),
                    "^"
                );
                $data[1] = self::bitOperation(
                    $data[1],
                    self::byteArrayToIntArray($messagePadded, $block + 8),
                    "^"
                );
                self::permutation($data, $permutationRoundsB);
            }
        }
        $data[4] = self::bitOperation(
            $data[4],
            [2147483648, 0],
            "^"
        );
        self::debug('process associated data', $data);
    }

    /**
     * Ascon plaintext processing phase (during encryption) - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $permutationRoundsB Number of intermediate rounds for permutation
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param array $plaintext A byte array of any length
     * @return int[] Returns the ciphertext as byte array
     */
    public static function processPlaintext(
        array &$data,
        int $permutationRoundsB,
        int $rate,
        array $plaintext
    ): array {
        $lastLen = count($plaintext) % $rate;
        $messagePadded = array_merge(
            $plaintext,
            [0x01],
            array_fill(0, $rate - $lastLen - 1, 0)
        );
        $messagePaddedLength = count($messagePadded);
        $ciphertext = [];
        // first t-1 blocks
        for ($block = 0; $block < $messagePaddedLength - $rate; $block += $rate) {
            $data[0] = self::bitOperation(
                $data[0],
                self::byteArrayToIntArray($messagePadded, $block),
                "^"
            );
            $ciphertext = array_merge($ciphertext, self::intArrayToByteArray($data[0]));
            $data[1] = self::bitOperation(
                $data[1],
                self::byteArrayToIntArray($messagePadded, $block + 8),
                "^"
            );
            $ciphertext = array_merge($ciphertext, self::intArrayToByteArray($data[1]));
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messagePaddedLength - $rate;

        $data[0] = self::bitOperation(
            $data[0],
            self::byteArrayToIntArray($messagePadded, $block),
            "^"
        );
        $data[1] = self::bitOperation(
            $data[1],
            self::byteArrayToIntArray($messagePadded, $block + 8),
            "^"
        );
        $ciphertext = array_merge(
            $ciphertext,
            array_slice(self::intArrayToByteArray($data[0]), 0, min(8, $lastLen)),
            array_slice(self::intArrayToByteArray($data[1]), 0, max(0, $lastLen - 8))
        );

        self::debug('process plaintext', $data);
        return $ciphertext;
    }

    /**
     * Ascon plaintext processing phase (during encryption) - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $permutationRoundsB Number of intermediate rounds for permutation
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param array $ciphertext A byte array of any length
     * @return int[] Returns the ciphertext as byte array
     */
    public static function processCiphertext(
        array &$data,
        int $permutationRoundsB,
        int $rate,
        array $ciphertext
    ): array {
        $lastLen = count($ciphertext) % $rate;
        $message = array_merge(
            $ciphertext,
            array_fill(0, $rate - $lastLen, 0)
        );
        $messageLength = count($message);
        $plaintext = [];
        // first t-1 blocks
        for ($block = 0; $block < $messageLength - $rate; $block += $rate) {
            $ci = self::byteArrayToIntArray($message, $block);
            $plaintext = array_merge(
                $plaintext,
                self::intArrayToByteArray(self::bitOperation($data[0], $ci, "^"))
            );
            $data[0] = $ci;
            $ci = self::byteArrayToIntArray($message, $block + 8);
            $plaintext = array_merge(
                $plaintext,
                self::intArrayToByteArray(self::bitOperation($data[1], $ci, "^"))
            );
            $data[1] = $ci;
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messageLength - $rate;
        $padding = array_merge(array_fill(0, $lastLen, 0), [0x01], array_fill(0, $rate - $lastLen - 1, 0));
        $mask = array_merge(array_fill(0, $lastLen, 0), array_fill(0, $rate - $lastLen, 0xFF));

        $ci = self::byteArrayToIntArray($message, $block);
        $plaintextAdd = self::intArrayToByteArray(self::bitOperation($data[0], $ci, "^"));
        $data[0] = self::bitOperation($data[0], self::byteArrayToIntArray($mask, 0), "&");
        $data[0] = self::bitOperation($data[0], $ci, "^");
        $data[0] = self::bitOperation($data[0], self::byteArrayToIntArray($padding, 0), "^");

        $ci = self::byteArrayToIntArray($message, $block + 8);
        $plaintextAdd = array_merge($plaintextAdd, self::intArrayToByteArray(self::bitOperation($data[1], $ci, "^")));
        $data[1] = self::bitOperation($data[1], self::byteArrayToIntArray($mask, 8), "&");
        $data[1] = self::bitOperation($data[1], $ci, "^");
        $data[1] = self::bitOperation($data[1], self::byteArrayToIntArray($padding, 8), "^");

        $plaintext = array_merge(
            $plaintext,
            array_slice($plaintextAdd, 0, $lastLen)
        );

        self::debug('process ciphertext', $data);
        return $plaintext;
    }

    /**
     * Ascon finalization phase - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $permutationRoundsA Number of initialization/finalization rounds for permutation
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param array $key A bytes array of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq;
     *   128-bit security)
     * @return int[] The tag as a byte array
     */
    public static function finalize(
        array &$data,
        int $permutationRoundsA,
        int $rate,
        array $key
    ): array {
        $index = ($rate / 8) | 0;
        $data[$index] = self::bitOperation($data[$index], self::byteArrayToIntArray($key, 0), "^");
        $index++;
        $data[$index] = self::bitOperation($data[$index], self::byteArrayToIntArray($key, 8), "^");
        $index++;
        $data[$index] = self::bitOperation($data[$index], self::byteArrayToIntArray($key, 16), "^");
        self::permutation($data, $permutationRoundsA);
        $data[3] = self::bitOperation($data[3], self::byteArrayToIntArray($key, -16), "^");
        $data[4] = self::bitOperation($data[4], self::byteArrayToIntArray($key, -8), "^");
        self::debug('finalization', $data);
        return array_merge(
            self::intArrayToByteArray($data[3]),
            self::intArrayToByteArray($data[4])
        );
    }

    /**
     * Ascon core permutation for the sponge construction - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $rounds
     */
    public static function permutation(array &$data, int $rounds = 1): void
    {
        self::assert($rounds <= 12, 'Permutation rounds must be <= 12');
        self::debug('permutation input', $data, true);
        for ($round = 12 - $rounds; $round < 12; $round++) {
            // add round constants
            $data[2] = self::bitOperation(
                $data[2],
                [0, 0xf0 - $round * 0x10 + $round * 0x1],
                "^"
            );
            self::debug('round constant addition', $data, true);
            // substitution layer
            $data[0] = self::bitOperation($data[0], $data[4], "^");
            $data[4] = self::bitOperation($data[4], $data[3], "^");
            $data[2] = self::bitOperation($data[2], $data[1], "^");
            $t = [];
            for ($i = 0; $i <= 4; $i++) {
                $t[$i] =
                    self::bitOperation(
                        self::bitOperation($data[$i], [0xffffffff, 0xffffffff], "^"),
                        $data[($i + 1) % 5],
                        "&"
                    );
            }
            for ($i = 0; $i <= 4; $i++) {
                $data[$i] = self::bitOperation(
                    $data[$i],
                    $t[($i + 1) % 5],
                    "^"
                );
            }
            $data[1] = self::bitOperation($data[1], $data[0], "^");
            $data[0] = self::bitOperation($data[0], $data[4], "^");
            $data[3] = self::bitOperation($data[3], $data[2], "^");
            $data[2] = self::bitOperation($data[2], [0xffffffff, 0xffffffff], "^");
            self::debug('substitution layer', $data, true);
            // linear diffusion layer
            $data[0] = self::bitOperation(
                $data[0],
                self::bitOperation(self::bitRotateRight($data[0], 19), self::bitRotateRight($data[0], 28), "^"),
                "^"
            );
            $data[1] = self::bitOperation(
                $data[1],
                self::bitOperation(self::bitRotateRight($data[1], 61), self::bitRotateRight($data[1], 39), "^"),
                "^"
            );
            $data[2] = self::bitOperation(
                $data[2],
                self::bitOperation(self::bitRotateRight($data[2], 1), self::bitRotateRight($data[2], 6), "^"),
                "^"
            );
            $data[3] = self::bitOperation(
                $data[3],
                self::bitOperation(self::bitRotateRight($data[3], 10), self::bitRotateRight($data[3], 17), "^"),
                "^"
            );
            $data[4] = self::bitOperation(
                $data[4],
                self::bitOperation(self::bitRotateRight($data[4], 7), self::bitRotateRight($data[4], 41), "^"),
                "^"
            );
            self::debug('linear diffusion layer', $data, true);
        }
    }

    /**
     * Convert a byte array to a binary string
     * @param array $byteArray
     * @return string
     */
    public static function byteArrayToStr(array $byteArray): string
    {
        return pack("C*", ...$byteArray);
    }

    /**
     * Convert an integer into a byte array of given length
     * @param int $nr
     * @param int $bytesCount
     * @return int[]
     */
    public static function intToByteArray(int $nr, int $bytesCount = 8): array
    {
        $arr = [];
        $i = 0;
        while ($bytesCount > 0) {
            $arr[$i++] = $nr & 255;
            $nr >>= 8;
            $bytesCount--;
        }
        return $arr;
    }

    /**
     * Convert a string to a byte array
     * @param string $str
     * @return int[]
     */
    public static function strToByteArray(string $str): array
    {
        return unpack("C*", $str);
    }

    /**
     * Perform a bit operation on the given integer array
     * @param int[] $intArrayA
     * @param int[] $intArrayB
     * @param string $operator See function for available operators
     * @return int[]
     */
    public static function bitOperation(
        array $intArrayA,
        array $intArrayB,
        string $operator
    ): array {
        return match ($operator) {
            "^" => [$intArrayA[0] ^ $intArrayB[0], $intArrayA[1] ^ $intArrayB[1]],
            "&" => [$intArrayA[0] & $intArrayB[0], $intArrayA[1] & $intArrayB[1]],
            "|" => [$intArrayA[0] | $intArrayB[0], $intArrayA[1] | $intArrayB[1]],
            "~" => [~$intArrayA[0], ~$intArrayA[1]]
        };
    }

    /**
     * Bit shift rotate right integer array for given number of places
     * @param int[] $intArr
     * @param int $places
     * @return int[]
     */
    public static function bitRotateRight(array $intArr, int $places): array
    {
        // if more than 32 bit shift, swap in 2 rounds
        if ($places > 32) {
            return self::bitRotateRight(self::bitRotateRight($intArr, 32), $places - 32);
        }
        return [
            ($intArr[0] >> $places) | ((($intArr[1] & (1 << $places) - 1) << (32 - $places))),
            ($intArr[1] >> $places) | ((($intArr[0] & (1 << $places) - 1) << (32 - $places))),
        ];
    }

    /**
     * Split 2x 32bit integers into 8 bytes
     * @param int[] $intArray
     * @return int[]
     */
    public static function intArrayToByteArray(array $intArray): array
    {
        return unpack("C*", pack("V", $intArray[1]) . pack("V", $intArray[0]));
    }

    /**
     * Convert given byte array into internal int array
     * @param int[] $byteArr
     * @param int $offset Starting from given offset
     * @return int[]
     */
    public static function byteArrayToIntArray(array $byteArr, int $offset): array
    {
        $len = count($byteArr);
        if ($offset < 0) {
            $offset = $len + $offset;
        }
        $arr = [0, 0];
        for ($i = 0; $i < 8; $i++) {
            $index = 7 - $i;
            $shift = $index * 8;
            $byte = ($byteArr[($index + $offset)] ?? 0);
            if ($shift < 32) {
                $arr[1] ^= $byte << $shift;
            } else {
                $arr[0] ^= $byte << ($shift - 32);
            }
        }
        return $arr;
    }

    /**
     * Convert given byte array into internal state array of 5 int arrays
     * @param int[] $byteArray
     * @return int[][]
     */
    public static function byteArrayToStateArray(array $byteArray): array
    {
        return [
            self::byteArrayToIntArray($byteArray, 0),
            self::byteArrayToIntArray($byteArray, 8),
            self::byteArrayToIntArray($byteArray, 16),
            self::byteArrayToIntArray($byteArray, 24),
            self::byteArrayToIntArray($byteArray, 32),
        ];
    }

    /**
     * Convert given byte array to visual hex representation with leading 0x
     * @param array $byteArray
     * @return string
     */
    public static function byteArrayToHex(array $byteArray): string
    {
        return "0x" . implode("", array_map(function ($byte) {
                return str_pad(dechex($byte), 2, "0", STR_PAD_LEFT);
            }, $byteArray));
    }

    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param mixed $value
     * @param array $values
     * @param string $errorMessage
     * @throws Exception
     */
    public static function assertInArray(mixed $value, array $values, string $errorMessage): void
    {
        self::assert(
            in_array($value, $values),
            $errorMessage . ": Value '$value' is not in available choices of\n" . var_export(
                $values,
                true
            )
        );
    }

    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param mixed $expected
     * @param mixed $actual
     * @param string $errorMessage
     * @throws Exception
     */
    public static function assertSame(mixed $expected, mixed $actual, string $errorMessage): void
    {
        self::assert(
            $expected === $actual,
            $errorMessage . ": Value is expected to be\n" . var_export(
                $expected,
                true
            ) . "\nbut actual value is\n" . var_export($actual, true)
        );
    }

    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param bool $result
     * @param string $errorMessage
     * @throws Exception
     */
    public static function assert(bool $result, string $errorMessage): void
    {
        if (!$result) {
            throw new Exception($errorMessage);
        }
    }

    /**
     * Debug output
     * @param mixed $msg
     * @param array|null $stateData
     * @param bool $permutation Is a permutation debug
     */
    public static function debug(
        mixed $msg,
        ?array $stateData = null,
        bool $permutation = false
    ): void {
        if (!$permutation && !self::$debug) {
            return;
        }
        if ($permutation && !self::$debugPermutation) {
            return;
        }
        if ($stateData) {
            echo $msg . ":\n " . implode(
                    " ",
                    array_map(function ($intArr) {
                        return str_pad(dechex($intArr[0]), 8, "0", STR_PAD_LEFT) .
                            str_pad(dechex($intArr[1]), 8, "0", STR_PAD_LEFT);
                    }, $stateData)
                ) . "\n";
            return;
        }
        if (is_array($msg)) {
            echo json_encode($msg);
        } elseif (is_bool($msg)) {
            echo $msg ? 'true' : 'false';
        } else {
            echo $msg;
        }
        echo "\n";
    }

}