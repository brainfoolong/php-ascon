<?php

namespace Nullix\Ascon;

use Exception;

use function array_fill;
use function array_map;
use function array_merge;
use function array_slice;
use function array_values;
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
 * PHP 8+ implementation of Ascon v1.2
 * If you need very good performance, you should consider embed a C module via FFI in PHP
 * I've aimed to provide a library that works out of the box, without modifying php.ini configs
 * Heavily inspired by the python implementation of https://github.com/meichlseder/pyascon
 * @link https://github.com/brainfoolong/php-ascon
 * @author BrainFooLong (Roland Eigelsreiter)
 * @version 1.0.0
 */
class Ascon
{

    public const VERSION = "1.0.0"; // version of this tool

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
        string $cipherVariant = "Ascon-128"
    ): string {
        $key = self::hash($secretKey, "Ascon-Xof", $cipherVariant === 'Ascon-80pq' ? 20 : 16);
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
        string $cipherVariant = "Ascon-128"
    ): mixed {
        $key = self::hash($secretKey, "Ascon-Xof", $cipherVariant === 'Ascon-80pq' ? 20 : 16);
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
     * @param string|array $key A string or byte array of a length 16 (for Ascon-128, Ascon-128a; 128-bit security) or
     *   20 (for Ascon-80pq; 128-bit security)
     * @param string|array $nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
     * @param string|array $associatedData A string or byte array of any length
     * @param string|array $plaintext A string or byte array of any length
     * @param string $variant "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of
     *   rounds)
     * @return int[] Return encrypted ciphertext and tag as byte array
     */
    public static function encrypt(
        string|array $key,
        string|array $nonce,
        string|array $associatedData,
        string|array $plaintext,
        string $variant = "Ascon-128"
    ): array {
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $nonce = !is_array($nonce) ? self::strToByteArray($nonce) : $nonce;
        $nonceLength = count($nonce);
        self::assertInArray($variant, ["Ascon-128", "Ascon-128a", "Ascon-80pq"], "Encrypt variant");
        if (in_array($variant, ["Ascon-128", "Ascon-128a"])) {
            self::assert($keyLength === 16 && $nonceLength === 16, 'Incorrect key or nonce length');
        } else {
            self::assert($keyLength === 20 && $nonceLength === 16, 'Incorrect key or nonce length');
        }
        $data = [];
        $keySizeBits = $keyLength * 8;
        $permutationRoundsA = 12;
        $permutationRoundsB = $variant === "Ascon-128a" ? 8 : 6;
        $rate = $variant === "Ascon-128a" ? 16 : 8;
        self::initialize($data, $keySizeBits, $rate, $permutationRoundsA, $permutationRoundsB, $key, $nonce);
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
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $nonce = !is_array($nonce) ? self::strToByteArray($nonce) : $nonce;
        $nonceLength = count($nonce);
        self::assertInArray($variant, ["Ascon-128", "Ascon-128a", "Ascon-80pq"], "Encrypt variant");
        if (in_array($variant, ["Ascon-128", "Ascon-128a"])) {
            self::assert($keyLength === 16 && $nonceLength === 16, 'Incorrect key or nonce length');
        } else {
            self::assert($keyLength === 20 && $nonceLength === 16, 'Incorrect key or nonce length');
        }
        $data = [];
        $keySizeBits = $keyLength * 8;
        $permutationRoundsA = 12;
        $permutationRoundsB = $variant === "Ascon-128a" ? 8 : 6;
        $rate = $variant === "Ascon-128a" ? 16 : 8;
        self::initialize($data, $keySizeBits, $rate, $permutationRoundsA, $permutationRoundsB, $key, $nonce);
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
     * @param string $variant "Ascon-Mac", "Ascon-Maca" (both 128-bit output, arbitrarily long input), "Ascon-Prf",
     *   "Ascon-Prfa" (both arbitrarily long input and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit
     *   input for m<=128)
     * @param int $tagLength The requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac", "Ascon-Maca",
     *   and "Ascon-PrfShort", arbitrary for "Ascon-Prf", "Ascon-Prfa"; should be >= 16 for 128-bit security)
     * @return array The byte array representing the authentication tag
     */
    public static function mac(
        string|array $key,
        string|array $message,
        string $variant = "Ascon-Mac",
        int $tagLength = 16
    ): array {
        self::assertInArray($variant, ["Ascon-Mac", "Ascon-Prf", "Ascon-Maca", "Ascon-Prfa", "Ascon-PrfShort"],
            "Mac variant");
        $key = !is_array($key) ? self::strToByteArray($key) : $key;
        $keyLength = count($key);
        $message = !is_array($message) ? self::strToByteArray($message) : $message;
        $messageLength = count($message);
        if (in_array($variant, ["Ascon-Mac", "Ascon-Maca"])) {
            self::assert($keyLength === 16 && $tagLength <= 16, 'Incorrect key length');
        } elseif (in_array($variant, ["Ascon-Prf", "Ascon-Prfa"])) {
            self::assert($keyLength === 16, 'Incorrect key length');
        } elseif ($variant == "Ascon-PrfShort") {
            self::assert($messageLength <= 16, 'Message to long for variant ' . $variant);
            self::assert($keyLength === 16 && $tagLength <= 16 && $messageLength <= 16, 'Incorrect key length');
        }
        $permutationRoundsA = 12;
        $permutationRoundsB = in_array($variant, ["Ascon-Prfa", "Ascon-Maca"]) ? 8 : 12;
        $messageBlockSize = in_array($variant, ["Ascon-Prfa", "Ascon-Maca"]) ? 40 : 32;
        $rate = 16;
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
            // finalization (squeezing)
            return array_merge(
                self::intArrayToByteArray(
                    self::bitOperation($data[3], self::byteArrayToIntArray($key, 0), "^")
                ),

                self::intArrayToByteArray(
                    self::bitOperation($data[4], self::byteArrayToIntArray($key, 8), "^")
                )
            );
        }
        $tagSpec = self::strToByteArray(pack("N", in_array($variant, ["Ascon-Mac", "Ascon-Maca"]) ? 128 : 0));
        $tmp = array_merge(
            [
                $keyLength * 8,
                $rate * 8,
                $permutationRoundsA + 128,
                $permutationRoundsA - $permutationRoundsB,
            ],
            $tagSpec,
            $key,
            array_fill(0, 16, 0)
        );
        $data = self::byteArrayToStateArray($tmp);
        self::debug("initial value", $data);
        self::permutation($data, $permutationRoundsA);
        self::debug("initialization", $data);
        // message processing (absorbing)
        $messagePadded = $message;
        $messagePadded[] = 0x80;
        $messagePadded = array_merge($messagePadded,
            array_fill(0, $messageBlockSize - ($messageLength % $messageBlockSize) - 1, 0x0));
        $messagePaddedLength = count($messagePadded);
        $iterations = in_array($variant, ["Ascon-Prfa", "Ascon-Maca"]) ? 4 : 3;
        // first s-1 blocks
        for ($block = 0; $block < $messagePaddedLength - $messageBlockSize; $block += $messageBlockSize) {
            for ($i = 0; $i <= $iterations; $i++) {
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
        for ($i = 0; $i <= $iterations; $i++) {
            $data[$i] = self::bitOperation(
                $data[$i],
                self::byteArrayToIntArray($messagePadded, $block + ($i * 8)),
                "^"
            );
        }
        $data[4] = self::bitOperation(
            $data[4],
            [0, 1],
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
     * @param string $variant "Ascon-Hash", "Ascon-Hasha" (both with 256-bit output for 128-bit security), "Ascon-Xof",
     *   or "Ascon-Xofa" (both with arbitrary output length, security=min(128, bitlen/2))
     * @param int $hashLength The requested output bytelength (must be 32 for variant "Ascon-Hash"; can be arbitrary
     *   for Ascon-Xof, but should be >= 32 for 128-bit security)
     * @return array The byte array representing the hash tag
     */
    public static function hash(string|array $message, string $variant = "Ascon-Hash", int $hashLength = 32): array
    {
        self::assertInArray($variant, ["Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa"], "Hash variant");
        if (in_array($variant, ["Ascon-Hash", "Ascon-Hasha"])) {
            self::assert($hashLength === 32, 'Incorrect hash length');
        }
        $message = !is_array($message) ? self::strToByteArray($message) : $message;
        $messageLength = count($message);
        $permutationRoundsA = 12;
        $permutationRoundsB = in_array($variant, ["Ascon-Hasha", "Ascon-Xofa"]) ? 8 : 12;
        $rate = 8;

        $tagSpec = self::strToByteArray(pack("N", in_array($variant, ["Ascon-Hash", "Ascon-Hasha"]) ? 256 : 0));
        $tmp = array_merge(
            [0, $rate * 8, $permutationRoundsA, $permutationRoundsA - $permutationRoundsB],
            $tagSpec,
            array_fill(0, 32, 0)
        );
        $data = self::byteArrayToStateArray($tmp);
        self::debug('initial value', $data, true);
        self::permutation($data, $permutationRoundsA);
        self::debug('initialization', $data, true);
        // message processing (absorbing)
        $messagePadded = $message;
        $messagePadded[] = 0x80;
        $messagePadded = array_merge($messagePadded, array_fill(0, $rate - ($messageLength % $rate) - 1, 0x0));
        $messagePaddedLength = count($messagePadded);
        // first s-1 blocks
        for ($block = 0; $block < $messagePaddedLength - $rate; $block += $rate) {
            $data[0] = self::bitOperation(
                $data[0],
                self::byteArrayToIntArray($messagePadded, $block),
                "^"
            );
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messagePaddedLength - $rate;
        $data[0] = self::bitOperation(
            $data[0],
            self::byteArrayToIntArray($messagePadded, $block),
            "^"
        );
        self::debug("process message", $data);
        // finalization (squeezing)
        $hash = [];
        self::permutation($data, $permutationRoundsA);
        while (count($hash) < $hashLength) {
            $hash = array_merge($hash, self::intArrayToByteArray($data[0]));
            self::permutation($data, $permutationRoundsB);
        }
        self::debug("finalization", $data);
        return $hash;
    }

    /**
     * Ascon initialization phase - internal helper function
     * @param int[][] $data Ascon state, a list of 5 64-bit integers
     * @param int $keySize Key size in bits
     * @param int $rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param int $permutationRoundsA Number of initialization/finalization rounds for permutation
     * @param int $permutationRoundsB Number of intermediate rounds for permutation
     * @param array $key A bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq;
     *   128-bit security)
     * @param array $nonce A bytes object of size 16
     */
    public static function initialize(
        array &$data,
        int $keySize,
        int $rate,
        int $permutationRoundsA,
        int $permutationRoundsB,
        array $key,
        array $nonce
    ): void {
        $data = self::byteArrayToStateArray(array_merge(
            [$keySize, $rate * 8, $permutationRoundsA, $permutationRoundsB],
            array_fill(0, 20 - count($key), 0),
            $key,
            $nonce
        ));
        self::debug('initial value', $data);
        self::permutation($data, $permutationRoundsA);
        $zeroKey = self::byteArrayToStateArray(array_merge(
            array_fill(0, 40 - count($key), 0),
            $key
        ));
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
            $messagePadded = $associatedData;
            $messagePadded[] = 0x80;
            $messagePadded = array_merge(
                $messagePadded,
                array_fill(0, $rate - (count($associatedData) % $rate) - 1, 0x0)
            );
            $messagePaddedLength = count($messagePadded);
            for ($block = 0; $block < $messagePaddedLength; $block += $rate) {
                $data[0] = self::bitOperation(
                    $data[0],
                    self::byteArrayToIntArray($messagePadded, $block),
                    "^"
                );
                if ($rate === 16) {
                    $data[1] = self::bitOperation(
                        $data[1],
                        self::byteArrayToIntArray($messagePadded, $block + 8),
                        "^"
                    );
                }
                self::permutation($data, $permutationRoundsB);
            }
        }
        $data[4] = self::bitOperation(
            $data[4],
            [0, 1],
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
        $messagePadded = $plaintext;
        $messagePadded[] = 0x80;
        $messagePadded = array_merge(
            $messagePadded,
            array_fill(0, $rate - $lastLen - 1, 0x0)
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
            if ($rate === 16) {
                $data[1] = self::bitOperation(
                    $data[1],
                    self::byteArrayToIntArray($messagePadded, $block + 8),
                    "^"
                );
                $ciphertext = array_merge($ciphertext, self::intArrayToByteArray($data[1]));
            }
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messagePaddedLength - $rate;
        if ($rate === 8) {
            $data[0] = self::bitOperation(
                $data[0],
                self::byteArrayToIntArray($messagePadded, $block),
                "^"
            );
            $ciphertext = array_merge(
                $ciphertext,
                array_slice(self::intArrayToByteArray($data[0]), 0, $lastLen),
            );
        } elseif ($rate === 16) {
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
        }
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
        $messagePadded = array_merge(
            $ciphertext,
            array_fill(0, $rate - $lastLen, 0x0)
        );
        $messagePaddedLength = count($messagePadded);
        $plaintext = [];
        // first t-1 blocks
        for ($block = 0; $block < $messagePaddedLength - $rate; $block += $rate) {
            $ci = self::byteArrayToIntArray($messagePadded, $block);
            $plaintext = array_merge(
                $plaintext,
                self::intArrayToByteArray(self::bitOperation($data[0], $ci, "^"))
            );
            $data[0] = $ci;
            if ($rate === 16) {
                $ci = self::byteArrayToIntArray($messagePadded, $block + 8);
                $plaintext = array_merge(
                    $plaintext,
                    self::intArrayToByteArray(self::bitOperation($data[1], $ci, "^"))
                );
                $data[1] = $ci;
            }
            self::permutation($data, $permutationRoundsB);
        }
        // last block
        $block = $messagePaddedLength - $rate;
        if ($rate === 8) {
            $ci = self::byteArrayToIntArray($messagePadded, $block);
            $plaintext = array_merge(
                $plaintext,
                array_slice(self::intArrayToByteArray(self::bitOperation($ci, $data[0], "^")), 0, $lastLen)
            );
            $shift = $lastLen * 8;
            $mask = [0xffffffff >> $shift, 0xffffffff >> max(0, $shift - 32)];
            $masked = self::bitOperation($data[0], $mask, "&");
            $shift = ($rate - $lastLen - 1) * 8;
            $padding = [$shift >= 32 ? 0x80 << ($shift - 32) : 0, $shift < 32 ? 0x80 << ($shift) : 0];
            $data[0] = self::bitOperation(self::bitOperation($ci, $masked, "^"), $padding, "^");
        } elseif ($rate === 16) {
            $lastLenWord = $lastLen % 8;
            $shift = (8 - $lastLenWord - 1) * 8;
            $padding = [$shift >= 32 ? 0x80 << ($shift - 32) : 0, $shift < 32 ? 0x80 << ($shift) : 0];
            $shift = $lastLenWord * 8;
            $mask = [0xffffffff >> $shift, 0xffffffff >> max(0, $shift - 32)];
            $ciA = self::byteArrayToIntArray($messagePadded, $block);
            $ciB = self::byteArrayToIntArray($messagePadded, $block + 8);
            $plaintextAdd = array_slice(array_merge(
                self::intArrayToByteArray(self::bitOperation($data[0], $ciA, "^")),
                self::intArrayToByteArray(self::bitOperation($data[1], $ciB, "^"))
            ), 0, $lastLen);
            $plaintext = array_merge(
                $plaintext,
                $plaintextAdd
            );
            if ($lastLen < 8) {
                $masked = self::bitOperation($data[0], $mask, "&");
                $data[0] = self::bitOperation(self::bitOperation($ciA, $masked, "^"), $padding, "^");
            } else {
                $masked = self::bitOperation($data[1], $mask, "&");
                $data[0] = $ciA;
                $data[1] = self::bitOperation(self::bitOperation($ciB, $masked, "^"), $padding, "^");
            }
        }
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
     * Convert a string to a byte array
     * @param string $str
     * @return int[]
     */
    public static function strToByteArray(string $str): array
    {
        return array_values(unpack("C*", $str));
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
            ($intArr[1] >> $places) | ((($intArr[0] & (1 << $places) - 1) << (32 - $places)))
        ];
    }

    /**
     * Split 2 32bit integers into 8 bytes
     * @param int[] $intArray
     * @return int[]
     */
    public static function intArrayToByteArray(array $intArray): array
    {
        return array_values(unpack("C*", pack("N", $intArray[0]) . pack("N", $intArray[1])));
    }

    /**
     * Convert given byte array into internal int array
     * @param int[] $byteArr
     * @param int $offset Starting from given offset
     * @return int[]
     */
    public static function byteArrayToIntArray(array $byteArr, int $offset): array
    {
        // split 8 bytes into 2 32bit integers
        if ($offset < 0) {
            $offset = count($byteArr) + $offset;
        }
        $arr = [0, 0];
        for ($i = 0; $i < 8; $i++) {
            $shift = (8 - 1 - $i) * 8;
            if ($shift < 32) {
                $arr[1] ^= ($byteArr[$i + $offset] ?? 0) << $shift;
            } else {
                $arr[0] ^= ($byteArr[$i + $offset] ?? 0) << ($shift - 32);
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
     * Convert given int array to visual hex representation with leading 0x
     * @param array $intArr
     * @return string
     */
    public static function intArrayToHex(array $intArr): string
    {
        return "0x" .
            str_pad(dechex($intArr[0]), 8, "0", STR_PAD_LEFT) .
            str_pad(dechex($intArr[1]), 8, "0", STR_PAD_LEFT);
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
        self::assert(in_array($value, $values),
            $errorMessage . ": Value '$value' is not in available choices of\n" . var_export($values,
                true));
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
        self::assert($expected === $actual, $errorMessage . ": Value is expected to be\n" . var_export($expected,
                true) . "\nbut actual value is\n" . var_export($actual, true));
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
        echo "[Ascon Debug] ";
        if ($stateData) {
            echo $msg . ": " . json_encode(
                    array_map([__CLASS__, 'intArrayToHex'], $stateData)
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