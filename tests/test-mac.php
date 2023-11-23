<?php

require_once __DIR__ . "/../src/Ascon.php";

use Nullix\Ascon\Ascon;

Ascon::$debug = false;
Ascon::$debugPermutation = false;

$key = [0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xEF];

$word = "ascon";
$expected = "0x5432a3ff217b31c6a7105a175438b1f9";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-Mac"');

$word = "asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+";
$expected = "0x558cb5e4ae72cc04da650971dc7b2f43";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-Mac"');

$word = "asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+";
$expected = "0x68dfa25dbca5a16559f963b34351b95b";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word, "Ascon-Maca"));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-Maca"');

$word = "asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+";
$expected = "0xc674ed5d593aeed416664d592c917050";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word, "Ascon-Prf"));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-Prf"');

$word = "asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+";
$expected = "0x4d7087c67b452a80b373df49f2c134c5";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word, "Ascon-Prfa"));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-Prfa"');

$word = "ascon";
$expected = "0xbc38d3219d01a84e0afecd930c40ac9d";
$actual = Ascon::byteArrayToHex(Ascon::mac($key, $word, "Ascon-PrfShort"));
Ascon::assertSame($expected, $actual, 'Mac of word "'.$word.'" in variant "Ascon-PrfShort"');