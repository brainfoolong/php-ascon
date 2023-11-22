<?php

require_once __DIR__ . "/../src/Ascon.php";

use NullixAT\Ascon\Ascon;

$key20 = [
  0x90,
  0x80,
  0x70,
  0x60,
  0x50,
  0x40,
  0x30,
  0x20,
  0x10,
  0xAA,
  0x90,
  0x90,
  0x90,
  0x90,
  0xCC,
  0xEF,
  0xAA,
  0x90,
  0x90,
  0x90,
];
$key16 = [0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xEF];
$nonce = [0x50, 0x10, 0x30, 0x70, 0x90, 0x60, 0x40, 0x30, 0xEF, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0xCC];

$plaintextSimple = 'ascon';
$plaintextMore = 'ascon-asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+';
$accociatedMore = 'BLAB-asconASDFNASKIQAL-_;:;#+asconKIQAL-_;:;#+asconASDFNASKIQAL+';
$variants = [
  [
    'variant' => "Ascon-128",
    'key' => $key16,
    'plaintext' => $plaintextSimple,
    'associatedData' => 'ASCON',
    'expectedCiphertextHex' => "0x265e8b5755",
    'expectedTagHex' => "0x0d95cfeeb4cfe5a4f9ff29380137f12d",
  ],
  [
    'variant' => "Ascon-128a",
    'key' => $key16,
    'plaintext' => $plaintextSimple,
    'associatedData' => 'ASCON',
    'expectedCiphertextHex' => "0x24443ec02c",
    'expectedTagHex' => "0xd411bf0897d558a95d09cccccc06d273",
  ],
  [
    'variant' => "Ascon-80pq",
    'key' => $key20,
    'plaintext' => $plaintextSimple,
    'associatedData' => 'ASCON',
    'expectedCiphertextHex' => "0x112e6c44be",
    'expectedTagHex' => "0x83bea05f00a5f8b9f08efd404144b87b",
  ],
  [
    'variant' => "Ascon-128",
    'key' => $key16,
    'plaintext' => $plaintextMore,
    'associatedData' => $accociatedMore,
    'expectedCiphertextHex' => "0x2287b412d5c2658c38fb1616e2a3c6ff85952bbaefe021757e535ccfd4a0806cf9c5d61a368739fe661ac16d4c943a84c16196b343fdc8aaf76cc2e5ad067843dc28bae8fcf7972bfa36aaf6e734ba4ac89b3c559bdb5ba49bfb8df56d6beafd0104d9d4d495",
    'expectedTagHex' => "0x7c1e88242bea67a90f369fb0889b74c9",
  ],
  [
    'variant' => "Ascon-128a",
    'key' => $key16,
    'plaintext' => $plaintextMore,
    'associatedData' => $accociatedMore,
    'expectedCiphertextHex' => "0x72e5fde15539b1dbf9f7aea29e58598267971ae9b0446db26a0fdd7f5821cb492ca4c5ec9c40d5fd6536cc4a1d4b4cb616423d4c6d33c8a06364e7137726447d1bdee5d2071cacea601c1ab199b57748e35766248cbb26f0287abb70280b8510de508e22cc6f",
    'expectedTagHex' => "0x45eafc378d5f1d2d3b4af25ba3ef70ac",
  ],
  [
    'variant' => "Ascon-80pq",
    'key' => $key20,
    'plaintext' => $plaintextMore,
    'associatedData' => $accociatedMore,
    'expectedCiphertextHex' => "0xe483db31c108a269c2cacd33534544c0ba524a6f46016473260b9d4aa81dd0a61f994f46bb3966f2aea436990f024fbaf1477c0cbd6664b53ecdd4acf91f683054762c952dbfa42235763a8cb97ee94a25d8f0d53e200ba6a291715e3713c02ee63196aa5917",
    'expectedTagHex' => "0x6d06c25335b03f3eef29537c3a133afd",
  ],
];
foreach ($variants as $variant => $row) {
    $variant = $row['variant'];
    $plaintext = $row['plaintext'];
    $plaintextHex = Ascon::byteArrayToHex(Ascon::strToByteArray($plaintext));
    $associatedData = $row['associatedData'];

    $ciphertextAndTag = Ascon::encrypt($row['key'], $nonce, $associatedData, $plaintext, $variant);
    $ciphertext = array_slice($ciphertextAndTag, 0, -16);
    $tag = array_slice($ciphertextAndTag, -16);
    // check ciphertext
    $expected = $row['expectedCiphertextHex'];
    $actual = Ascon::byteArrayToHex($ciphertext);
    Ascon::assertSame($expected, $actual,
      'Encrypted ciphertext of word "' . $plaintext . '" in variant "' . $variant . '"');
    // check encrypted tag
    $expected = $row['expectedTagHex'];
    $actual = Ascon::byteArrayToHex($tag);
    Ascon::assertSame($expected, $actual, 'Encrypted tag of word "' . $plaintext . '" in variant "' . $variant . '"');
    // check decryption
    $plaintextReceived = Ascon::decrypt($row['key'], $nonce, $associatedData, $ciphertextAndTag, $variant);
    $actual = Ascon::byteArrayToHex($plaintextReceived ?? []);
    Ascon::assertSame($plaintextHex, Ascon::byteArrayToHex($plaintextReceived ?? []),
      'Decryption from ciphertext failed in variant "' . $variant . '"');
}

// test convenient methods
$key = "mypassword";
$message = ["this can be any data type 😎 文", 123];
$associatedData = "Some data 😋 文 This data is not contained in the encrypt output. You must pass the same data to encrypt and decrypt in order to be able to decrypt the message.";
$encrypted = Ascon::encryptToHex($key, $message, $associatedData);
$decrypted = Ascon::decryptFromHex($key, $encrypted, $associatedData);
Ascon::assertSame($message, $decrypted, 'Encryption/Decryption to hex failed');
