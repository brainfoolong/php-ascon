<?php

require __DIR__ . "/../src/Ascon.php";

use Nullix\Ascon\Ascon;

// this show the usage of the original raw ascon encrypt/decrypt values
// you have to provide correct parameters and byte arrays to make this work
// see convenient-usage.php is you like a more streamlined version that handles most things for you


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

var_export([
  'plaintext' => $plaintext,
  'ciphertextHex' => Ascon::byteArrayToHex($ciphertextByteArray),
  'plaintextDecrypted' => Ascon::byteArrayToStr($plaintextDecrypted),
  'verifiedDecryption' => Ascon::strToByteArray($plaintext) === $plaintextDecrypted,
]);


var_dump(Ascon::hash('Testmessage'));
var_dump(Ascon::mac($key, 'Testmessage'));