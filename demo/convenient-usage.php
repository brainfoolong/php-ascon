<?php
require __DIR__ . "/../src/Ascon.php";

use NullixAT\Ascon\Ascon;

// convenient usage of the ascon cipher for real world usage
// it automatically manages all the key conversion to correct key sizes
// it automatically generate random bytes when needed
// it convert encrypt message to a hex string, so you can transfer it easily without encoding issues
// it decrypt back from a hex string to
// you can pass any kind of message, not even strings or byte arrays
// everything that is json_encodable can be passed

$key = "mypassword";
$message = ["this can be any data type 😎 文", 123];
$associatedData = "Some data 😋 文 This data is not contained in the encrypt output. You must pass the same data to encrypt and decrypt in order to be able to decrypt the message.";
$encrypted = Ascon::encryptToHex($key, $message, $associatedData);
$decrypted = Ascon::decryptFromHex($key, $encrypted, $associatedData);

var_export([
    'encrypted' => $encrypted,
    'decrypted' => $decrypted,
    'verifiedDecryption' => $message === $decrypted
]);