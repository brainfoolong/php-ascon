<?php

require_once __DIR__ . "/../src/Ascon.php";

use Nullix\Ascon\Ascon;

// generate known answers and compare them to LWC expected results
// https://lab.las3.de/gitlab/lwc/compare/blob/master/test_vectors

function genBytes(int $len): array
{
    return array_map(function ($i) {
        return $i % 256;
    }, range(0, $len - 1));
}

const MAX_MESSAGE_LENGTH = 32;
const MAX_ASSOCIATED_DATA_LENGTH = 32;
$variants = ["Ascon-128", "Ascon-128a", "Ascon-80pq"];

foreach ($variants as $variant) {
    $klen = $variant == "Ascon-80pq" ? 20 : 16;
    $nlen = 16;
    $tlen = 16;
    $filename = "LWC_AEAD_KAT_" . ($klen * 8) . "_" . ($nlen * 8) . "_" . strtoupper(substr($variant, 6));

    $key = genBytes($klen);
    $nonce = genBytes($nlen);
    $msg = genBytes(MAX_MESSAGE_LENGTH);
    $ad = genBytes(MAX_ASSOCIATED_DATA_LENGTH);

    $fileData = "";
    $count = 1;
    for ($mlen = 0; $mlen < MAX_MESSAGE_LENGTH + 1; $mlen++) {
        for ($adlen = 0; $adlen < MAX_ASSOCIATED_DATA_LENGTH + 1; $adlen++) {
            $fileMsg = "Count = $count\n";
            $count++;
            $adSliced = array_slice($ad, 0, $adlen);
            $msgSliced = array_slice($msg, 0, $mlen);
            $encrypt = Ascon::encrypt($key, $nonce, $adSliced, $msgSliced, $variant);
            Ascon::assertSame($mlen + $tlen, count($encrypt), 'Not match expected encrypt message length');
            $decrypt = Ascon::decrypt($key, $nonce, $adSliced, $encrypt, $variant);
            Ascon::assertSame($mlen, count($decrypt ?? []), 'Not match expected decrypt message length');
            $fileMsg .= "Key = " . strtoupper(substr(Ascon::byteArrayToHex($key), 2)) . "\n";
            $fileMsg .= "Nonce = " . strtoupper(substr(Ascon::byteArrayToHex($nonce), 2)) . "\n";
            $fileMsg .= "PT = " . strtoupper(substr(Ascon::byteArrayToHex($msgSliced), 2)) . "\n";
            $fileMsg .= "AD = " . strtoupper(substr(Ascon::byteArrayToHex($adSliced), 2)) . "\n";
            $fileMsg .= "CT = " . strtoupper(substr(Ascon::byteArrayToHex($encrypt), 2)) . "\n\n";
            $fileData .= $fileMsg;
        }
    }
    file_put_contents(__DIR__ . "/genkat_results/$filename.txt", $fileData);
    Ascon::assertSame($fileData, file_get_contents(__DIR__ . "/genkat_expected/$filename.txt", $fileData),
        'Test results for variant ' . $variant . ' not matching LWC known results');
}

echo basename(__FILE__) . " successfully done\n";