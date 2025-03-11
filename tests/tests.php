<?php

namespace Nullix\Ascon;

require_once __DIR__ . "/../src/Ascon.php";

function genBytes($len): array
{
    $arr = [];
    for ($i = 0; $i < $len; $i++) {
        $arr[] = $i % 256;
    }
    return $arr;
}

$argv = $_SERVER['argv'];
$tests = isset($argv[1]) ? explode(',', strtolower($argv[1])) : [];
$aead_variants = empty($tests) || in_array(
    'aead',
    $tests
) ? ['Ascon-AEAD128' => ['filename' => 'LWC_AEAD_KAT_128_128.txt']] : [];
$hash_variants = empty($tests) || in_array('hash', $tests) ? [
    'Ascon-Hash256' => ['filename' => 'LWC_HASH_KAT_256.txt'],
    'Ascon-XOF128' => ['filename' => 'LWC_HASHXOF_KAT_256.txt'],
    'Ascon-CXOF128' => ['filename' => 'LWC_HASHCXOF_KAT_256.txt'],
] : [];
$cxof_variants = empty($tests) || in_array(
    'cxof',
    $tests
) ? ['Ascon-CXOF128' => ['filename' => 'LWC_CXOF_KAT_256.txt']] : [];
$auth_variants = empty($tests) || in_array('auth', $tests) ? [
    'Ascon-Mac' => ['filename' => 'LWC_AUTHMAC_KAT_128_128.txt'],
    'Ascon-Prf' => ['filename' => 'LWC_AUTHPRF_KAT_128_128.txt'],
    'Ascon-PrfShort' => ['filename' => 'LWC_AUTHPRFSHORT_KAT_128_128.txt'],
] : [];

foreach ($hash_variants as $variant => $row) {
    $messageLength = 1024;
    $hlen = 32;
    $expected = str_replace("\r", '', file_get_contents(__DIR__ . '/genkat_expected/' . $row['filename']));
    $fileData = '';
    $count = 1;
    file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
    for ($index = 0; $index <= $messageLength; $index++) {
        $msg = genBytes($index);
        $hash = Ascon::hash($msg, $variant, $hlen);
        $fileMsg = 'Count = ' . $count . "\n";
        $fileDataStart = strlen($fileData);
        $fileMsg .= 'Msg = ' . strtoupper(substr(Ascon::byteArrayToHex($msg), 2)) . "\n";
        $fileMsg .= 'MD = ' . strtoupper(substr(Ascon::byteArrayToHex($hash), 2)) . "\n";
        $fileData .= $fileMsg . "\n";
        file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
        $expectedPart = substr($expected, $fileDataStart, strlen($fileData) - $fileDataStart);
        $actualPart = substr($fileData, $fileDataStart);
        $count++;
        if ($expectedPart !== $actualPart) {
            Ascon::assertSame(
                $expectedPart,
                $actualPart,
                'Test results for cycle ' . ($count - 1) . ' variant ' . $variant . ' not matching LWC known results'
            );
        }
    }
    Ascon::assertSame(
        $expected,
        $fileData,
        'Test results for variant ' . $variant . ' not matching LWC known results'
    );
}

foreach ($cxof_variants as $variant => $row) {
    $messageLength = 32;
    $customizationLength = 32;
    $hlen = 32;
    $expected = str_replace("\r", '', file_get_contents(__DIR__ . '/genkat_expected/' . $row['filename']));
    $fileData = '';
    $count = 1;
    file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
    for ($msgLen = 0; $msgLen <= $messageLength; $msgLen++) {
        for ($customLen = 0; $customLen <= $customizationLength; $customLen++) {
            $msg = genBytes($msgLen);
            $custom = genBytes($customLen);
            $hash = Ascon::hash($msg, $variant, $hlen, $custom);
            $fileMsg = 'Count = ' . $count . "\n";
            $fileDataStart = strlen($fileData);
            $fileMsg .= 'Msg = ' . strtoupper(substr(Ascon::byteArrayToHex($msg), 2)) . "\n";
            $fileMsg .= 'Z = ' . strtoupper(substr(Ascon::byteArrayToHex($custom), 2)) . "\n";
            $fileMsg .= 'MD = ' . strtoupper(substr(Ascon::byteArrayToHex($hash), 2)) . "\n";
            $fileData .= $fileMsg . "\n";
            file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
            $expectedPart = substr($expected, $fileDataStart, strlen($fileData) - $fileDataStart);
            $actualPart = substr($fileData, $fileDataStart);
            $count++;
            if ($expectedPart !== $actualPart) {
                Ascon::assertSame(
                    $expectedPart,
                    $actualPart,
                    'Test results for cycle ' . ($count - 1) . ' variant ' . $variant . ' not matching LWC known results'
                );
            }
        }
    }
    Ascon::assertSame(
        $expected,
        $fileData,
        'Test results for variant ' . $variant . ' not matching LWC known results'
    );
}

foreach ($auth_variants as $variant => $row) {
    $messageLength = $variant === 'Ascon-PrfShort' ? 16 : 1024;
    $klen = 16;
    $tlen = 16;
    $expected = str_replace("\r", '', file_get_contents(__DIR__ . '/genkat_expected/' . $row['filename']));
    $fileData = '';
    $count = 1;
    file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
    for ($index = 0; $index <= $messageLength; $index++) {
        $key = genBytes($klen);
        $msg = genBytes($index);
        $hash = Ascon::mac($key, $msg, $variant, $tlen);
        $fileMsg = 'Count = ' . $count . "\n";
        $fileDataStart = strlen($fileData);
        $fileMsg .= 'Key = ' . strtoupper(substr(Ascon::byteArrayToHex($key), 2)) . "\n";
        $fileMsg .= 'Msg = ' . strtoupper(substr(Ascon::byteArrayToHex($msg), 2)) . "\n";
        $fileMsg .= 'Tag = ' . strtoupper(substr(Ascon::byteArrayToHex($hash), 2)) . "\n";
        $fileData .= $fileMsg . "\n";
        file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
        $expectedPart = substr($expected, $fileDataStart, strlen($fileData) - $fileDataStart);
        $actualPart = substr($fileData, $fileDataStart);
        $count++;
        if ($expectedPart !== $actualPart) {
            Ascon::assertSame(
                $expectedPart,
                $actualPart,
                'Test results for cycle ' . ($count - 1) . ' variant ' . $variant . ' not matching LWC known results'
            );
        }
    }
    Ascon::assertSame(
        $expected,
        $fileData,
        'Test results for variant ' . $variant . ' not matching LWC known results'
    );
}

foreach ($aead_variants as $variant => $row) {
    $messageLength = 32;
    $assocDataLength = 32;
    $tlen = 16;
    $expected = str_replace("\r", '', file_get_contents(__DIR__ . '/genkat_expected/' . $row['filename']));
    $fileData = '';
    $count = 1;
    file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
    for ($mlen = 0; $mlen <= $messageLength; $mlen++) {
        for ($adlen = 0; $adlen <= $assocDataLength; $adlen++) {
            $fileMsg = 'Count = ' . $count . "\n";
            $fileDataStart = strlen($fileData);
            $key = genBytes(16);
            $nonce = genBytes(16);
            $msg = genBytes($mlen);
            $ad = genBytes($adlen);
            $encrypt = Ascon::encrypt($key, $nonce, $ad, $msg, $variant);
            Ascon::assertSame(
                $mlen + $tlen,
                count($encrypt),
                'Not match expected encrypt message length in cycle ' . $count
            );
            $decrypt = Ascon::decrypt($key, $nonce, $ad, $encrypt, $variant);
            Ascon::assertSame(
                $mlen,
                count($decrypt ?? []),
                'Not match expected decrypt message length in cycle ' . $count
            );
            $fileMsg .= 'Key = ' . strtoupper(substr(Ascon::byteArrayToHex($key), 2)) . "\n";
            $fileMsg .= 'Nonce = ' . strtoupper(substr(Ascon::byteArrayToHex($nonce), 2)) . "\n";
            $fileMsg .= 'PT = ' . strtoupper(substr(Ascon::byteArrayToHex($msg), 2)) . "\n";
            $fileMsg .= 'AD = ' . strtoupper(substr(Ascon::byteArrayToHex($ad), 2)) . "\n";
            $fileMsg .= 'CT = ' . strtoupper(substr(Ascon::byteArrayToHex($encrypt), 2)) . "\n";
            $fileData .= $fileMsg . "\n";
            file_put_contents(__DIR__ . '/genkat_results/' . $row['filename'], $fileData);
            $expectedPart = substr($expected, $fileDataStart, strlen($fileData) - $fileDataStart);
            $actualPart = substr($fileData, $fileDataStart);
            $count++;
            if ($expectedPart !== $actualPart) {
                Ascon::assertSame(
                    $expectedPart,
                    $actualPart,
                    'Test results for cycle ' . ($count - 1) . ' variant ' . $variant . ' not matching LWC known results'
                );
            }
        }
    }
    Ascon::assertSame(
        $expected,
        $fileData,
        'Test results for variant ' . $variant . ' not matching LWC known results'
    );
}

$secret = '👌SecretSauce';
$msg = 'SecretMsg🥐';
$encrypted = Ascon::encryptToHex($secret, $msg);
$decrypted = Ascon::decryptFromHex($secret, $encrypted);
Ascon::assertSame($msg, $decrypted, 'Encryption/Decryption failed');

echo 'Tests successfully done' . PHP_EOL;
?>