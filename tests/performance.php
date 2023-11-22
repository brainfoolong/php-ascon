<?php

require_once __DIR__ . "/../src/Ascon.php";

use NullixAT\Ascon\Ascon;

$cycles = [
  [
    "nr" => 25,
    "messageSize" => 32,
    "assocSize" => 128,
  ],
  [
    "nr" => 25,
    "messageSize" => 128,
    "assocSize" => 512,
  ],
  [
    "nr" => 25,
    "messageSize" => 128 * 8,
    "assocSize" => 512 * 4,
  ],
  [
    "nr" => 25,
    "messageSize" => 512 * 8,
    "assocSize" => 0,
  ],
];

$memoryMax = 0;
foreach ($cycles as $cycle) {
    $totalTime = 0;
    $runs = $cycle['nr'];
    for ($i = 1; $i <= $runs; $i++) {
        $key = random_bytes(16);
        $message = bin2hex(random_bytes($cycle['messageSize']));
        $associatedData = $cycle['assocSize'] ? bin2hex(random_bytes($cycle['assocSize'])) : null;

        $memory = memory_get_peak_usage(true);
        if ($memory > $memoryMax) {
            $memoryMax = $memory;
        }

        $start = microtime(true);
        $encrypted = Ascon::encryptToHex($key, $message, $associatedData);
        $decrypted = Ascon::decryptFromHex($key, $encrypted, $associatedData);
        $totalTime += microtime(true) - $start;
        Ascon::assertSame($message, $decrypted, 'Encryption/Decryption to hex failed');
    }

    echo "### $runs cycles with " . strlen($message) . " byte message data and " . strlen($associatedData ?? '') . " byte associated data ###\n";
    echo "Total Time: " . round($totalTime, 2) . " seconds\n";
    echo "Memory Usage: " . round($memoryMax / 1024 / 1024, 2) . "MB\n\n";
}
