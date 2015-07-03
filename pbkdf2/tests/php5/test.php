<?php
$iterations = 1 << 23;
$k = hash_pbkdf2('sha1', 'password', 'saltsalt', $iterations, 0);
echo "SHA1,$iterations,$k\n";
?>
