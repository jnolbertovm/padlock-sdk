<?php

require './vendor/autoload.php';

use nolbertovilchez\sdk\padlock\PadlockUser;

$user = new PadlockUser("admin", "admin");
$login = $user->login();
echo "<pre>"; print_r($login->getData());
