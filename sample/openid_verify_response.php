<?php
require_once 'Zend/Loader/Autoloader.php';
$autoloader = Zend_Loader_Autoloader::getInstance();

//$consumer = new Zend_OpenId_Consumer();
$autoloader->registerNamespace('Kjgk_');
$consumer = new Kjgk_OpenId_Consumer();

if ($consumer->verify($_GET, $id)) {
    echo "VALID " . htmlspecialchars($id);
} else {
    echo "INVALID " . htmlspecialchars($id) . $consumer->getError();
}
