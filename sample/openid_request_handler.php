<?php
require_once 'Zend/Loader/Autoloader.php';
$autoloader = Zend_Loader_Autoloader::getInstance();

//$consumer = new Zend_OpenId_Consumer();
$autoloader->registerNamespace('Kjgk_');
$consumer = new Kjgk_OpenId_Consumer();

if (!$consumer->login($_POST['openid_identifier'], 'openid_verify_response.php')) {
    die("OpenID login failed.:".$consumer->getError());
}
