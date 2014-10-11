<?php
/**
 * Zend Framework
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://framework.zend.com/license/new-bsd
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@zend.com so we can send you a copy immediately.
 *
 * @category   Zend
 * @package    Zend_OpenId
 * @subpackage Demos
 * @copyright  Copyright (c) 2005-2010 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 */

$dir = realpath(dirname(__FILE__)."/../../..");
set_include_path("$dir/library" . PATH_SEPARATOR . get_include_path());

/**
 * @see Zend_OpenId_Consumer
 */
require_once "Zend/OpenId/Consumer.php";
require_once 'Kjgk/OpenId/Consumer.php';

/**
 * @see Zend_OpenId_Extension_Sreg
 */
require_once "Zend/OpenId/Extension/Sreg.php";
require_once "Kjgk/OpenId/Extension/AX.php";

$id = "";
$status = "";
$data = array();
if (isset($_POST['openid_action']) &&
    $_POST['openid_action'] == "login" &&
    !empty($_POST['openid_identifier'])) {

    //$consumer = new Zend_OpenId_Consumer();
    $consumer = new Kjgk_OpenId_Consumer();
    $props = array();
    foreach (Kjgk_OpenId_Extension_Ax::getAxProperties() as $prop) {
        if (isset($_POST[$prop])) {
            if ($_POST[$prop] === "required") {
                $props[$prop] = true;
            } else if ($_POST[$prop] === "optional") {
                $props[$prop] = false;
            }
        }
    }

    $ax = new Kjgk_OpenId_Extension_Ax($props, null, 1.1);
    $id = $_POST['openid_identifier'];
    if (!$consumer->login($id, null, null, $ax)) {
        $status = "OpenID login failed (".$consumer->getError().")";
    }
} else if (isset($_GET['openid_mode'])) {
    if ($_GET['openid_mode'] == "id_res") {
        $ax = new Kjgk_OpenId_Extension_Ax();
        //$consumer = new Zend_OpenId_Consumer();
        $consumer = new Kjgk_OpenId_Consumer();
        if ($consumer->verify($_GET, $id, $ax)) {
            $status = "VALID $id";
            $data = $ax->getProperties();
        } else {
            $status = "INVALID $id (".$consumer->getError().")";
        }
    } else if ($_GET['openid_mode'] == "cancel") {
        $status = "CANCELED";
    }
}
$ax_html = "";
$ax = new Kjgk_OpenId_Extension_Ax();
foreach (Kjgk_OpenId_Extension_Ax::getAxProperties() as $prop) {
    $val = isset($data[$prop]) ? $data[$prop] : "";
    $ax_html .= <<<EOF
<tr><td>$prop</td>
<td>
  <input type="radio" name="$prop" value="required">
</td><td>
  <input type="radio" name="$prop" value="optional">
</td><td>
  <input type="radio" name="$prop" value="none" checked="1">
</td><td>
  $val
</td></tr>
EOF;
}
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Zend OpenID Consumer Example</title>
<style>
input.openid_login {
    background: url(login-bg.gif) no-repeat;
    background-color: #fff;
    background-position: 0 50%;
    color: #000;
    padding-left: 18px;
    width: 220px;
    margin-right: 10px;
}
</style>
</head>
<body>
<?php echo "$status<br>\n";?>
<div>
<form action="<?php echo Zend_OpenId::selfUrl(); ?>"
    method="post" onsubmit="this.login.disabled=true;">
<fieldset id="openid">
<legend>OpenID Login</legend>
<input type="hidden" name="openid_action" value="login">
<div>
<input type="text" name="openid_identifier" class="openid_login" value="<?php echo $id;?>">
<input type="submit" name="login" value="login">
<table border="0" cellpadding="2" cellspacing="2">
<tr><td>&nbsp;</td><td>requird</td><td>optional</td><td>none</td><td>&nbsp</td></tr>
<?php echo "$ax_html<br>\n";?>
</table>
<br>
<a href="<?php echo dirname(Zend_OpenId::selfUrl()); ?>/test_server.php?openid.action=register">register</a>
</div>
</fieldset>
</form>
</div>
</body>
</html>
