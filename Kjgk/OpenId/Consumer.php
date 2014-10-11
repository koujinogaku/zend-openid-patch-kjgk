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
 * @subpackage Zend_OpenId_Consumer
 * @copyright  Copyright (c) 2005-2009 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 */

/**
 * Modified openid consumer to be spec 2.0 compliant
 *
 * @author Akeem Philbert <akeem.philbert@gmail.com>
 * @copyright Copyright (c) 2009 Akeem Philbert
 * @modifier Koujinogaku <http://koujinogaku.blog9.fc2.com/>
 * @copyright Copyleft (c) 2011 Koujinogaku
 */
class Kjgk_OpenId_Consumer extends Zend_OpenId_Consumer
{
    const MODE_DISCOVERY_HTML  = 1;
    const MODE_DISCOVERY_XRI   = 2;
    const MODE_DISCOVERY_YADIS = 3;
    const NAMESPACE_AUTH_20_SERVER = 'http://specs.openid.net/auth/2.0/server';
    const NAMESPACE_AUTH_20_SIGNON = 'http://specs.openid.net/auth/2.0/signon';
    const NAMESPACE_AUTH_20_IDENTIFIER_SELECT = 'http://specs.openid.net/auth/2.0/identifier_select';

    /**
     * Create (or reuse existing) association between OpenID consumer and
     * OpenID server based on Diffie-Hellman key agreement. Returns true
     * on success and false on failure.
     *
     * @param string $url OpenID server url
     * @param float $version OpenID protocol version
     * @param string $priv_key for testing only
     * @return bool
     */
    protected function _associate($url, $version, $priv_key=null)
    {

        /* Check if we already have association in chace or storage */
        if ($this->_getAssociation(
                $url,
                $handle,
                $macFunc,
                $secret,
                $expires)) {
            return true;
        }

        if ($this->_dumbMode) {
            /* Use dumb mode */
            return true;
        }

        $params = array();

        if ($version >= 2.0) {
            $params = array(
                'openid.ns'           => Zend_OpenId::NS_2_0,
                'openid.mode'         => 'associate',
                'openid.assoc_type'   => 'HMAC-SHA256',
                'openid.session_type' => 'DH-SHA256',
            );
        } else {
            $params = array(
                'openid.mode'         => 'associate',
                'openid.assoc_type'   => 'HMAC-SHA1',
                'openid.session_type' => 'DH-SHA1',
            );
        }

        $dh = Zend_OpenId::createDhKey(pack('H*', Zend_OpenId::DH_P),
                                       pack('H*', Zend_OpenId::DH_G),
                                       $priv_key);
        $dh_details = Zend_OpenId::getDhKeyDetails($dh);

        $params['openid.dh_modulus']         = base64_encode(
            Zend_OpenId::btwoc($dh_details['p']));
        $params['openid.dh_gen']             = base64_encode(
            Zend_OpenId::btwoc($dh_details['g']));
        $params['openid.dh_consumer_public'] = base64_encode(
            Zend_OpenId::btwoc($dh_details['pub_key']));

        while(1) {
            $ret = $this->_httpRequest($url, 'POST', $params, $status, $headers);
            if ($ret === false) {
                $this->_setError("HTTP request failed");
                return false;
            }
            $r = array();
            $bad_response = false;
            foreach(explode("\n", $ret) as $line) {
                $line = trim($line);
                if (!empty($line)) {
                    $x = explode(':', $line, 2);
                    if (is_array($x) && count($x) == 2) {
                        list($key, $value) = $x;
                        $r[trim($key)] = trim($value);
                    } else {
                        $bad_response = true;
                    }
                }
            }
            if ($bad_response && strpos($ret, 'Unknown session type') !== false) {
                $r['error_code'] = 'unsupported-type';
            }
            $ret = $r;

            if (isset($ret['error_code']) &&
                $ret['error_code'] == 'unsupported-type') {
                if ($params['openid.session_type'] == 'DH-SHA256') {
                    $params['openid.session_type'] = 'DH-SHA1';
                    $params['openid.assoc_type'] = 'HMAC-SHA1';
                } else if ($params['openid.session_type'] == 'DH-SHA1') {
                    $params['openid.session_type'] = 'no-encryption';
                } else {
                    $this->_setError("The OpenID service responded with: " . $ret['error_code']);
                    return false;
                }
            } else {
                break;
            }
        }

        if ($status != 200) {
            $this->_setError("The server responded with status code: " . $status);
            return false;
        }

        if ($version >= 2.0 &&
            isset($ret['ns']) &&
            $ret['ns'] != Zend_OpenId::NS_2_0) {
            $this->_setError("Wrong namespace definition in the server response");
            return false;
        }

        if (!isset($ret['assoc_handle']) ||
            !isset($ret['expires_in']) ||
            !isset($ret['assoc_type']) /********************||
            $params['openid.assoc_type'] != $ret['assoc_type']*********/) {
            //if ($params['openid.assoc_type'] != $ret['assoc_type']) {
            //    $this->_setError("The returned assoc_type differed from the supplied openid.assoc_type");
            //} else {
                $this->_setError("Missing required data from provider (assoc_handle, expires_in, assoc_type are required)");
            //}
            return false;
        }

        $handle     = $ret['assoc_handle'];
        $expiresIn = $ret['expires_in'];

        if ($ret['assoc_type'] == 'HMAC-SHA1') {
            $macFunc = 'sha1';
        } else if ($ret['assoc_type'] == 'HMAC-SHA256' &&
            $version >= 2.0) {
            $macFunc = 'sha256';
        } else {
            $this->_setError("Unsupported assoc_type");
            return false;
        }

        if ((empty($ret['session_type']) ||
             ($version >= 2.0 && $ret['session_type'] == 'no-encryption')) &&
             isset($ret['mac_key'])) {
            $secret = base64_decode($ret['mac_key']);
        } else if (isset($ret['session_type']) &&
            $ret['session_type'] == 'DH-SHA1' &&
            !empty($ret['dh_server_public']) &&
            !empty($ret['enc_mac_key'])) {
            $dhFunc = 'sha1';
        } else if (isset($ret['session_type']) &&
            $ret['session_type'] == 'DH-SHA256' &&
            $version >= 2.0 &&
            !empty($ret['dh_server_public']) &&
            !empty($ret['enc_mac_key'])) {
            $dhFunc = 'sha256';
        } else {
            $this->_setError("Unsupported session_type");
            return false;
        }
        if (isset($dhFunc)) {
            $serverPub = base64_decode($ret['dh_server_public']);
            $dhSec = Zend_OpenId::computeDhSecret($serverPub, $dh);
            if ($dhSec === false) {
                $this->_setError("DH secret comutation failed");
                return false;
            }
            $sec = Zend_OpenId::digest($dhFunc, $dhSec);
            if ($sec === false) {
                $this->_setError("Could not create digest");
                return false;
            }
            $secret = $sec ^ base64_decode($ret['enc_mac_key']);
        }
        if ($macFunc == 'sha1') {
            if (Zend_OpenId::strlen($secret) != 20) {
                $this->_setError("The length of the sha1 secret must be 20");
                return false;
            }
        } else if ($macFunc == 'sha256') {
            if (Zend_OpenId::strlen($secret) != 32) {
                $this->_setError("The length of the sha256 secret must be 32");
                return false;
            }
        }
        $this->_addAssociation(
            $url,
            $handle,
            $macFunc,
            $secret,
            time() + $expiresIn);
        return true;
    }

    /**
     * Performs discovery of identity and finds OpenID URL, OpenID server URL
     * and OpenID protocol version. Returns true on succees and false on
     * failure.
     *
     * @param string &$id OpenID identity URL
     * @param string &$server OpenID server URL
     * @param float &$version OpenID protocol version
     * @return bool
     * @todo OpenID 2.0 (7.3) XRI and Yadis discovery
     */
    protected function _discovery(&$id, &$server, &$version)
    {
        $realId = $id;
        if ($this->_storage->getDiscoveryInfo(
                $id,
                $realId,
                $server,
                $version,
                $expire)) {
            $id = $realId;
            return true;
        }

        /* TODO: OpenID 2.0 (7.3) XRI and Yadis discovery */
        /* Modify: koujinogaku for OpenID 2.0 XRI and Yadis discovery (only google.com & mixi.jp) */
        $discovery_mode = false;

        $response = $this->_httpRequest($id, 'GET', array(), $status, $headers);
        if ($status != 200 || !is_string($response)) {
            $this->_setError("HTTP Response is {$status}");
            return false;
        }

        /* Check XRDS-based discovery */
        if($discovery_mode===false) {
            foreach($headers as $key => $val) {
                if(strtolower($key)=='content-type' && strpos(strtolower($val),'application/xrds+xml')!==false) {
                    $discovery_mode = self::MODE_DISCOVERY_XRI;
                    break;
                }
                if(strtolower($key)=='x-xrds-location') {
                    $discovery_mode = self::MODE_DISCOVERY_YADIS;
                    $xrdsLocation = $val;
                    break;
                }
            }
            if($discovery_mode===false) {
                $this->_setError("Discovery mode is not found");
                return false;
            }

        }

        /* Check HTML-based discovery or HTML-based Yadis */
        if($discovery_mode===false) {
          $discovery_mode = $this->_discoveryMatchHtml($response, $id, $realId, $server, $version, $xrdsLocation);
        }

        switch($discovery_mode) {
            case self::MODE_DISCOVERY_HTML;
              break;
            case self::MODE_DISCOVERY_YADIS;
                $response = $this->_httpRequest($xrdsLocation, 'GET', array(), $status, $headers);
                if ($status != 200 || !is_string($response)) {
                    $this->_setError("HTTP Response is {$status} for XRDS");
                    return false;
                }
            case self::MODE_DISCOVERY_XRI;
                $r = $this->_discoveryMatchXRDS($response, $id, $realId, $server, $version);
                if($r===false) {
                    $this->_setError("XRDS is not found");
                    return false;
                }
        }

        $expire = time() + 60 * 60;
        $this->_storage->addDiscoveryInfo($id, $realId, $server, $version, $expire);
        $id = $realId;

        return true;
    }
    protected function _discoveryMatchHtml($response, &$id, &$realId, &$server, &$version, &$xrdsLocation)
    {
        if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.provider[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 2.0;
            $server = $r[3];
        } else if (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.provider[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 2.0;
            $server = $r[2];
        } else if (preg_match(
                '/<meta[^>]*http-equiv[ \t]*=[ \t]*["\']x-xrds-location["\'][ \t]*content[ \t]=[ \t]["\']([^"\'])/i',
                $response,
                $r)) {
            $version = 2.0;
            $xrdsLocation = $r[1];
            return self::MODE_DISCOVERY_YADIS;
        } else if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.server[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 1.1;
            $server = $r[3];
        } else if (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.server[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 1.1;
            $server = $r[2];
        } else {
            return false;
        }
        if ($version >= 2.0) {
            if (preg_match(
                    '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[3];
            } else if (preg_match(
                    '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\3[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[2];
            }
        } else {
            if (preg_match(
                    '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[3];
            } else if (preg_match(
                    '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\3[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[2];
            }
        }

        return self::MODE_DISCOVERY_HTML;
    }

    protected function _discoveryMatchXRDS($response, &$id, &$realId, &$server, &$version)
    {
        $discoveryMode = false;
        $xrd = simplexml_load_string($response);
        if(!isset($xrd->XRD->Service))
            return false;

        foreach($xrd->XRD->Service as $service) {
            foreach($service->Type as $type) {
                $typestr = strval($type);
                if($discoveryMode === false &&
                   ($typestr == self::NAMESPACE_AUTH_20_SERVER ||
                    $typestr == self::NAMESPACE_AUTH_20_SIGNON    ) )
                {
                    $version = 2.0;
                    $server = strval($service->URI);
                    $discoveryMode = self::MODE_DISCOVERY_XRI;
                    return $discoveryMode;
                }
            }
        }
            return $discoveryMode;
    }

    /**
     * Performs check of OpenID identity.
     *
     * This is the first step of OpenID authentication process.
     * On success the function does not return (it does HTTP redirection to
     * server and exits). On failure it returns false.
     *
     * @param bool $immediate enables or disables interaction with user
     * @param string $id OpenID identity
     * @param string $returnTo HTTP URL to redirect response from server to
     * @param string $root HTTP URL to identify consumer on server
     * @param mixed $extensions extension object or array of extensions objects
     * @param Zend_Controller_Response_Abstract $response an optional response
     *  object to perform HTTP or HTML form redirection
     * @return bool
     */
    protected function _checkId($immediate, $id, $returnTo=null, $root=null,
        $extensions=null, Zend_Controller_Response_Abstract $response = null, $authRequest = true)
    {

        $this->_setError('');

        if (!Zend_OpenId::normalize($id)) {
            $this->_setError("Normalisation failed");
            return false;
        }
        $claimedId = $id;
        if (!$this->_discovery($id, $server, $version)) {
            $this->_setError("Discovery failed: " . $this->getError());
            return false;
        }
        if (!$this->_associate($server, $version)) {
            $this->_setError("Association failed: " . $this->getError());
            return false;
        }
        if (!$this->_getAssociation(
                $server,
                $handle,
                $macFunc,
                $secret,
                $expires)) {
            /* Use dumb mode */
            unset($handle);
            unset($macFunc);
            unset($secret);
            unset($expires);
        }

        $params = array();
        if ($version >= 2.0) {
            $params['openid.ns'] = Zend_OpenId::NS_2_0;
        }

        $params['openid.mode'] = $immediate ?
            'checkid_immediate' : 'checkid_setup';

        $params['openid.identity'] = $id;

        $params['openid.claimed_id'] = $claimedId;

        if ($version < 2.0 || ( $version == 2.0 && $authRequest==false) ) {
            if (isset($this->_session) && $this->_session !== null) {
                $this->_session->identity = $id;
                $this->_session->claimed_id = $claimedId;
            } else if (defined('SID')) {
                $_SESSION["zend_openid"] = array(
                    "identity" => $id,
                    "claimed_id" => $claimedId);
            } else {
                require_once "Zend/Session/Namespace.php";
                $this->_session = new Zend_Session_Namespace("zend_openid");
                $this->_session->identity = $id;
                $this->_session->claimed_id = $claimedId;
            }
        }
        else if ($version == 2.0 && $authRequest==true) {
            if (isset($this->_session) && $this->_session !== null) {
                $this->_session->identity = self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT;
                $this->_session->claimed_id = self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT;
            } else if (defined('SID')) {
                $_SESSION["zend_openid"] = array(
                    "identity"   => self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT,
                    "claimed_id" => self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT);
            } else {
                require_once "Zend/Session/Namespace.php";
                $this->_session = new Zend_Session_Namespace("zend_openid");
                $this->_session->identity = $id;
                $this->_session->claimed_id = $claimedId;
                $params['openid.identity'] = self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT;
                $params['openid.claimed_id'] = self::NAMESPACE_AUTH_20_IDENTIFIER_SELECT;
            }
        }

        if (isset($handle)) {
            $params['openid.assoc_handle'] = $handle;
        }

        $params['openid.return_to'] = Zend_OpenId::absoluteUrl($returnTo);

        if (empty($root)) {
            $root = Zend_OpenId::selfUrl();
            if ($root[strlen($root)-1] != '/') {
                $root = dirname($root);
            }
        }
        if ($version >= 2.0) {
            $params['openid.realm'] = $root;
        } else {
            $params['openid.trust_root'] = $root;
        }

        if (!Zend_OpenId_Extension::forAll($extensions, 'prepareRequest', $params)) {
            $this->_setError("Extension::prepareRequest failure");
            return false;
        }

        Zend_OpenId::redirect($server, $params, $response);
        return true;
    }

    /**
     * Performs check (with possible user interaction) of OpenID identity.
     *
     * This is the first step of OpenID authentication process.
     * On success the function does not return (it does HTTP redirection to
     * server and exits). On failure it returns false.
     *
     * @param string $id OpenID identity
     * @param string $returnTo URL to redirect response from server to
     * @param string $root HTTP URL to identify consumer on server
     * @param mixed $extensions extension object or array of extensions objects
     * @param Zend_Controller_Response_Abstract $response an optional response
     *  object to perform HTTP or HTML form redirection
     * @return bool
     */
    public function login($id, $returnTo = null, $root = null, $extensions = null,
                          Zend_Controller_Response_Abstract $response = null, $authRequest = true)
    {
        return $this->_checkId(
            false,
            $id,
            $returnTo,
            $root,
            $extensions,
            $response,
            $authRequest);
    }


    /**
     * Performs HTTP request to given $url using given HTTP $method.
     * Send additinal query specified by variable/value array,
     * On success returns HTTP response without headers, false on failure.
     *
     * @param string $url OpenID server url
     * @param string $method HTTP request method 'GET' or 'POST'
     * @param array $params additional qwery parameters to be passed with
     * @param int &$staus HTTP status code
     *  request
     * @return mixed
     */
    protected function _httpRequest($url, $method = 'GET', array $params = array(), &$status = null, &$headers = null)
    {
        if(isset($this->_httpClient))
          $client = $this->_httpClient;
        else
          $client = null;
        if ($client === null) {
            $client = new Zend_Http_Client(
                    $url,
                    array(
                        'maxredirects' => 4,
                        'timeout'      => 15,
                        'useragent'    => 'Zend_OpenId'
                    )
                );
        } else {
            $client->setUri($url);
        }

        $client->resetParameters();
        if ($method == 'POST') {
            $client->setMethod(Zend_Http_Client::POST);
            $client->setParameterPost($params);
        } else {
            $client->setMethod(Zend_Http_Client::GET);
            $client->setParameterGet($params);
        }

        try {
            $response = $client->request();
        } catch (Exception $e) {
            $this->_setError('HTTP Request failed: ' . $e->getMessage());
            return false;
        }
        $status = $response->getStatus();
        $body = $response->getBody();
        if ($status == 200 || ($status == 400 && !empty($body))) {
            $headers = $response->getHeaders();
            return $body;
        }else{
            $this->_setError('Bad HTTP response');
            return false;
        }
    }



}
