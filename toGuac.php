<?php

namespace IMDCDevOps;

// error_reporting(E_ALL);   
// ini_set('display_errors', 1);

/**
 * Classes defintion file for Teampass & Guacamole
 *
 * PHP version 7.2  
 *
 * @category   ISDevOps 
 * @package    IMDCDevOps-Guac
 * @author     Reynald GIL <reynald.gil@gmail.com>
 * @author     Reynald GIL <reynald.gil@gmail.com>
 * @copyright  1997-2018 The IMDC team
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version    SVN: $Id$
 * @link       http://pear.php.net/package/PackageName
 * @see        NetOther, Net_Sample::Net_Sample()
 * @since      File available since Release 1.2.0
 * @deprecated File deprecated in Release 2.0.0
 */

// require '../vendor/autoload.php';
require_once $SETTINGS['cpassman_dir'].'/includes/libraries/guacamole/vendor/autoload.php';

use GuzzleHttp\Client as Client;
use GuzzleHttp\RequestOptions as RequestOptions;
use GuzzleHttp\Exception\RequestException as ResquestException;
use GuzzleHttp\Psr7\Request as Request;
/**
 * Guacamole Class to ask token to Guacamole
 *  
 * ToGuacamole.php
 *   
 * @category Class
 * @package  SG4Guacamole
 * @author   Display Name <reynald.gil@saint-gobain.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     http://www.hashbangcode.com/
 */
 
class Guacamole
{
    
    const OPENSSL_CIPHER_NAME = 'aes-128-cbc'; 
    const CIPHER_KEY_LEN = 16; //Cypher lenhgt 16 for AES 128 bits 
    const INIT_VECTOR = "00000000000000000000000000000000"; //initialization Vector
    const SSH = "ssh";
    const RDP = "rdp";

    /**  
     * Fix Key lenght
     * 
     * @param string $key key to shortened
     * 
     * @return string Shortened key
     */  
    public static function fixKey($key) 
    {  
        if (strlen($key) < self::CIPHER_KEY_LEN) {
            //0 pad to len 16
            return str_pad("$key", self::CIPHER_KEY_LEN, "0");
        }
        if (strlen($key) > self::CIPHER_KEY_LEN) {
            //truncate to 16 bytes
            return substr($key, 0, self::CIPHER_KEY_LEN);
        }
        return $key;
    }

    /**  
     * Parse Host Guacamole
     * 
     * @param string $url url of host 
     * 
     * @return array Shortened key
     */  
    public static function parseUrl($url) 
    {  
        $parsed = parse_url($url);
        
        if ($parsed['scheme'] <> self::SSH && $parsed['scheme'] <> self::RDP) {
            $parsed = "";
        }
        return $parsed;
    }

    /**
     * Handling HTTP errors when calling Guacd API
     * 
     * @param string $e Exception object from gazzleHTTP
     * 
     * @return string Response of error
     */
    public static function statusCodeHandling($e)
    {
        // echo $e->getResponse()->getStatusCode();
        if ($e->getResponse()->getStatusCode() == '400') {
            
        } elseif ($e->getResponse()->getStatusCode() == '422') {
            $response = json_decode($e->getResponse()->getBody(true)->getContents());
            return $response;
        } elseif ($e->getResponse()->getStatusCode() == '500') {
            $response = json_decode($e->getResponse()->getBody(true)->getContents());
            return $response;
        } elseif ($e->getResponse()->getStatusCode() == '401') {
            $response = json_decode($e->getResponse()->getBody(true)->getContents());
            return $response;
        } elseif ($e->getResponse()->getStatusCode() == '403') {
            $response = json_decode($e->getResponse()->getBody(true)->getContents());
            return $response;
        } else {
            $response = json_decode($e->getResponse()->getBody(true)->getContents());
            return $response;
        }
    }


        
    /**  
     * AES Encrypt AES-128-CBC
     * 
     * @param string $data   data to be encrypted
     * @param string $secret secret key word for encryption
     * 
     * @return string aes-128-cbc Encrypted Data
     */  
    public static function aesEncrypt($data, $secret)
    {
        // if (!is_string($data)) {
        //     throw new \InvalidArgumentException('Input parameter "$data" must be a string.');
        // } 
        // if (!function_exists("openssl_encrypt")) {
        //     throw new \SimpleSAML_Error_Exception('The openssl PHP module is not loaded.');
        // }
        //HMAC Key in SHA256 && bin
        // $hmackey = hash("md5", $secret, false);
        // echo $hmackey;
        $hmackeyhex = hex2bin($secret);
        
        // last parameter is, again, whether or not to output raw bytes
        // $data = '{"username":"tecmint","expires":"1541461612000","connections":{"0":{"protocol":"ssh","parameters":{"hostname":"10.139.55.222","port":"22"}},"1":{"protocol":"rdp","parameters":{"hostname":"ampsv012fl0xd","port":"3389"}}}}'."\n";

        $iv = hex2bin(self::INIT_VECTOR);
        $aes = base64_encode(openssl_encrypt($data, self::OPENSSL_CIPHER_NAME, self::fixKey($hmackeyhex), OPENSSL_RAW_DATA, $iv));

        return $aes;
    }

    /**
     * Sign JsonData HMAC SHA256
     * 
     * @param string $jsonData of hosts Connections
     * @param string $secret   Secret 
     * 
     * @return $string Signed data in Hex
     */
    public static function signData($jsonData,$secret)
    {
        // Convert Secret to 128 bytes key
        // $key = hash("md5", $secret, false);
        
        //Secret Key need to be set as Binary for hash_hmac function
        $binkey = hex2bin($secret);
        
        //HMAC binary digest of jsonData  
        $s = hash_hmac('sha256', $jsonData, $binkey, true);

        return $s;
    }

    /**
     * Ping SSH Server
     * 
     * @param string $host hosts Connections
     * @param string $port Secret 
     * 
     * @return $string Signed data in Hex
     */
    public static function pingHost($host, $port) 
    {
        set_time_limit(0);   
        
        $fp = fsockopen($host, $port, $errno, $errstr, 300);
        if ($fp) {
            return $result = "UP";
        } else {
            return $result = "DOWN";
        }
    }
    
    /**
     * Add host connections
     * 
     * @param array $hosts comment 
     * 
     * @return string Connection array object
     */  
    public static function createConnections($hosts)
    {
        $connection     = new \stdClass();
        $parameters     = new \stdClass();
        $connections    = new \stdClass();
        $guacamole      = new \stdClass();

        foreach ($hosts as &$host ) {
            $parameters->hostname   = $host['hostname'];
            $parameters->port       = $host['port'];
            $parameters->username   = $host['username'];
            $parameters->password   = $host['password'];
            if ($host['protocol'] == 'rdp' 
                && strpos($parameters->username, 'LMA') !== false )
                //&& substr($_SESSION['login'],0,3) == 'R55' )
                {
                $parameters->security = 'nla';  
                //$parameters->domain = 'za';  
                $parameters->{'ignore-cert'} = 'true';
                //$parameters->{'resize-method'} = 'display-update';
                
                $parameters->{'resize-method'} = 'reconnect';
                //$parameters->username = $_SESSION['login'];
            }
            //$parameters->security = $parameters->username;
            $hostid                 = $host['hostid'];
            $connection->protocol   = $host['protocol'];
            //$connection->id         = '\''.uniqid().'\'';
            $connection->id         = uniqid();
            $connection->parameters = $parameters;           
            $connections->$hostid   = $connection;
        }
           
  
        // $guacamole->username    = htmlspecialchars_decode($host['username']);//"tecmint";
        $guacamole->username    = "guacadmin";
        unset($host);
        $time = time()*1000 + 2*3600*1000;
        //$guacamole->expires     = $time;
        $guacamole->connections = $connections;

        return json_encode($guacamole)."\n";
    }  


    /**
     * Get Guacamole Token
     * 
     * @param string $uri     Base Uri of Guacamole API 
     * @param string $encoded Signed data 
     * 
     * @return string Guacd Url for authentication
     */  
    public static function getToken($uri, $encoded)
    {
        try {
            $client = new Client(
            [
                // Base URI is used with relative requests
                'base_uri' => $uri, //'http://10.139.55.222:8080',
                // You can set any number of default request options.
                'timeout' => 2.0,
                'debug' => false,
                'allow_redirects' => [
                    'max'             => 5,        // allow at most 10 redirects.
                    'strict'          => false,      // use "strict" RFC compliant redirects.
                    'referer'         => true,      // add a Referer header
                    'protocols'       => ['https'], // only allow https URLs
                    'track_redirects' => true
                ]
            ]
            );  
            
            $response = $client->request(
                'POST', '/guacamole/api/tokens', 
                [
                    'headers'       => [
                        'Accept'        => 'application/json',
                        'cache-control' => 'no-cache',
                        'Content-Type'  => 'application/x-www-form-urlencoded'
                    ],
                    'form_params'   => [
                        'data' => $encoded
                    ]
                ]
            );
        }

        catch (RequestException $e)
        {
            
            $response = self::statusCodeHandling($e);
            
            return $response->message;
        }    
    
        $result = json_decode($response->getBody()->getContents());
        
        //Getting Access Token
        
            $access_token = $result->authToken;
            // $access_token = "";
        
        //http://10.139.55.222:8080
        $url = $uri."/guacamole/#/?token=".$access_token."\n";
        return $url;
    }
}
?>