<?php

namespace nolbertovilchez\sdk\padlock;

use nolbertovilchez\http\Response as HttpResponse;

class Http {

    public static $AUTHORIZATION_HEADER_NAME            = "Authorization";
    public static $DATE_HEADER_NAME                     = "X-Padlock-Date";
    public static $AUTHORIZATION_METHOD                 = "PADLOCK";
    public static $AUTHORIZATION_HEADER_FIELD_SEPARATOR = " ";
    public static $X_PADLOCK_HEADER_PREFIX              = "X-Padlock-";
    public static $UTC_STRING_FORMAT                    = "Y-m-d H:i:s";
    private static $X_PADLOCK_HEADER_SEPARATOR          = ":";
    private static $HMAC_ALGORITHM                      = "sha1";
    private $_authKey;
    private $_authSecret;

    public function __construct($authKey, $authSecret) {
        $this->_authKey    = $authKey;
        $this->_authSecret = $authSecret;
    }

    public function init($method, $url, $headers, $params) {
        $curlHeaders = array();
        foreach ($headers as $hkey => $hvalue) {
            array_push($curlHeaders, $hkey . ":" . $hvalue);
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        if ($method == "PUT" || $method == "POST") {
            $params_string = self::getSerializedParams($params);
            rtrim($params_string, '&');
            curl_setopt($ch, CURLOPT_POST, count($params));
            curl_setopt($ch, CURLOPT_POSTFIELDS, $params_string);
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

        $response = curl_exec($ch);
//        echo "<pre>"; print_r($response);die();
        curl_close($ch);

        return $response;
    }

    public function GET_proxy($url) {
        return new HttpResponse($this->init("GET", $url, $this->authenticationHeaders("GET", $url, null), null));
    }

    public function POST_proxy($url, $params) {
        return new HttpResponse($this->init("POST", $url, $this->authenticationHeaders("POST", $url, null, null, $params), $params));
    }

    public function PUT_proxy($url, $params) {
        return new HttpResponse($this->init("PUT", $url, $this->authenticationHeaders("PUT", $url, null, null, $params), $params));
    }

    public function DELETE_proxy($url) {
        return new HttpResponse($this->init("DELETE", $url, $this->authenticationHeaders("DELETE", $url, null), null));
    }

    public function authenticationHeaders($HTTPMethod, $queryString, $xHeaders = null, $utc = null, $params = null) {
        $utc = trim(($utc != null) ? $utc : $this->getCurrentUTC());

        $stringToSign = trim(strtoupper($HTTPMethod)) . "\n" .
                $utc . "\n" .
                $this->getSerializedHeaders($xHeaders) . "\n" .
                trim($queryString);

        if ($params != null && sizeof($params) > 0) {
            $serializedParams = $this->getSerializedParams($params);
            if ($serializedParams != null && sizeof($serializedParams) > 0) {
                $stringToSign = trim($stringToSign . "\n" . $serializedParams);
            }
        }

        $authorizationHeader = self::$AUTHORIZATION_METHOD .
                self::$AUTHORIZATION_HEADER_FIELD_SEPARATOR .
                $this->_authKey .
                self::$AUTHORIZATION_HEADER_FIELD_SEPARATOR .
                $this->signData($stringToSign);

        $headers                                   = array();
        $headers[self::$AUTHORIZATION_HEADER_NAME] = $authorizationHeader;
        $headers[self::$DATE_HEADER_NAME]          = $utc;
        return $headers;
    }

    private function getSerializedHeaders($xHeaders) {
        $result_to_return = "";
        $error            = false;
        if ($xHeaders != null) {
            $headers           = array_change_key_case($xHeaders, CASE_LOWER);
            ksort($headers);
            $serializedHeaders = "";
            foreach ($headers as $key => $value) {
                if (strncmp(strtolower($key), strtolower(self::$X_PADLOCK_HEADER_PREFIX), strlen(self::$X_PADLOCK_HEADER_PREFIX)) == 0) {
                    error_log("Error serializing headers. Only specific " . self::$X_PADLOCK_HEADER_PREFIX . " headers need to be singed");
                    $error = true;
                    break;
                } else {
                    $serializedHeaders .= $key . self::$X_PADLOCK_HEADER_SEPARATOR . $value . " ";
                }
            }
            if ($error === false) {
                $result_to_return = trim($serializedHeaders, "utf-8");
            }
        }
        return $result_to_return;
    }

    private function getSerializedParams($params) {
        $result = "";
        if ($params != null && !empty($params)) {
            ksort($params);
            $serializedParams = "";
            foreach ($params as $key => $value) {
                if (gettype($value) == "array" && !empty($value)) {
                    ksort($params[$key]);
                    foreach ($params[$key] as $value2) {
                        if (gettype($value2) == "string") {
                            $serializedParams .= $key . "=" . $value2 . "&";
                        }
                    }
                } else {
                    $serializedParams .= $key . "=" . $params[$key] . "&";
                }
            }
            $result = trim($serializedParams, "&");
        }
        return $result;
    }

    private function signData($data) {
        return base64_encode(hash_hmac(self::$HMAC_ALGORITHM, $data, $this->_authSecret, true));
    }

    private function getCurrentUTC() {
        return date(self::$UTC_STRING_FORMAT);
    }

}
