<?php

namespace nolbertovilchez\sdk\padlock;

use nolbertovilchez\sdk\padlock\Padlock;
use nolbertovilchez\sdk\padlock\Http;

class PadlockUser extends Padlock {

    private $_username;
    private $_password;

    public function __construct($username, $password) {
        $this->_username = $username;
        $this->_password = $password;
    }

    public function login() {
        $http = new Http($this->_username, $this->_password);

        return $http->POST_proxy(self::$API_HOST . self::$API_LOGIN_USER, [
                    "username" => $this->_username,
                    "password" => $this->_password
        ]);
    }

}
