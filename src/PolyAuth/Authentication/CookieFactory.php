<?php

namespace PolyAuth\Authentication;

use Symfony\Component\HttpFoundation\Cookie;

class CookieFactory{

	protected $cookie_options;

	public function __construct(array $cookie_options){

		$this->cookie_options = $cookie_options;

	}

	public function create($name, $value, $lifetime = null, $path = null, $domain = null, $secure = null, $http_only = null){

		//$lifetime is the duration that cookies should be present
		if(is_null($lifetime)){
			//if null, then it's the default session cookie
			$expire = 0;
		}else{
			$expire = ($lifetime > 0) ? time() + $lifetime : 0;
		}

		if(is_null($path)){
			$path = $this->cookie_options['cookie_path'];
		}

		if(is_null($domain)){
			$domain = $this->cookie_options['cookie_domain'];
		}

		if(is_null($secure)){
			$secure = $this->cookie_options['cookie_secure'];
		}

		if(is_null($http_only)){
			$http_only = $this->cookie_options['cookie_httponly'];
		}

		return new Cookie($name, $value, $expire, $path, $domain, $secure, $http_only);

	}

}