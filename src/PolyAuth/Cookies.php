<?php

namespace PolyAuth;

use PolyAuth\Options;

class Cookies{

	protected $options;
	
	//setup some configuration
	public function __construct(Options $options){
	
		$this->options = $options;
		
	}
	
	//automatically adds the prefix in
	public function set_cookie($name = '', $value = '', $expire = ''){

		if(!is_numeric($expire)){
			$expire = time() - 86500;
		}else{
			$expire = ($expire > 0) ? time() + $expire : 0;
		}
		
		return setcookie($this->options['cookie_prefix'] . $name, $value, $expire, $this->options['cookie_path'], $this->options['cookie_domain'], $this->options['cookie_secure'], $this->options['cookie_httponly']);
		
	}
	
	public function get_cookie($index = ''){
	
		$prefix = isset($_COOKIE[$index]) ? '' : $this->options['cookie_prefix'];
		$index = $prefix . $index;
		return $this->fetch_from_array($_COOKIE, $index);
	
	}
	
	public function delete_cookie($name = ''){
	
		unset($_COOKIE[$name]);
		return $this->set_cookie($name, '', '');
		
	}
	
	protected function fetch_from_array(&$array, $index = ''){
	
		if(isset($array[$index])){
		
			$value = $array[$index];
			
		}elseif(($count = preg_match_all('/(?:^[^\[]+)|\[[^]]*\]/', $index, $matches)) > 1){
		
			$value = $array;
			for ($i = 0; $i < $count; $i++){
			
				$key = trim($matches[0][$i], '[]');
				// Empty notation will return the value as array
				if($key === ''){
					break;
				}

				if(isset($value[$key])){
					$value = $value[$key];
				}else{
					return NULL;
				}
				
			}
			
		}else{
		
			return NULL;
		
		}
		
		return $value;
		
	}

}