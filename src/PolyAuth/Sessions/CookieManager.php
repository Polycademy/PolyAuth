<?php

//replicates CI's cookie styles

namespace PolyAuth;

class CookieManager{

	protected $options;
	
	//setup some configuration
	public function __construct($domain = '', $path = '/', $prefix = '', $secure = false, $httponly = false){
	
		$this->options = array(
			'domain'	=> $domain,
			'path'		=> $path,
			'prefix'	=> $prefix,
			'secure'	=> $secure,
			'httponly'	=> $httponly,
		);
		
	}
	
	//automatically adds the prefix in
	public function set_cookie($name = '', $value = '', $expire = ''){

		if(!is_numeric($expire)){
			$expire = time() - 86500;
		}else{
			$expire = ($expire > 0) ? time() + $expire : 0;
		}

		setcookie($this->options['prefix'] . $name, $value, $expire, $this->options['path'], $this->options['domain'], $this->options['secure'], $this->options['httponly']);
		
	}
	
	public function get_cookie($index = ''){
	
		$prefix = isset($_COOKIE[$index]) ? '' : $this->options['prefix'];
		$index = $prefix . $index;
		return $this->fetch_from_array($_COOKIE, $index);
	
	}
	
	public function delete_cookie($name = ''){
	
		$this->set_cookie($name, '', '');
		
	}
	
	protected function fetch_from_array(&$array, $index = ''){
	
		if (isset($array[$index])){
		
			$value = $array[$index];
			
		}elseif (($count = preg_match_all('/(?:^[^\[]+)|\[[^]]*\]/', $index, $matches)) > 1){
		
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