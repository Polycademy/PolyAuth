<?php

namespace PolyAuth\Accounts;

class BcryptFallback{

	private $rounds;
	private $random_state;
	
	public function __construct($rounds = 8){
	
		if(CRYPT_BLOWFISH != 1) {
			throw new Exception('Bcrypt is not supported on this PHP installation! See http://php.net/crypt');
		}
		$this->rounds = $rounds;
		
	}

	public function hash($input){
	
		$hash = crypt($input, $this->get_salt());
		if(strlen($hash) > 13){
			return $hash;
		}
		return false;
		
	}

	public function verify($input, $existing_hash) {
	
		$hash = crypt($input, $existing_hash);
		return ($hash === $existing_hash);
		
	}

	private function get_salt() {
	
		$salt = sprintf('$2a$%02d$', $this->rounds);
		$bytes = $this->get_random_bytes(16);
		$salt .= $this->encode_bytes($bytes);
		return $salt;
		
	}

	private function get_random_bytes($count) {
	
		$bytes = '';
		if(function_exists('openssl_random_pseudo_bytes') && (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN')){
			// OpenSSL slow on Win
			$bytes = openssl_random_pseudo_bytes($count);
		}

		if($bytes === '' && @is_readable('/dev/urandom') && ($hRand = @fopen('/dev/urandom', 'rb')) !== FALSE){
			$bytes = fread($hRand, $count);
			fclose($hRand);
		}

		if(strlen($bytes) < $count) {
		
			$bytes = '';
			
			if($this->random_state === null) {
				$this->random_state = microtime();
				if(function_exists('getmypid')) {
					$this->random_state .= getmypid();
				}
			}
			
			for($i = 0; $i < $count; $i += 16) {
				$this->random_state = md5(microtime() . $this->random_state);
				if (PHP_VERSION >= '5') {
					$bytes .= md5($this->random_state, true);
				} else {
					$bytes .= pack('H*', md5($this->random_state));
				}
			}
			
			$bytes = substr($bytes, 0, $count);
			
		}
		
		return $bytes;
		
	}

	private function encode_bytes($input){
	
		// The following is code from the PHP Password Hashing Framework
		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		$output = '';
		$i = 0;
		
		do {
			$c1 = ord($input[$i++]);
			$output .= $itoa64[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			if ($i >= 16) {
				$output .= $itoa64[$c1];
				break;
			}
			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $itoa64[$c1];
			$c1 = ($c2 & 0x0f) << 2;
			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $itoa64[$c1];
			$output .= $itoa64[$c2 & 0x3f];
		} while (1);
		
		return $output;
		
	}
	
}