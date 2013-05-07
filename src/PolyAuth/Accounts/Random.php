<?php

namespace PolyAuth\Accounts;

class Random{

	//generates a random token include A-Z,a-z,0-9 with spiecal it will also include all the weird characters!
	public function generate($length, $special = false){
	
		$token = "";
		$code_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$code_alphabet.= "abcdefghijklmnopqrstuvwxyz";
		$code_alphabet.= "0123456789";
		
		if($special){
			$code_alphabet .= '<,>./?;:\'"{[}]|\\-_+=)(*&^%$#@!`~';
		}
		
		for($i=0;$i<$length;$i++){
			$token .= $code_alphabet[crypto_rand_secure(0, strlen($code_alphabet))];
		}
		
		return $token;
		
	}
	
	protected function crypto_rand_secure($min, $max) {
	
		$range = $max - $min;
		if ($range < 0) return $min; // not so random...
		$log = log($range, 2);
		$bytes = (int) ($log / 8) + 1; // length in bytes
		$bits = (int) $log + 1; // length in bits
		$filter = (int) (1 << $bits) - 1; // set all lower bits to 1
		do {
			$rnd = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes)));
			$rnd = $rnd & $filter; // discard irrelevant bits
		} while ($rnd >= $range);
		return $min + $rnd;
		
	}

}