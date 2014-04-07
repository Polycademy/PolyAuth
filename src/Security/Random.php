<?php

namespace PolyAuth\Security;

class Random{

	//generates a random token include at least one of each A-Z, a-z, 0-9 with special it will also include all the weird characters!
	public function generate($length, $special = false){
	
		$length = abs($length);
	
		//if it is 3, then it's not good if special is true (which requires 4 characters)
		//if it is 2 or less, then it's not good at all!
		if($length < 4 AND $special = true){
			return false;
		}elseif($length < 3){
			return false;
		}
		
		$token = '';
		$codes[0] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$codes[1] = "abcdefghijklmnopqrstuvwxyz";
		$codes[2] = "0123456789";
		
		
		if($special){
			$codes[3] = '<,>./?;:\'"{[}]|\\-_+=)(*&^%$#@!`~ ';
			$parts = 4;
		}else{
			$parts = 3;
		}
		
		//$iterations is an array integers which is dependent on the rounded up integer of $length divided by $parts
		for($i=0; $i<$parts; $i++){
			//we only have to worry about equal or greater by using ceil
			$iterations[$i] = ceil($length / $parts);
		}
		
		//if the the total number is greater than the original length, we need to reduce one or more of the integers
		if(array_sum($iterations) > $length){
		
			//total difference could be 1 or more
			$difference = array_sum($iterations) - $length;
			//we need to equally distribute the difference by 1 and minus them off the iteration integers
			for($i=0; $i<$difference; $i++){
				$iterations[$i] = $iterations[$i] - 1;
			}
		
		}
		
		foreach($codes as $key => $code){
		
			//the $iterations will cycle through each integer each time the foreach runs
			for($i = 0; $i < $iterations[$key]; $i++){
				//add to the token by a single character
				$token .= $code[$this->crypto_rand_secure(0, strlen($code))];
			}
		
		}
		
		$token = str_shuffle($token);
		
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