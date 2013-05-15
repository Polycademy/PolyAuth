<?php

namespace PolyAuth\Security;
	
/**
 * This encryption class serialises data and encrypts with a given key. It can of course do the opposite. This is not for password hashing.
 * PolyAuth will be using this in order to encrypt cookie and session data.
 * Such as the autologin token, and generally PHP session data. The PHPSESSID will not be encrypted.
 */
class Encryption{

	public function encrypt($data, $key){
	
		$data = serialize($data);
		return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($key), $data, MCRYPT_MODE_CBC, md5(md5($key))));

	}
	
	public function decrypt($data, $key){
	
		$data = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key), base64_decode($data), MCRYPT_MODE_CBC, md5(md5($key))), "\0");
		return unserialize($data);
	
	}

}