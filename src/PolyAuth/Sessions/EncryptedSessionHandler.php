<?php

namespace PolyAuth\Sessions;

use PolyAuth\Security\Encryption;

class EncryptedSessionHandler extends \SessionHandler{

	protected $key;
	protected $encryption;
	
	public function __construct($key, Encryption $encryption = null){
		$this->key = $key;
		$this->encryption = ($encryption) ? $encryption : new Encryption;
	}

	public function read($id){
		$data = parent::read($id);
		return $this->encryption->decrypt($data, $this->key);
	}

	public function write($id, $data){
		$data = $this->encryption->encrypt($data, $this->key);	
		return parent::write($id, $data);
	}
	
}