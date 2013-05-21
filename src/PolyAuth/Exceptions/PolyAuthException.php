<?php

namespace PolyAuth\Exceptions;

class PolyAuthException extends \Exception {

	protected $errors_array = array();

	public function append_error($error) {
		$this->errors_array[] = $error;
	}

	public function get_errors() {
		return $this->errors_array;
	}

}