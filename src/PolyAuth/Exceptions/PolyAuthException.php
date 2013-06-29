<?php

namespace PolyAuth\Exceptions;

class PolyAuthException extends \Exception {

	protected $errors_array = array();

	/**
	 * This appends an error to an array of errors. This can be useful for multiple errors at the same time.
	 * @param  string $error message of the error
	 */
	public function append_error($error) {
		$this->errors_array[] = $error;
	}

	/**
	 * This gets an array of all errors. It incorporates the basic single message error of most exceptions.
	 * This way you only have to use get_errors() regardless of whether it's multiple errors or a single error.
	 * @return array array of errors
	 */
	public function get_errors() {
		if(!empty($this->message)){
			$this->append_error($this->message);
		}
		return $this->errors_array;
	}

}