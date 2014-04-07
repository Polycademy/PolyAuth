<?php

namespace PolyAuth\Exceptions;

use Exception;

class PolyAuthException extends Exception {

    protected $payload = null;

    /**
     * Constructs a PolyAuth Exception.
     * It is possible to construct the exception with an array such that:
     * [
     *     0    => 'message',
     *     1    => 'payload'
     * ]
     * The payload can be any value.
     * Assign exception codes using the constants.
     * 
     * @param string|array  $error    Error message string or an array containing a message and payload
     * @param integer       $code     Exception code
     * @param Exception     $previous Previous exception
     */
    public function __construct ($error = '', $code = 0, Exception $previous = null) {

        if (is_array($error)) {
            $message = $error[0];
            $payload = $error[1];
            $this->payload = $payload;
        } else {
            $message = $error;
        }

        parent::__construct($message, $code, $previous);

    }

    /**
     * Gets the payload
     * 
     * @return mixed
     */
    public function getPayload () {

        return $this->payload;
    
    }

    /**
     * Overrides parent::_toString() in order to potentially add serialized payload if it existed.
     * 
     * @return string
     */
    public function __toString () {

        $output = "exception '" . __CLASS__ . "' with message '{$this->getMessage()}'";
        if (!is_null($this->payload)) {
            $payload = json_encode($this->getPayload());
            if (!$payload) {
                $payload = 'Unencodable Value';
            }
            $output .= " and payload '$payload'";
        }
        $output .= " in {$this->getFile()} code:{$this->getCode()}\n";
        $output .= $this->getTraceAsString();

        return $output;

    }

}