<?php

namespace PolyAuth\Storage;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;

//RBAC's interface

//OAuth's interface
use OAuth\Common\Storage\TokenStorageInterface;

interface StorageInterface extends LoggerAwareInterface, TokenStorageInterface{

	/**
	 * Sets a logger instance on the object
	 */
	public function setLogger(LoggerInterface $logger);

}