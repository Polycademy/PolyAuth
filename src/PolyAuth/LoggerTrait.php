<?php

namespace PolyAuth;

use Psr\Log\LoggerInterface;

trait LoggerTrait{

	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){
		$this->logger = $logger;
	}
	
}