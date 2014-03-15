<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\Ephemeral;
use Stash\Pool;

class MemoryPersistence extends AbstractPersistence{

	public function __construct(Ephemeral $driver = null, Pool $cache = null){
	
		$driver = ($driver) ? $driver : new Ephemeral();
		$cache = ($cache) ? $cache : new Pool();
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = ''; //memory is already unique, so no need for a particular namespace
	
	}

}