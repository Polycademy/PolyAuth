<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\Ephemeral;
use Stash\Pool;

class Memory extends PersistenceAbstract{

	public function __construct(Ephemeral $driver = null, Pool $cache = null){
	
		$driver = ($driver) ? $driver : new Ephemeral();
		$cache = ($cache) ? $cache : new Pool();
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = 'PolyAuth/Memory/Sessions/';
	
	}

}