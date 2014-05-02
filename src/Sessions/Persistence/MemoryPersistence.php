<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\Ephemeral;
use Stash\Pool;

/**
 * Memory Persistence is the most basic session persistence. The session is persisted during the execution of PHP.
 * In single request single response and new process per request architectures, the garbage collection is handled 
 * by finishing the execution and killing the process. However in event driven daemons, you'll need to regularly 
 * purge the expired sessions in memory to avoid a memory leak.
 */
class MemoryPersistence extends AbstractPersistence{

	public function __construct(Ephemeral $driver = null, Pool $cache = null){
	
		$driver = ($driver) ? $driver : new Ephemeral();
		$cache = ($cache) ? $cache : new Pool();
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = ''; //memory is already unique, so no need for a particular namespace
	
	}

}