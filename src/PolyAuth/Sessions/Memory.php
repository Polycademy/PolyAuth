<?php

namespace PolyAuth\Sessions;

use Stash\Driver\Ephemeral;
use Stash\Pool;

class Memory{

	protected $cache;
	protected $namespace;

	public function __construct(Ephemeral $driver = null, Pool $cache = null){
	
		$driver = ($driver) ? $driver : new Ephemeral();
		$cache = ($cache) ? $cache : new Pool();
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = 'PolyAuth/Memory/Sessions/';
	
	}
	
	/**
	 * Gets an item in the cache.
	 */
	public function get($key){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->get();
	
	}
	
	/**
	 * Sets the item in the cache. Expiration is optional, and can be time in seconds, a datetime object or negative.
	 */
	public function set($key, $value){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->set($value);
	
	}
	
	/**
	 * This will check if a particular item exists. This is better than checking for null.
	 */
	public function exists($key){
	
		$item = $this->cache->getItem($this->namespace . $key);
		//opposite return
		return !$item->isMiss();
	
	}

	/**
	 * Clears the cache based on the key. If the key is not given, it will clear all of PolyAuth's memory sessions
	 */
	public function clear($key = false){
	
		if($key){
			$item = $this->cache->getItem($this->namespace . $key);
		}else{
			$item = $this->cache->getItem($this->namespace);
		}
		return $item->clear();
	
	}

}