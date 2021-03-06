<?php

namespace PolyAuth\Sessions\Persistence;

abstract class AbstractPersistence{

	protected $cache;
	protected $namespace;
	
	/**
	 * Gets an item in the cache.
	 */
	public function get($key, $invalidation = 0, $arg1 = null, $arg2 = null){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->get($invalidation, $arg1, $arg2);
	
	}
	
	/**
	 * Sets the item in the cache. Expiration is optional, and can be time in seconds, a datetime object or negative.
	 */
	public function set($key, $value, $expiration = null){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->set($value, $expiration);
	
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
	 * Locks an item in the cache to prevent cache stampede. Works with invalidation parameter in $this->get
	 */
	public function lock($key, $ttl = null){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->lock($ttl);
	
	}
	
	/**
	 * Clears the cache based on the key. If the key is not given, it will clear all of PolyAuth's cache.
	 */
	public function clear($key = false){
	
		if($key){
			$item = $this->cache->getItem($this->namespace . $key);
		}else{
			$item = $this->cache->getItem($this->namespace);
		}
		return $item->clear();
	
	}
	
	/**
	 * Purge all the stale data from the cache. Do this as part of maintenance.
	 */
	public function purge(){
	
		return $this->cache->purge();
	
	}
	
	/**
	 * Empty the entire cache, will also empty cache outside of PolyAuth if you are also using Stash.
	 */
	public function flush(){
	
		return $this->cache->flush();
	
	}

}