<?php

namespace PolyAuth\Caching;

interface CachingInterface{

	public function get($key);
	
	public function set($key, $value, $expiration);
	
	public function exists($key);

}