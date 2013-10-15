<?php

namespace PolyAuth\AuthStrategies;

interface StrategyInterface{

	/**
	 * CompositeStrategy uses detect_relevance() to see which strategy is to be used for 
	 * a particular request response cycle. The detect_relevance() would check for a 
	 * session id in the relevant transport method.
	 */
	public function detect_relevance();

}