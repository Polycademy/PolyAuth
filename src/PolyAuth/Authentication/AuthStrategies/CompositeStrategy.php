<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Exceptions\ValidationExceptions\StrategyValidationException;

class CompositeStrategy extends AbstractStrategy{

	protected $strategies;

	public function __construct(){

		$strategies = func_get_args();

		if(empty($strategies)){
			throw StrategyValidationException('CompositeStrategy needs to be passed a list of strategies');
		}

		foreach($strategies as $strategy){
			if(!$strategy instanceof StrategyInterface){
				throw StrategyValidationException('Authentication strategies in CompositeStrategy needs to implement StrategyInterface.');
			}
		}

		$this->strategies = $strategies;

	}

}