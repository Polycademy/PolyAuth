<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Authentication\AuthStrategies\Decorators\AbstractDecorator;
use PolyAuth\Exceptions\ValidationExceptions\StrategyValidationException;

/**
 * This class needs to match all of the public API functions of the Abstract Strategy
 */
class CompositeStrategy{

	protected $strategies;
	protected $context; //this will be switched depending on get relevance

	public function __construct(){

		$strategies = func_get_args();

		if(empty($strategies)){
			throw StrategyValidationException('CompositeStrategy needs to be passed a list of strategies');
		}

		foreach($strategies as $strategy){

			if($strategy->detect_relevance()){
				$this->context = $strategy;
				break;
			}

		}

		if(empty($this->context)){
			$this->context = $strategies[0];
		}

		$this->strategies = $strategies;

	}

	/**
	 * Switches the context based on the class name of the strategy.
	 * Note this works with decorated strategies, you pass the name of the original strategy,
	 * not the decoration. This is because there can multiple decorations. But each original 
	 * strategy would be unique.
	 * On the other hand, one should just decorate the CompositeStrategy, not the individual
	 * strategies.
	 * @param  String $selected_strategy Class name of the strategy, can be lower case
	 * @return Void
	 */
	public function switch_context($selected_strategy){

		foreach($this->strategies as $strategy){

			if($strategy instanceof AbstractDecorator){
				$strategy = $strategy->get_original_object();
			}

			$strategy_name_parts = explode('\\', get_class($strategy));
			$strategy_name = end($strategy_name_parts);

			if(strtolower($selected_strategy) == strtolower($strategy_name)){
				$this->context = $strategy;
				return;
			}

		}

	}

	public function start_session(){

		return $this->context->start_session();

	}

	public function get_session(){

		return $this->context->get_session();
	
	}

	public function autologin(){

		return $this->context->autologin();

	}

	public function login(array $data, $external = false){

		return $this->context->login($data, $external);

	}

	public function logout(){

		return $this->context->logout();

	}

	public function challenge(){

		return $this->context->challenge();

	}

	public function get_response($data_type = false){

		return $this->context->get_response($data_type);
	
	}

}