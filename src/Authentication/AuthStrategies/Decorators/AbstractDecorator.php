<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

/**
 * DecoratorAbstract allows the creation of flexible nested decorators.
 * Decorators can be stacked. They can also have methods that overwrite each other.
 * Decorators can omit methods that parent decorators have defined and/or child decorators have defined.
 * Methods will cascade to the original child object.
 * Properties will read and set from the original child object except when your instance has the property defined.
 */
abstract class AbstractDecorator{

	protected $strategy;

	/**
	 * Gets the original object that all the decorators have wrapped themselves around.
	 * @return Object
	 */
	public function get_original_object(){
		
		$strategy = $this->strategy;
		
		while(is_a($strategy, get_class())){
			$strategy = $strategy->get_original_object();
		}
			  
		return $strategy;
		
	}

	/**
	 * Magic __call will recursively call itself and cascade through all the methods on the decorators.
	 * This will work for the child object's methods, and even when methods are missing in between the decorator stack.
	 * @param  String $method
	 * @param  Array  $args
	 * @return Mixed
	 */
	public function __call($method, $args){

		return call_user_func_array(array($this->strategy, $method), $args);

	}

	/**
	 * Magic __get will return the properties from the original object.
	 * This won't be executed if the current instance has the property defined.
	 * @param  String $property
	 * @return Mixed
	 */
	public function __get($property){

		$strategy = $this->get_original_object();
		if(property_exists($strategy, $property)){
			return $strategy->$property;
		}
		return null;

	}

	/**
	 * Magic __set will set a property on the original object.
	 * This won't be executed if the current instance has the property defined.
	 * @param  String $property
	 * @param  Mixed  $value
	 * @return Object $this
	 */
	public function __set($property, $value){

		$strategy = $this->get_original_object();
		$strategy->$property = $value;
		return $this;

	}

}