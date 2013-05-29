<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PolyAuth\Options;

ob_start();

class CookiesSpec extends ObjectBehavior{

	function let(Options $options){
	
		$prophet = new Prophet;
	
		$options = $options->options;
		$options_object = $prophet->prophesize('PolyAuth\Options');
		$options_object->offsetGet(Argument::any())->will(function($args) use (&$options){
			$key = $args[0];
			return $options[$key];
		});
		$options_object->offsetSet(Argument::cetera())->will(function($args) use (&$options){
			if(is_null($args[0])){
				$options[] = $args[1];
			} else {
				$options[$args[0]] = $args[1];
			}
		});
		$options_object = $options_object->reveal();
		
		$_COOKIE['testcookie'] = 'some test data'; 
		
		$this->beConstructedWith($options_object);		

	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Cookies');
		
	}
	
	function it_should_set_cookies(){
	
		$this->set_cookie('blah', 'some value to store')->shouldReturn(true);
	
	}
	
	function it_should_get_cookies(){
		
		$this->get_cookie('testcookie')->shouldReturn('some test data');
		
	}
	
	function it_should_delete_cookies(){
	
		$this->delete_cookie('testcookie');
		$this->get_cookie('testcookie')->shouldReturn(null);
		
	}
	
}

ob_flush();