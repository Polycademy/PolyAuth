<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use PolyAuth\Options;
use PolyAuth\Language;

class PasswordComplexitySpec extends ObjectBehavior{

	function let(Options $options, Language $language){
	
		$option_array = $options->options;
		
		$options->offsetGet(Argument::any())->will(function($args) use ($option_array){
			$key = $args[0];
			return $option_array[$key];
		});
		
		$this->beConstructedWith($options, $language);
	
	}
	
	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\PasswordComplexity');
	
	}
	
	function it_should_determine_min_and_max_of_passwords(){
	
		$options = array(
			'min'			=> 8,
			'max'			=> 32,
			'lowercase'		=> false,
			'uppercase'		=> false,
			'number'		=> false,
			'specialchar'	=> false,
			'diffpass'		=> false,
			'diffidentity'	=> false,
			'unique'		=> false,
		);
		
		$this->set_complexity($options);
	
		//minimum
		$this->complex_enough('apass')->shouldReturn(false);
		//maximum
		$this->complex_enough('sdggoj4rnt34985uofnmsp089f7u934h5;q3p')->shouldReturn(false);
		//just right
		$this->complex_enough('123long345')->shouldReturn(true);
	
	}
	
	function it_should_determine_lower_and_upper_of_passwords(){
	
		$options = array(
			'min'			=> 0,
			'max'			=> 32,
			'lowercase'		=> true,
			'uppercase'		=> true,
			'number'		=> false,
			'specialchar'	=> false,
			'diffpass'		=> false,
			'diffidentity'	=> false,
			'unique'		=> false,
		);
	
		$this->set_complexity($options);
		
		$this->complex_enough('aaa')->shouldReturn(false);
		$this->complex_enough('AAA')->shouldReturn(false);
		$this->complex_enough('AaBb')->shouldReturn(true);
	
	}
	
	function it_should_determine_number_and_special_characters_of_passwords(){
	
		$options = array(
			'min'			=> 0,
			'max'			=> 32,
			'lowercase'		=> false,
			'uppercase'		=> false,
			'number'		=> true,
			'specialchar'	=> true,
			'diffpass'		=> false,
			'diffidentity'	=> false,
			'unique'		=> false,
		);
	
		$this->set_complexity($options);
		
		$this->complex_enough('abc')->shouldReturn(false);
		$this->complex_enough('1234')->shouldReturn(false);
		$this->complex_enough('%^&')->shouldReturn(false);
		$this->complex_enough('1234^&*(')->shouldReturn(true);
	
	}
	
	function it_should_determine_passwords_that_are_different_from_old_password_and_identity(){
	
		$options = array(
			'min'			=> 0,
			'max'			=> 32,
			'lowercase'		=> false,
			'uppercase'		=> false,
			'number'		=> false,
			'specialchar'	=> false,
			'diffpass'		=> 4,
			'diffidentity'	=> true,
			'unique'		=> false,
		);
	
		$this->set_complexity($options);
		
		$this->complex_enough('abc', 'abc')->shouldReturn(false);
		$this->complex_enough('abc', false, 'abc')->shouldReturn(false);
		$this->complex_enough('abcd', '1234', 'abce')->shouldReturn(true);
	
	}
	
	function it_should_determine_unique_characters_in_passwords(){
	
		$options = array(
			'min'			=> 0,
			'max'			=> 32,
			'lowercase'		=> false,
			'uppercase'		=> false,
			'number'		=> false,
			'specialchar'	=> false,
			'diffpass'		=> false,
			'diffidentity'	=> false,
			'unique'		=> 5,
		);
	
		$this->set_complexity($options);
		
		$this->complex_enough('aaaab')->shouldReturn(false);
		$this->complex_enough('abcdefg')->shouldReturn(true);
	
	}

}
