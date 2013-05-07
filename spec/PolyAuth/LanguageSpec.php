<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;

class LanguageSpec extends ObjectBehavior{

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Language');
		
	}
	
	function it_should_manipulate_language_array(){
	
		$this->set_language(array(
			'permission_delete_unsuccessful'	=> 'A different description!',
		));
		
		$this['permission_delete_unsuccessful']->shouldReturn('A different description!');
		
		$this['permission_delete_unsuccessful'] = 'Another description!';
		
		$this['permission_delete_unsuccessful']->shouldReturn('Another description!');
		
	}
	
}
