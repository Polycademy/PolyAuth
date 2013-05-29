<?php

namespace spec\PolyAuth\Security;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class EncryptionSpec extends ObjectBehavior{

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Security\Encryption');
	}
	
	function it_should_encrypt_and_decrypt_data_with_the_right_key(){
	
		$encrypted_data = $this->encrypt('blah', 'abcd1234');
		$this->decrypt($encrypted_data, 'abcd1234')->shouldReturn('blah');
	
	}
	
	function it_should_not_decrypt_properly_with_the_wrong_key(){
	
		$encrypted_data = $this->encrypt('blah', 'abcd1234');
		$this->decrypt($encrypted_data, 'abcdgsgfgh')->shouldReturn(false);
	
	}
	
}
