<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\UserAccount;

class EmailerSpec extends ObjectBehavior{

	public $user;

	function let(Options $options, Language $language, UserAccount $user, \PHPMailer $mailer){
	
		//mocking
		$mailer->AddAddress(Argument::any())->willReturn(true);
		$mailer->Send()->willReturn(true);
		$mailer->__destruct()->willReturn(true);
		
		$this->beConstructedWith($options, $language, null, $mailer);
		
		$user->id = 1;
		$user->email = 'example@example.com';
		$user->activationCode = 'ABCDEFG';
		$user->forgottenCode = '1234567';
		
		$this->user = $user;
	
	}

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Emailer');
	}
	
	function it_should_interpolate_email_body(){
	
		$body = 'ID: {{user_id}} ACTIVATION: {{activation_code}} FORGOTTEN: {{forgotten_code}}';
		
		$this->interpolate_email_body($body, array(
			'{{user_id}}'			=> $this->user->id,
			'{{activation_code}}'	=> $this->user->activationCode,
		))->shouldReturn('ID: 1 ACTIVATION: ABCDEFG FORGOTTEN: {{forgotten_code}}');
	
	}
	
	function it_should_send_activation_email(){
	
		$this->send_activation($this->user, 'a subject', 'ID: {{user_id}} ACTIVATION: {{activation_code}}', 'This is an alt body')->shouldReturn(true);
	
	}
	
	function it_should_send_forgotten_identity_email(){
	
		$this->send_forgotten_identity($this->user, 'a subject', 'ID: {{user_id}} IDENTITY: {{identity}}', 'This is an alt body')->shouldReturn(true);
	
	}
	
	function it_should_send_forgotten_password_email(){
	
		$this->send_forgotten_password($this->user, 'a subject', 'ID: {{user_id}} IDENTITY: {{identity}}', 'This is an alt body')->shouldReturn(true);
	
	}
	
}
