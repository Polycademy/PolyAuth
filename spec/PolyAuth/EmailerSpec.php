<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Prophet;
use Prophecy\Argument;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\UserAccount;

class EmailerSpec extends ObjectBehavior{

	public $user;

	function let(Options $options, Language $language, \PHPMailer $mailer){
	
		$prophet = new Prophet;
		
		//MAILER MOCKING
		$mailer->AddAddress(Argument::any())->willReturn(true);
		$mailer->Send()->willReturn(true);
		$mailer->__destruct()->willReturn(true);
		$mailer->IsHTML(Argument::any())->willReturn(true);
		
		//OPTIONS MOCKING
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
		
		$this->beConstructedWith($options_object, $language, $mailer);
		
		//USER MOCKING
		$user_data = array(
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'activationCode'	=> 'ABCDEFG',
			'forgottenCode'		=> '1234567',
		);
		$user_object = $prophet->prophesize('PolyAuth\UserAccount');
		$user_object->offsetGet(Argument::any())->will(function($args) use (&$user_data){
			$key = $args[0];
			return $user_data[$key];
		});
		$user_object->offsetSet(Argument::cetera())->will(function($args) use (&$user_data){
			if(is_null($args[0])){
				$user_data[] = $args[1];
			} else {
				$user_data[$args[0]] = $args[1];
			}
		});
		$this->user = $user_object->reveal();
	
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Emailer');
		
	}
	
	function it_should_interpolate_email_body(){
	
		$body = 'ID: {{user_id}} ACTIVATION: {{activation_code}} FORGOTTEN: {{forgotten_code}}';
		
		$this->interpolate_email_body($body, array(
			'{{user_id}}'			=> $this->user['id'],
			'{{activation_code}}'	=> $this->user['activationCode'],
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