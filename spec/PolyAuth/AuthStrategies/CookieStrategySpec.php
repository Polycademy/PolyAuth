<?php

namespace spec\PolyAuth\AuthStrategies;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;
use PolyAuth\Cookies;
use PolyAuth\Security\Random;

class CookieStrategySpec extends ObjectBehavior{

	public $prophet;
	public $options;

	function let(
		PDO $db,
		PDOStatement $sth,
		Options $options,
		Cookies $cookies,
		Random $random
	){
	
		//setting up the prophet
		$this->prophet = new Prophet;
		
		$mocks = array();
		$mocks += $this->setup_db_mocks($db, $sth);
		$mocks += $this->setup_options_mocks($options);
		$mocks += $this->setup_logger_mocks();
		$mocks += $this->setup_cookies_mocks($cookies);
		$mocks += $this->setup_random_mocks($random);
		
		$this->beConstructedWith(
			$mocks['db'],
			$mocks['options'],
			$mocks['logger'], 
			$mocks['cookies'],
			$mocks['random']
		);
	
	}
	
	function setup_db_mocks(PDO $db, PDOStatement $sth){
	
		//STH
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(true);
		
		//PDO
		$db->prepare(Argument::any())->willReturn($sth);
		
		return [
			'db'	=> $db, 
		];
	
	}
	
	function setup_options_mocks(Options $options){
	
		//OPTIONS
		$options_array = $options->options;
		$options = $this->prophet->prophesize('PolyAuth\Options');
		$options->offsetGet(Argument::any())->will(function($args) use (&$options_array){
			$key = $args[0];
			return $options_array[$key];
		});
		$options->offsetSet(Argument::cetera())->will(function($args) use (&$options_array){
			if(is_null($args[0])){
				$options_array[] = $args[1];
			} else {
				$options_array[$args[0]] = $args[1];
			}
		});
		$options->offsetExists(Argument::any())->will(function($args) use (&$options_array){
			return isset($options_array[$args[0]]);
		});
		$options = $options->reveal();
		
		$this->options = $options;
		
		return [
			'options'	=> $options, 
		];
		
	}
	
	function setup_logger_mocks(){
	
		$logger = $this->prophet->prophesize();
		$logger->willExtend('stdClass');
		$logger->willImplement('Psr\Log\LoggerInterface');
		$logger->error(Argument::type('string'), Argument::type('array'))->willReturn(true);
		return [
			'logger'	=> $logger->reveal(),
		];
	
	}
	
	function setup_cookies_mocks(Cookies $cookies){
	
		$id = '1';
		$autoCode = '1234dsf4846dcvx4v459';
		
		$cookies->get_cookie(Argument::any())->willReturn(serialize(['id' => (integer) $id, 'autoCode' => $autoCode]));
		
		//set cookie should be set in this way!
		$cookies->set_cookie('autologin', serialize(['id' => (integer) $id, 'autoCode' => $autoCode]), $this->options['login_expiration'])->willReturn(true);
		
		$cookies->delete_cookie(Argument::any())->willReturn(true);
		
		return [
			'cookies'	=> $cookies,
		];
	
	}
	
	function setup_random_mocks(Random $random){
	
		$random->generate(20)->willReturn('1234dsf4846dcvx4v459');
		
		return [
			'random'	=> $random,
		];
	
	}
	
	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\AuthStrategies\CookieStrategy');
	}
	
	function it_implements_auth_strategy_interface(){
		$this->shouldImplement('PolyAuth\AuthStrategies\AuthStrategyInterface');
	}
	
	function it_implements_logger_interface(){
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	}
	
	function it_should_not_autologin_when_row_was_not_returned_from_database(PDOStatement $sth){
	
		$sth->fetch(Argument::any())->willReturn(false);
		
		//cleared autologin
		$sth->rowCount()->willReturn(1);
		
		$this->autologin()->shouldReturn(false);
	
	}
	
	function it_should_autologin_when_row_is_returned_from_database(PDOStatement $sth){
	
		$row = new \stdClass;
		$row->id = 1;
		
		$sth->fetch(Argument::any())->willReturn($row);
		
		//update the autologin row!
		$sth->rowCount()->willReturn(1);
		
		$this->autologin()->shouldReturn(1);
	
	}
	
	function it_should_setup_autologin_given_an_user_id(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
		$this->set_autologin(1)->shouldReturn(true);
	
	}
	
	function it_should_clear_autologin_given_an_user_id(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
		$this->clear_autologin(1)->shouldReturn(true);
	
	}
	
	function it_should_bounce_during_login_hook(){
	
		$this->login_hook('blah')->shouldReturn('blah');
	
	}
	
	function it_should_do_nothing_during_logout_hook(){
	
		$this->logout_hook()->shouldReturn(null);
	
	}
	
}
