<?php

namespace spec\PolyAuth\AuthStrategies;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;
use PolyAuth\Options;

class HTTPStrategySpec extends ObjectBehavior{

	public $prophet;

	function let(
		PDO $db,
		PDOStatement $sth,
		Options $options
	){
	
		//setting up the prophet
		$this->prophet = new Prophet;
		
		$mocks = array();
		$mocks += $this->setup_db_mocks($db, $sth);
		$mocks += $this->setup_options_mocks($options);
		$mocks += $this->setup_logger_mocks();
		
		$this->beConstructedWith(
			$mocks['db'],
			$mocks['options'],
			$mocks['logger'], 
			'PolyAuth'
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

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\AuthStrategies\HTTPStrategy');
	}

	function it_implements_auth_strategy_interface(){
		$this->shouldImplement('PolyAuth\AuthStrategies\AuthStrategyInterface');
	}
	
	function it_implements_logger_interface(){
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	}
	
	function it_should_not_autologin_when_row_was_not_returned_from_database(PDOStatement $sth){
	
		$sth->fetch(Argument::any())->willReturn(false);
		$this->autologin()->shouldReturn(false);
	
	}
	
	function it_should_autologin_when_row_is_returned_from_database(PDOStatement $sth){
	
		$_SERVER['PHP_AUTH_USER'] = 'CMCDragonkai';
		$_SERVER['PHP_AUTH_PW'] = 'password';
	
		$row = new \stdClass;
		$row->id = 1;
		$row->password = password_hash('password', PASSWORD_BCRYPT);
		
		$sth->fetch(Argument::any())->willReturn($row);
		
		$this->autologin()->shouldReturn(1);
	
	}
	
	function it_should_do_nothing_during_set_autologin(){
	
		$this->set_autologin(1)->shouldReturn(null);
	
	}
	
	function it_should_give_back_login_credentials_during_login_hook(){
	
		$_SERVER['PHP_AUTH_USER'] = 'CMCDragonkai';
		$_SERVER['PHP_AUTH_PW'] = 'password';
		
		$this->login_hook(array())->shouldReturn(['identity' => 'CMCDragonkai', 'password' => 'password']);
	
	}
	
	function it_should_send_HTTP_challenge_during_logout_hook(){
	
		$this->logout_hook()->shouldReturn(null);	
	
	}
	
}