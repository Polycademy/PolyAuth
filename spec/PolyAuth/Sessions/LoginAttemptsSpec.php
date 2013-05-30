<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;
use PolyAuth\Options;

class LoginAttemptsSpec extends ObjectBehavior{

	public $prophet;

	function let(PDO $db, PDOStatement $sth, Options $options){
	
		$this->prophet = new Prophet;
		
		$mocks = [];
		$mocks += $this->setup_db_mocks($db, $sth);
		$mocks += $this->setup_options_mocks($options);
		$mocks += $this->setup_logger_mocks();
		
		$this->beConstructedWith(
			$mocks['db'],
			$mocks['options'],
			$mocks['logger']
		);
		
		date_default_timezone_set('Australia/ACT');
	
	}
	
	function setup_db_mocks(PDO $db, PDOStatement $sth){
	
		//STH
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(true);
		
		//PDO
		$db->prepare(Argument::any())->willReturn($sth);
		$db->getAttribute(PDO::ATTR_DRIVER_NAME)->willReturn('mysql');
		
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
		
		$options['login_lockout'] = array('ipaddress', 'identity');
		$options['login_lockout_cap'] = 172800;
		
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
	
		$this->shouldHaveType('PolyAuth\Sessions\LoginAttempts');
		
	}
	
	function it_implements_logger_interface(){
	
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	
	}
	
	function it_should_return_the_lockout_time_in_seconds_if_locked_out(PDOStatement $sth){
	
		$row = new \stdClass;
		$row->lastAttempt = date('Y-m-d H:i:s');
		$row->attemptNum = 10;
	
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($row);
		
		//according to y = 1.8(x-1)
		$lockout_duration = round(pow(1.8, $row->attemptNum - 1));
		$timeout = strtotime($row->lastAttempt) + $lockout_duration;
		
		//time in seconds
		$this->locked_out('CMCDragonkai')->shouldReturn((integer) $timeout - time());
	
	}
	
	function it_should_correctly_determine_if_the_user_locked_out(PDOStatement $sth){
	
		$row = new \stdClass;
		$row->lastAttempt = date('Y-m-d H:i:s', strtotime('-1 week')); //last attempt was a week ago, so this should return false
		$row->attemptNum = 10;
	
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($row);
		
		$this->locked_out('CMCDragonkai')->shouldReturn(false);
	
	}
	
	function it_should_increment_login_attempts(){
	
		$this->increment('CMCDragonkai')->shouldReturn(true);
	
	}
	
	function it_should_clear_login_attempts(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
	
		$this->clear('CMCDragonkai')->shouldReturn(true);
		
		$this->clear('CMCDragonkai', true)->shouldReturn(true);
	
	}
	
}