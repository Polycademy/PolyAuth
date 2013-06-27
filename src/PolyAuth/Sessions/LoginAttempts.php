<?php

namespace PolyAuth\Sessions;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use PolyAuth\Options;

class LoginAttempts implements LoggerAwareInterface{

	protected $db;
	protected $options;
	protected $logger;

	public function __construct(PDO $db, Options $options, LoggerInterface $logger = null){
	
		$this->db = $db;
		$this->options = $options;
		$this->logger = $logger;
	
	}
	
	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){
		$this->logger = $logger;
	}
	
	/**
	 * Checks if the current login attempt is locked according to an exponential timeout.
	 * There is cap on the length of the timeout however. The timeout could grow to infinity without the cap.
	 * This returns how many seconds the session is locked out from attempting a login.
	 *
	 * @param $identity string
	 * @return false | int
	 */
	public function locked_out($identity){
	
		$lockout_options = $this->options['login_lockout'];
		
		if(
			!empty($identity) 
			AND is_array($lockout_options)
			AND (
				in_array('ipaddress', $lockout_options) 
				OR 
				in_array('identity', $lockout_options)
			)
		){
		
			$query = "
				SELECT 
				MAX(lastAttempt) as lastAttempt, 
				COUNT(*) as attemptNum
				FROM {$this->options['table_login_attempts']} 
			";
			
			//if we are tracking both, it's an OR, not an AND, because a single ip address may be attacking multiple identities and a single identity may be attacked from multiple ip addresses
			if(in_array('ipaddress', $lockout_options) AND in_array('identity', $lockout_options)){
			
				$query .= "WHERE ipAddress = :ip_address OR identity = :identity";
			
			}elseif(in_array('ipaddress', $lockout_options)){
			
				$query .= "WHERE ipAddress = :ip_address";
			
			}elseif(in_array('identity', $lockout_options)){
			
				$query .= "WHERE identity = :identity";
			
			}
			
			$sth = $this->db->prepare($query);
			$sth->bindValue('ip_address', $this->get_ip(), PDO::PARAM_STR);
			$sth->bindValue('identity', $identity, PDO::PARAM_STR);
			
			try{
			
				$sth->execute();
				$row = $sth->fetch(PDO::FETCH_OBJ);
				if(!$row){
					return false;
				}
				$number_of_attempts = $row->attemptNum;
				$last_attempt = $row->lastAttempt;
			
			}catch(PDOException $db_err){
			
				if($this->logger){
					$this->logger->error('Failed to execute query to check whether a login attempt was locked out.', ['exception' => $db_err]);
				}
				throw $db_err;
			
			}
			
			//y = 1.8^(n-1) where n is number of attempts, resulting in exponential timeouts, to prevent brute force attacks
			$lockout_duration = round(pow(1.8, $number_of_attempts - 1));
			
			//capping the lockout time
			if($this->options['login_lockout_cap']){
				$lockout_duration = min($lockout_duration, $this->options['login_lockout_cap']);
			}
			
			//adding the lockout time to the last attempt will create the overall timeout
			$timeout = strtotime($last_attempt) + $lockout_duration;
			
			//if the current time is less than the timeout, then attempt is locked out
			if(time() < $timeout){
				//return the difference in seconds
				return (integer) $timeout - time();
			}
			
		}
		
		return false;
	
	}
	
	/**
	 * Increment the number of login attempts.
	 * This will track both the ip address and the identity used to login.
	 * It will only increment for the current session's ip.
	 *
	 * @param $identity string
	 * @return true
	 */
	public function increment($identity){
	
		$query = "INSERT {$this->options['table_login_attempts']} (ipAddress, identity, lastAttempt) VALUES (:ip, :identity, :date)";
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip', $this->get_ip(), PDO::PARAM_STR);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		$sth->bindValue('date', date('Y-m-d H:i:s'), PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to insert a login attempt.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Clear all the login attempts on a successful login for a particular identity.
	 * Clears only where the identity and the current session's ip match.
	 * The $either_or allows people to force this function to clear ipaddress or identity simultaneously.
	 * This will be used when the forgotten cycle completes, because we want to allow the session to bypass
	 * ipaddress checks and identity checks.
	 * Normally it would check ipaddress AND identity
	 * 
	 * @param $identity string
	 * @param $either_or boolean
	 * @return true | false
	 */
	public function clear($identity, $either_or = false){
	
		$lockout_options = $this->options['login_lockout'];
		
		if(
			!empty($identity) 
			AND is_array($lockout_options)
			AND (
				in_array('ipaddress', $lockout_options) 
				OR 
				in_array('identity', $lockout_options)
			)
		){
		
			$query = "DELETE FROM {$this->options['table_login_attempts']} ";
			
			if($either_or){
			
				//this is the most complete clearing, simultaneously clearing any ips and identities
				$query .= "WHERE ipAddress = :ip_address OR identity = :identity";
			
			}elseif(in_array('ipaddress', $lockout_options) AND in_array('identity', $lockout_options)){
			
				//this is the most stringent clearing, requiring both ip and identity to be matched
				$query .= "WHERE ipAddress = :ip_address AND identity = :identity";
			
			}elseif(in_array('ipaddress', $lockout_options)){
			
				$query .= "WHERE ipAddress = :ip_address";
			
			}elseif(in_array('identity', $lockout_options)){
			
				$query .= "WHERE identity = :identity";
			
			}
			
			$sth = $this->db->prepare($query);
			$sth->bindValue('ip', $this->get_ip(), PDO::PARAM_STR);
			$sth->bindValue('identity', $identity, PDO::PARAM_STR);
			
			try{
			
				$sth->execute();
				if($sth->rowCount() >= 1){
					return true;
				}
			
			}catch(PDOException $db_err){
				
				if($this->logger){
					$this->logger->error('Failed to execute query to clear old login attempts.', ['exception' => $db_err]);
				}
				throw $db_err;
				
			}
			
		}
		
		return false;
	
	}
	
	/**
	 * Helper function to get the ip and format it correctly for insertion.
	 *
	 * @return $ip_address binary | string
	 */
	protected function get_ip() {
	
		$ip_address = (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
		return inet_pton($ip_address);
		
	}

}