<?php

namespace PolyAuth;

//for logger
use Psr\Log\LoggerInterface;

//for options
use PolyAuth\Options;

//for languages
use PolyAuth\Language;

use PolyAuth\UserAccount;

//this class handles the sending of emails
class Emailer{

	protected $options;
	protected $lang;
	protected $logger;
	protected $mailer;
	
	protected $errors = array();

	public function __construct(Options $options, Language $language, \PHPMailer $mailer = null, LoggerInterface $logger = null){
	
		$this->options = $options;
		$this->lang = $language;
		$this->logger = $logger;
		$this->mailer = ($mailer) ? $mailer : new \PHPMailer;
	
	}
	
	//assume $body has {{activation_code}}
	//this can be sent multiple times, the activation code doesn't change (so the concept of resend activation email)
	public function send_activation(UserAccount $user, $subject = false, $body = false, $alt_body = false){
	
		$subject = (empty($subject)) ? $this->lang('email_activation_subject') : $subject;
		$body = (empty($body)) ? $this->options['email_activation_template'] : $body;
			
		//use sprintf to insert activation code and user id
		$body = $this->interpolate_email_body($body, array(
			'{{user_id}}'			=> $user['id'],
			'{{activation_code}}'	=> $user['activationCode'],
		));
		
		//send email via PHPMailer
		if(!$this->send_mail($user['email'], $subject, $body, $alt_body)){
			if($this->logger){
				$this->logger->error('Failed to send activation email.');
			}
			$this->errors[] = $this->lang['activation_email_unsuccessful'];
			return false;
		}
		
		return true;
		
	}
	
	public function send_forgotten_identity(UserAccount $user, $subject = false, $body = false, $alt_body = false){
	
		$subject = (empty($subject)) ? $this->lang('email_forgotten_identity_subject') : $subject;
		$body = (empty($body)) ? $this->options['email_forgotten_identity_template'] : $body;
		
		$body = $this->interpolate_email_body($body, array(
			'{{user_id}}'			=> $user['id'],
			'{{identity}}'			=> $user["{$this->options['identity']}"],
		));
		
		if(!$this->send_mail($user['email'], $subject, $body, $alt_body)){
			if($this->logger){
				$this->logger->error('Failed to send forgotten identity email.');
			}
			$this->errors[] = $this->lang['forgotten_identity_email_unsuccessful'];
			return false;
		}
		
		return true;
		
	}
	
	public function send_forgotten_password(UserAccount $user, $subject = false, $body = false, $alt_body = false){
	
		$subject = (empty($subject)) ? $this->lang('email_forgotten_password_subject') : $subject;
		$body = (empty($body)) ? $this->options['email_forgotten_password_template'] : $body;
		
		$body = $this->interpolate_email_body($body, array(
			'{{user_id}}'			=> $user['id'],
			'{{identity}}'			=> $user["{$this->options['identity']}"],
			'{{forgotten_code}}'	=> $user['forgottenCode'],
		));
		
		if(!$this->send_mail($user['email'], $subject, $body, $alt_body)){
			if($this->logger){
				$this->logger->error('Failed to send forgotten password email.');
			}
			$this->errors[] = $this->lang['forgotten_password_email_unsuccessful'];
			return false;
		}
		
		return true;
	
	}
	
	public function interpolate_email_body($body, array $replacements){
	
		foreach($replacements as $key => $interpolated_value){
			$body = preg_replace("/$key/", $interpolated_value, $body);
		}
		
		return $body;
	
	}
	
	public function send_mail($email_to, $subject, $body, $alt_body = false){
	
		if($this->options['email_smtp']){
			$this->mailer->IsSMTP();
			$this->mailer->Host = $this->options['email_host'];
			if($this->options['email_auth']){
				$this->mailer->SMTPAuth = true;
				$this->mailer->Username = $this->options['email_username'];
				$this->mailer->Password = $this->options['email_password'];
			}
			if($this->options['email_smtp_secure']) $this->mailer->SMTPSecure = $this->options['email_smtp_secure'];
		}
		
		$this->mailer->From = $this->options['email_from'];
		$this->mailer->FromName = $this->options['email_from_name'];
		$this->mailer->AddAddress($email_to);
		if($this->options['email_replyto']) $this->mailer->AddReplyTo($this->options['email_replyto'], $this->options['email_replyto_name']);
		if($this->options['email_cc']) $this->mailer->AddCC($this->options['email_cc']);
		if($this->options['email_bcc']) $this->mailer->AddBCC($this->options['email_bcc']);
		if($this->options['email_html']) $this->mailer->IsHTML(true);
		
		$this->mailer->Subject = $subject;
		$this->mailer->Body = $body;
		if($alt_body) $this->mailer->AltBody = $alt_body;
		
		if(!$this->mailer->Send()){
			return false;
		}
		
		return true;
	
	}
	
	public function get_errors(){
		if(!empty($this->errors)){
			return $this->errors;
		}else{
			return false;
		}
	}

}