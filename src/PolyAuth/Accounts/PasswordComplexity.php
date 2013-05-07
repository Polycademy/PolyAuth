<?php

class PasswordComplexity{

	const REQUIRE_MIN = 1;
	const REQUIRE_MAX = 2;
	const REQUIRE_LOWERCASE = 4;
	const REQUIRE_UPPERCASE = 8;
	const REQUIRE_NUMBER = 16;
	const REQUIRE_SPECIALCHAR = 32;
	const REQUIRE_DIFFPASS = 64;
	const REQUIRE_DIFFIDENTITY = 128;
	const REQUIRE_UNIQUE = 256;
	
	protected $options;
	protected $lang;
	protected $r;
	
	protected $min = 0;
	protected $max = 32;
	protected $diffpass = 3;
	protected $unique = 4;
	protected $complexity_level;
	
	protected $errors = array();
	
	public function __construct(Options $options, Language $language){
	
		$this->options = $options;
		$this->lang = $language;
		$this->r = new \ReflectionClass($this);
		$this->set_complexity($this->options['login_password_complexity']);
	
	}
	
	public function set_complexity(array $complexity_options){
	
		$this->min = (!empty($complexity_options['min']) ? $complexity_options['min'] : $this->min;
		$this->max = (!empty($complexity_options['max']) ? $complexity_options['max'] : $this->max;
		$this->diffpass = (!empty($complexity_options['diffpass']) ? $complexity_options['diffpass'] : $this->diffpass;
		$this->unique = (!empty($complexity_options['unique'])) ? $complexity_options['unique'] : $this->unique;
		
		//if it is false, then no complexity settings
		if(!empty($complexity_options)){
		
			$complexity_level = 0;			
			
			foreach($this->r->getConstants() as $name => $constant){
			
				//REQUIRE_MIN => min
				$name = explode('_', strtolower($name), 2);
				//check if the option is set and it is not strictly equal to false
				if(isset($complexity_options[$name] AND $complexity_options[$name] !== false){
					//add to the complexity level
					$complexity_level += $constant;
				}
			
			}
			
			$this->complexity_level = $complexity_level;
			
		}else{
		
			//a 0 byte would share no bits with any other number
			$this->complexity_level = 0;
			
		}
		
	}
	
	public function complex_enough($new_pass, $old_pass = false, $identity = false){
	
		$enough = TRUE;
		
		//if the complexity level is left at 0, just return true since it's complex enough!
		if($this->complexity_level !== 0){
		
			foreach($this->r->getConstants() as $name => $constant){
			
				//bitwise operator, looks for a matching bit for each constant and the complexity level
				if($this->complexity_level & $constant){
				
					//apparently case does not matter here
					$result = call_user_func_array(array($this, $name), array($new_pass, $old_pass, $identity));
					
					if($result !== TRUE){
						$enough = FALSE;
						$this->errors[] = $result;
					}
					
				}
				
			}
		
		}
		
		return $enough;
		
	}
	
	public function get_errors(){
		return $this->errors;
	}
	
	protected function require_min($new_pass){
	
		if (strlen($new_pass) < $this->min) {
			return $this->lang['password_min'];
		}
		return true;
		
	}
	
	protected function require_max($new_pass){
	
		if (strlen($new_pass) > $this->max) {
			return $this->lang['password_max'];
		}
		return true;
		
	}
	
	protected function require_lowercase($new_pass){
	
		if (!preg_match('/[a-z]/', $new_pass)) {
			return $this->lang['password_lowercase'];
		}
		return true;
	
	}
	
	protected function require_uppercase($new_pass){
	
		if (!preg_match('/[A-Z]/', $new_pass)) {
			return $this->lang['password_uppercase'];
		}
		return true;
		
	}
	
	protected function require_number($new_pass){
	
		if (!preg_match('/[0-9]/', $new_pass)) {
			return $this->lang['password_number'];
		}
		return true;
		
	}
	
	protected function require_specialchar($new_pass){
	
		if (!preg_match('/[^a-zA-Z0-9]/', $new_pass)) {
			return $this->lang['password_specialchar'];
		}
		return true;
		
	}
	
	protected function require_diffpass($new_pass, $old_pass){
	
		//if the old_pass was false, then the check is optional
		if($old_pass){
			if (strlen($new_pass) - similar_text($old_pass, $new_pass) < $this->diffpass || stripos($new_pass, $old_pass) !== FALSE) {
				return $this->lang['password_diffpass'];
			}
		}
		return true;
		
	}
	
	protected function require_diffidentity($new_pass, $old_pass, $identity){
	
		//if the identity was false, then the check is optional
		if($identity){
			if (stripos($new_pass, $identity) !== FALSE) {
				return $this->lang['password_diffidentity'];
			}
		}
		return true;
		
	}
	
	protected function require_unique($new_pass){
	
		$uniques = array_unique(str_split($new_pass));
		if (count($uniques) < $this->unique) {
			return $this->lang['password_unique'];
		}
		return true;
		
	}
	
}