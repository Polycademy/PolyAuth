<?php

namespace PolyAuth;

//if you're implementing the php 5.4 interface, then just implement both of them!
interface SessionInterface{

	public function close();
	
	public function destroy($session_id);
	
	public function gc($maxlifetime);
	
	public function open($save_path, $name);
	
	public function read($session_id);
	
	public function write($session_id, $session_data);
	
}