<?php

namespace PolyAuth;

//if you're implementing the php 5.4 interface, then just implement both of them!
interface SessionInterface{

	abstract public bool close ( void )
	
	abstract public bool destroy ( string $session_id )
	
	abstract public bool gc ( string $maxlifetime )
	
	abstract public bool open ( string $save_path , string $name )
	
	abstract public string read ( string $session_id )
	
	abstract public bool write ( string $session_id , string $session_data )
	
}