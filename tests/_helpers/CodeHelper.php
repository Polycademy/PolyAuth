<?php
namespace Codeception\Module;

// here you can define custom functions for CodeGuy 

class CodeHelper extends \Codeception\Module
{

    public function dump($var){

        ob_start();
        var_dump($var);
        $result = trim(ob_get_clean());
        fwrite(STDERR, print_r("\n======\n" . $result . "\n======\n", TRUE));

    }
    
}
