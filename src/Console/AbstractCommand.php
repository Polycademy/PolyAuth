<?php

namespace PolyAuth\Console;

use PolyAuth\Console\StorageConstructor;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;

use PolyAuth\Exceptions\ConsoleExceptions\InvalidPathException;
use PolyAuth\Exceptions\ConsoleExceptions\JSONParseException;

abstract class AbstractCommand extends Command {

    public function __construct ($name = null) {

        parent::__construct($name);

        $this->getOptions();
        $this->setConsoleOptions();

    }

    protected function getOptions () {

        //this is going to acquire a configuration file
        //if that file exists, we're going to merge them against the Options object
        //however during the execution, the getStorage command will overwrite these commands with the ones passed in during the CLI
        //regardless we're returning an Options object

    }

    /**
     * Sets the default options for all commands.
     */
    protected function setConsoleOptions () {

        $this->setOption(
            'options',
            null,
            InputOption:VALUE_REQUIRED,
            'Location of .polyauthrc'
        )->setOption(
            'dbadapter',
            null,
            InputOption::VALUE_REQUIRED,
            'Database adapter name.'
        )->setOption(
            'dbdsn',
            null,
            InputOption::VALUE_REQUIRED,
            'Database data source name.'
        )->setOption(
            'dbuser',
            null,
            InputOption::VALUE_REQUIRED,
            'Database username.'
        )->setOption(
            'dbpass',
            null,
            InputOption::VALUE_REQUIRED,
            'Database password.'
        );

    }


    protected function getStorage (InputInterface $input) {

        //if storage didnt come up, we need to throw an exception

        $config = $this->getConfigFile($input->getOption('config'));

        if ($config) {
            $databaseAdapter

        } else {
            $databaseAdapter = $input->getOption('dbadapter');
            $databaseUser = $input->getOption('dbuser');
            $databasePass = $input->getOption('dbpass');
            $databaseDsn = $input->getOption('dbdsn');
        }


    }

    /**
     * This acquires the config file.
     * If there is no config file available in the cwd or home, then it just returns null.
     *
     * @param string $path Path to a specified configuration file.
     * 
     * @return array|null
     *
     * @throws InvalidPathException If the $path does not exist or is not readable
     */
    protected function getConfigFile ($path = null) {

        if ($path) {
            if (!file_exists($path) OR !is_readable($path)) {
                throw new InvalidPathException('Config path does not exist or the path is not readable.');
            }
        }

        if ($!path) {

            $file = '.polyauthrc';
            $cwd = getcwd();
            //this will get home from the unix HOME or from windows
            ($home = getenv('HOME')) OR $home = getenv('HOMEDRIVE') . getenv('HOMEPATH');

            if (file_exists($cwd . $file)) {
                $path = $cwd . $file;
            } elseif (file_exists($home . $file)) {
                $path = $home . $file;
            } else {
                return null;
            }

        }

        return $this->parseJsonFile($path);

    }

    /**
     * Acquires a JSON file and returns an associative array
     *
     * @return array
     *
     * @throws \Exception If JSON filepath or the file is incorrect
     */
    protected parseJsonFile ($jsonFile) {

        if(is_file($jsonFile) AND is_readable($jsonFile)){
            $data = file_get_contents($jsonFile);
        }else{
            throw new InvalidPathException("The $jsonFile file could not be found or could not be read.");
        }

        $data = json_decode($data, true);

        switch(json_last_error()){
            case JSON_ERROR_DEPTH:
                $error = "The $jsonFile file exceeded maximum stack depth.";
            break;
            case JSON_ERROR_STATE_MISMATCH:
                $error = "The $jsonFile file hit an underflow or the mods mismatched.";
            break;
            case JSON_ERROR_CTRL_CHAR:
                $error = "The $jsonFile file has an unexpected control character.";
            break;
            case JSON_ERROR_SYNTAX:
                $error = "The $jsonFile file has a syntax error, it\'s JSON is malformed.";
            break;
            case JSON_ERROR_UTF8:
                $error = "The $jsonFile file has malformed UTF-8 characters, it could be incorrectly encoded.";
            break;
            case JSON_ERROR_NONE:
            default:
                $error = '';
        }

        if(!empty($error)){
            throw new JSONParseException($error);
        }

        return $data;

    }

}