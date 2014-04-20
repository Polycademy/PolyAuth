<?php

namespace PolyAuth\Database\Console\Database;

use PolyAuth\Console\AbstractCommand;

use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Seed extends AbstractCommand {

    protected function configure () {

        $this->setName(
            'db:seed'
        )->setDescription(
            'Seeds the database with initial data. You run this after installing the schema.'
        );

    }

    protected function execute (InputInterface $input, OutputInterface $output) {

        //we need the storage to execute the seeding!
        $storage = $this->getStorage($input);






    }

}