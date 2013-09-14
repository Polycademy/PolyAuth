<?php

namespace PolyAuth\Storage;

use Psr\Log\LoggerAwareInterface;
use RBAC\DataStore\StorageInterface as RBACStorageInterface;

interface StorageInterface extends LoggerAwareInterface, RBACStorageInterface{



}