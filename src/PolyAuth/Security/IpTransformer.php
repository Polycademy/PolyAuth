<?php

namespace PolyAuth\Security;

class IpTransformer{

    /**
     * Helper function to transform the ip and format it correctly for insertion.
     * If inputted with a string, it will output a packed in_addr representation.
     * If inputted with a binary string, it will leave it the same.
     *
     * @return $ip binary
     */
    protected insert($ip){

        //in_addr binary
        if(ctype_print($ip)){
            return inet_pton($ip);
        }

        return $ip;

    }

    /**
     * Helper function to transform the ip and format it correctly for extraction.
     * If inputted with a string, it will leave it the same.
     * If inputted with a binary string, it will output an unpacked human readable string.
     *
     * @return $ip string
     */
    protected extract($ip){

        //human readable string
        if(ctype_print($ip)){
            return $ip;
        }

        return inet_ntop($ip);

    }

}