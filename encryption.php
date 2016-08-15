<?php 
//class starford
//this is my version of encryption function
class Encryption{

    const METHOD = 'aes-128-cbc';
    private $key;//where the key will be stored
    private $hashkey;//where the key will be stored
    
    /**
    * This function implements the algorithm outlined
    * @param string $key    the string to use for the opensslkey
    * @param  string $hashkey the string is used for the hash_mac key
    * @param string $crypto_algo the desired HMAC crypto algorithm
    * @return string 
    */
    public function __construct($key, $hashkey)
    {
        //convert the string into a binary
        $key = hash('SHA256',$key, true);
        if (!extension_loaded('openssl'))://check if open ssl is loaded]
            //exit('openssl isnt loaded');//if openssl isnt loaded exit here
            throw new Exception("openssl isnt loaded");
        endif;
        if (mb_strlen($key, '8bit') !== 32):
            throw new Exception("Needs a 256-bit key!");
        endif;
        if (empty($hashkey)):
            throw new Exception("Hash Key needs to be set");
        endif;
        $this->key = $key;//initialize the key
        $this->hashkey = $hashkey;//initialize the key
    }

    /**
    * This function implements the algorithm outlined
    * @param string $message    the string to  be encrypted
    * @return string as an encrypted value and added hash to it 
    */
    public function encrypt($message){

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $iv = openssl_random_pseudo_bytes($ivsize);
        //$iv = "+Á@4–`ÀàãSº§";//hard coded the vector to see how it behaves

        // print($iv);
        // echo '<br/>';

        $ciphertext = openssl_encrypt($message,self::METHOD,$this->key,OPENSSL_RAW_DATA,$iv);
        $encrypted_data = base64_encode($iv.$ciphertext);
        //add a MAC to this function
        $encrypted_data_hash = hash_hmac("sha256", $encrypted_data,$this->hashkey);

        //return $iv.$ciphertext;
        return $encrypted_data_hash.$encrypted_data;

    }//end of encrypt function

    /**
    * This function implements the algorithm outlined
    * @param string $message    the string to  be encrypted
    * @return string as an decrypted value and added hash to it 
    */
    public function decrypt($message){
        //get the hash input
        $hmac_input = substr($message, 0, 64);//the value will be 64 coz of the algorithm used
        $data = substr($message, strlen(hash_hmac("sha256", $message,$this->hashkey)));
        $generated_hash = hash_hmac("sha256", $data,$this->hashkey);
        // if($generated_hash != $hmac_input)://throw an exception
        //  throw new Exception("Hash Does Not Match");
        // endif;

        $data = base64_decode($data);

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $iv = mb_substr($data, 0, $ivsize, '8bit');
        $ciphertext = mb_substr($data, $ivsize, null, '8bit');

        //$decrypted_data = openssl_decrypt($ciphertext,self::METHOD,$this->key,OPENSSL_RAW_DATA,$iv);
        $decrypted_data = openssl_decrypt($ciphertext,self::METHOD,$this->key,OPENSSL_RAW_DATA,$iv);

        return $decrypted_data;

    }//end of decrypting function
}

 ?>
