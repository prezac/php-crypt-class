<?php
/****
File name : class.Crypt.php
Description : Class for string encrypt-decrypt.
Author : Petr Rezac
Date : 12th Apr 2021
Version : 1.7
Copyright (c) 2010 PR-Software <prezac@pr-software.net>
****/


class Crypt{

 var $inputString;    // input data
 var $cryptKey;       // crypting key
 var $cryptMethod;    // encrypt/decrypt
 var $cryptType;      // string/mcrypt/openssl/sodium
 
 function runCrypt($in,$k,$m,$t){
  $this->inputString=$in;
  $this->cryptKey=$k;
  $this->cryptMethod=$m;
  $this->cryptType=$t;
  switch ($this->cryptMethod){
   case "encrypt":
    return $this->encrypt($this->cryptType);
   break;
   case "decrypt":
    return $this->decrypt($this->cryptType);
   break;
  }
 }

public function encrypt($ty) {
  switch ($ty){
   case "string":
    $result = "";
    for($i=0; $i<strlen($this->inputString); $i++) {
        $char = substr($this->inputString, $i, 1);
        $keychar = substr($this->cryptKey, ($i % strlen($this->cryptKey))-1, 1);
        $char = chr(ord($char)+ord($keychar));
        $result.=$char;
    }
    return base64_encode($result);
   break;
   case "mcrypt":
    $iv = md5(md5($this->cryptKey));
    $output = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($this->cryptKey), $this->inputString, MCRYPT_MODE_CBC, $iv);
    $output = base64_encode($output);
    return $output;
   break;
   case "openssl":
    $encrypted_string=openssl_encrypt($this->inputString,"AES-256-ECB",$this->cryptKey);
    return $encrypted_string;
   break;   
   case "sodium":
    $nonce = \Sodium\randombytes_buf(
        \Sodium\CRYPTO_SECRETBOX_NONCEBYTES
    );
    return base64_encode(
        $nonce.
        \Sodium\crypto_secretbox(
            $this->inputString,
            $nonce,
            $this->cryptKey
        )
    );
   break;   
  }
}

public function decrypt($ty) {
  switch ($ty){
   case "string":
    $result = "";
    $this->inputString = base64_decode($this->inputString);
    for($i=0; $i<strlen($this->inputString); $i++) {
        $char = substr($this->inputString, $i, 1);
        $keychar = substr($this->cryptKey, ($i % strlen($this->cryptKey))-1, 1);
        $char = chr(ord($char)-ord($keychar));
        $result.=$char;
    }
    return $result;
   break;
   case "mcrypt":
    $iv = md5(md5($this->cryptKey));
    $output = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($this->cryptKey), base64_decode($this->inputString), MCRYPT_MODE_CBC, $iv);
    $output = rtrim($output, "");
    return $output;
   break;
   case "openssl":
    $decrypted_string=openssl_decrypt($this->inputString,"AES-256-ECB",$this->cryptKey);
    return $decrypted_string;
   break;
   case "sodium":
    $decoded = base64_decode($this->inputString);
    $nonce = mb_substr($decoded, 0, \Sodium\CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
    $ciphertext = mb_substr($decoded, \Sodium\CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
    return \Sodium\crypto_secretbox_open(
        $ciphertext,
        $nonce,
        $this->cryptKey
    );
   break;
  }
}
//end class
}
?>
