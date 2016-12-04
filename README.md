# AES algorithm implementation by ABAP

ABAP Utilities for AES encryption, decryption under MIT License.

Actual Implementation is done by the more generic Rijndael way, and AES is treated as a special case.

Supporting:  
  * Encryption mode: ECB, CBC, PCBC, CFB, OFB, CTR.  
  * Padding standard: None, PKCS #5, PKCS #7.

Please just copy the source code file into ABAP editor (Source Code-Based mode), and activate it. Or install via [abapGit](http://www.abapgit.org).

Classes:  
  * ZIF_AES_MODE: Interface for different encryption mode.  
  * ZCL_AES_MODE_CBC: CBC mode.  
  * ZCL_AES_MODE_CFB: CFB mode.  
  * ZCL_AES_MODE_CTR: CTR mode.  
  * ZCL_AES_MODE_ECB: ECB mode.  
  * ZCL_AES_MODE_OFB: OFB mode.  
  * ZCL_AES_MODE_PCBC: PCBC mode.  
  * ZCL_BYTE_PADDING_UTILITY: Abstract class for Byte padding utilities, including factory method to get concrete class instances.  
  * ZCL_PADDING_UTILITY_NONE: No padding.  
  * ZCL_PADDING_UTILITY_PKCS_5: Padding using PKCS #5.  
  * ZCL_PADDING_UTILITY_PKCS_7: Padding using PKCS #7.  
  * ZCL_RIJNDAEL_UTILITY: implementation of Rijndael, encrypt and decrypt using xstring.  
  * ZCL_AES_UTILITY: AES wrapper on ZCL_RIJNDAEL_UTILITY, just need to provide key and data.  
  * ZCL_AES_UTILITY_TEST:   
    * Testing cases of ZCL_AES_UTILITY, including encryption mode ECB, CBC, CFB, OFB, CTR, Testing of PCBC is not included yet. 
	* Testing Data is from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf  
    * Testing cases of No padding and PKCS #7 padding, but only in ECB, CBC and CTR mode.  
  

