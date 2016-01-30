# AES algorithm implementation by ABAP

ABAP Utilities for AES encryption, decryption under MIT License.

Actual Implementation is done by the more generic Rijndael way, and AES is treated as a special case.

Please just copy the source code file into ABAP editor (Source Code-Based mode), and activate it.

Classes:
  ZCL_RIJNDAEL_UTILITY: implementation of Rijndael, encrypt and decrypt using xstring.
  ZCL_AES_UTILITY: AES wrapper on ZCL_RIJNDAEL_UTILITY, just need to provide key and data.
  ZCL_AES_UTILITY_TEST: Testing cases of ZCL_AES_UTILITY, including encryption mode ECB, CBC, CFB, OFB, CTR, Testing of PCBC is not included yet. Testing Data is from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
  

