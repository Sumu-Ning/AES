CLASS zcl_aes_utility DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
*"* public components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!

    CONSTANTS mc_block_length_in_bit TYPE int4 VALUE 128.   "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_128 TYPE int4 VALUE 128. "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_192 TYPE int4 VALUE 192. "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_256 TYPE int4 VALUE 256. "#EC NOTEXT

    CLASS-METHODS is_valid_key_xstring
      IMPORTING
        !i_key TYPE xstring
      RETURNING
        value(r_valid) TYPE boole_d .
    CLASS-METHODS encrypt_xstring
      IMPORTING
        !i_key TYPE xstring
        !i_data TYPE xstring
      EXPORTING
        !e_data TYPE xstring .
    CLASS-METHODS decrypt_xstring
      IMPORTING
        !i_key TYPE xstring
        !i_data TYPE xstring
      EXPORTING
        !e_data TYPE xstring .
  PROTECTED SECTION.
*"* protected components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!

    CLASS-DATA mo_rijndael_128_128 TYPE REF TO zcl_rijndael_utility .
    CLASS-DATA mo_rijndael_128_192 TYPE REF TO zcl_rijndael_utility .
    CLASS-DATA mo_rijndael_128_256 TYPE REF TO zcl_rijndael_utility .

    CLASS-METHODS get_rijndael
      IMPORTING
        !i_key TYPE xstring
      RETURNING
        value(r_rajndael) TYPE REF TO zcl_rijndael_utility .
  PRIVATE SECTION.
*"* private components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_AES_UTILITY IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>DECRYPT_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_DATA                         TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD decrypt_xstring.
    DATA: rijndael  TYPE REF TO zcl_rijndael_utility.

    rijndael = get_rijndael( i_key = i_key ).

    rijndael->decrypt_xstring(
      EXPORTING
        i_key = i_key
        i_data = i_data
      IMPORTING
        e_data = e_data
    ).
  ENDMETHOD.                    "decrypt_xstring


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>ENCRYPT_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_DATA                         TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD encrypt_xstring.
    DATA: rijndael  TYPE REF TO zcl_rijndael_utility.

    rijndael = get_rijndael( i_key = i_key ).

    rijndael->encrypt_xstring(
      EXPORTING
        i_key = i_key
        i_data = i_data
      IMPORTING
        e_data = e_data
    ).
  ENDMETHOD.                    "encrypt_xstring


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Protected Method ZCL_AES_UTILITY=>GET_RIJNDAEL
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [<-()] R_RAJNDAEL                     TYPE REF TO ZCL_RIJNDAEL_UTILITY
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD get_rijndael.
    DATA: key_length_in_bit   TYPE int4.

    key_length_in_bit = xstrlen( i_key ) * zcl_rijndael_utility=>mc_factor_bit_byte.

    IF key_length_in_bit = mc_key_length_in_bit_128.
      IF mo_rijndael_128_128 IS NOT BOUND.
        CREATE OBJECT
          mo_rijndael_128_128
          EXPORTING
            i_key_length_in_bit   = mc_key_length_in_bit_128
            i_block_length_in_bit = mc_block_length_in_bit.
      ENDIF.

      r_rajndael = mo_rijndael_128_128.

    ELSEIF key_length_in_bit = mc_key_length_in_bit_192.
      IF mo_rijndael_128_192 IS NOT BOUND.
        CREATE OBJECT
          mo_rijndael_128_192
          EXPORTING
            i_key_length_in_bit   = mc_key_length_in_bit_192
            i_block_length_in_bit = mc_block_length_in_bit.
      ENDIF.

      r_rajndael = mo_rijndael_128_192.

    ELSEIF key_length_in_bit = mc_key_length_in_bit_256.
      IF mo_rijndael_128_256 IS NOT BOUND.
        CREATE OBJECT
          mo_rijndael_128_256
          EXPORTING
            i_key_length_in_bit   = mc_key_length_in_bit_256
            i_block_length_in_bit = mc_block_length_in_bit.
      ENDIF.

      r_rajndael = mo_rijndael_128_256.
    ELSE.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_KEY'
          value = 'Incorrect key length'.
    ENDIF.

  ENDMETHOD.                    "get_rijndael


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>IS_VALID_KEY_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [<-()] R_VALID                        TYPE        BOOLE_D
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD is_valid_key_xstring.
    DATA: key_length_in_bit   TYPE int4.

    key_length_in_bit = xstrlen( i_key ) * zcl_rijndael_utility=>mc_factor_bit_byte.

    IF key_length_in_bit = mc_key_length_in_bit_128
        OR key_length_in_bit = mc_key_length_in_bit_192
        OR key_length_in_bit = mc_key_length_in_bit_256.
      r_valid = abap_true.
    ENDIF.

  ENDMETHOD.                    "is_valid_key_xstring
ENDCLASS.
