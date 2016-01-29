*----------------------------------------------------------------------*
*       CLASS ZCL_AES_UTILITY DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_aes_utility DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
*"* public components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!

    CONSTANTS mc_block_length_in_bit TYPE int4 VALUE 128.   "#EC NOTEXT
    CONSTANTS mc_block_length_in_byte TYPE int4 VALUE 16.   "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_128 TYPE int4 VALUE 128. "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_192 TYPE int4 VALUE 192. "#EC NOTEXT
    CONSTANTS mc_key_length_in_bit_256 TYPE int4 VALUE 256. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_ecb TYPE char10 VALUE 'ECB'. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_cbc TYPE char10 VALUE 'CBC'. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_pcbc TYPE char10 VALUE 'PCBC'. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_cfb TYPE char10 VALUE 'CFB'. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_ofb TYPE char10 VALUE 'OFB'. "#EC NOTEXT
    CONSTANTS mc_encryption_mode_ctr TYPE char10 VALUE 'CTR'. "#EC NOTEXT

    CLASS-METHODS is_valid_key_xstring
      IMPORTING
        !i_key TYPE xstring
      RETURNING
        value(r_valid) TYPE boole_d .
    CLASS-METHODS is_valid_iv_xstring
      IMPORTING
        !i_initialization_vector TYPE xstring
      RETURNING
        value(r_valid) TYPE boole_d .
    CLASS-METHODS encrypt_xstring
      IMPORTING
        !i_key TYPE xstring
        !i_data TYPE xstring
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_encryption_mode TYPE char10 OPTIONAL
      EXPORTING
        !e_data TYPE xstring .
    CLASS-METHODS decrypt_xstring
      IMPORTING
        !i_key TYPE xstring
        !i_data TYPE xstring
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_encryption_mode TYPE char10 OPTIONAL
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
    CLASS-METHODS get_blockdata_in_xstring
      IMPORTING
        !i_data TYPE xstring
        !i_data_length_in_byte TYPE int4
        !i_block_length_in_byte TYPE int4
        !i_block_sequence_number TYPE int4
      EXPORTING
        !e_block_data TYPE xstring .
    CLASS-METHODS get_counter_increment
      IMPORTING
        !i_data TYPE xstring
      RETURNING
        value(r_data) TYPE xstring .	
  PRIVATE SECTION.
*"* private components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!
ENDCLASS.                    "ZCL_AES_UTILITY DEFINITION



*----------------------------------------------------------------------*
*       CLASS ZCL_AES_UTILITY IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_aes_utility IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>DECRYPT_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_INITIALIZATION_VECTOR        TYPE        XSTRING(optional)
* | [--->] I_ENCRYPTION_MODE              TYPE        CHAR10(optional)
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD decrypt_xstring.
    DATA: rijndael  TYPE REF TO zcl_rijndael_utility.
    DATA: data_length_in_byte     TYPE int4,
          number_of_blocks        TYPE int4,
          block_sequence_cursor   TYPE int4 VALUE 0.
    DATA: working_plain_block     TYPE xstring,
          working_cipher_block    TYPE xstring,
          origin_plain_block      TYPE xstring,
          converted_plain_block   TYPE xstring,
          origin_cipher_block     TYPE xstring,
          converted_cipher_block  TYPE xstring,
          converter_block         TYPE xstring.

    IF i_encryption_mode = mc_encryption_mode_cbc
          OR i_encryption_mode = mc_encryption_mode_pcbc
          OR i_encryption_mode = mc_encryption_mode_cfb
          OR i_encryption_mode = mc_encryption_mode_ofb
          OR i_encryption_mode = mc_encryption_mode_ctr.
      IF is_valid_iv_xstring( i_initialization_vector ) = abap_false.
        RAISE EXCEPTION TYPE cx_me_illegal_argument
          EXPORTING
            name  = 'I_INITIALIZATION_VECTOR'
            value = 'Incorrect Initialization Vector length'.      
      ENDIF.

    ELSEIF i_encryption_mode = mc_encryption_mode_ecb
          OR i_encryption_mode IS INITIAL.
      "Nothing, default is ECB mode

    ELSE.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_ENCRYPTION_MODE'
          value = 'Incorrect Encryption Mode'.    

    ENDIF.

    CLEAR e_data.

    rijndael = get_rijndael( i_key = i_key ).

    "Prepare some data
    data_length_in_byte = xstrlen( i_data ).
    number_of_blocks = ceil( '1.0' * data_length_in_byte * zcl_rijndael_utility=>mc_factor_bit_byte / mc_block_length_in_bit ).

    CASE i_encryption_mode.
      WHEN mc_encryption_mode_cbc.
        converter_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = working_cipher_block ).

          rijndael->decrypt_xstring(
            EXPORTING
              i_data  = working_cipher_block
              i_key   = i_key
            IMPORTING
              e_data  = working_plain_block ).

          origin_plain_block = working_plain_block BIT-XOR converter_block.

          e_data = e_data && origin_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          converter_block = working_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_pcbc.
        converter_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = working_cipher_block ).

          rijndael->decrypt_xstring(
            EXPORTING
              i_data  = working_cipher_block
              i_key   = i_key
            IMPORTING
              e_data  = working_plain_block ).

          origin_plain_block = working_plain_block BIT-XOR converter_block.

          e_data = e_data && origin_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          converter_block = working_cipher_block BIT-XOR origin_plain_block.
        ENDWHILE.

      WHEN mc_encryption_mode_cfb.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).
          converter_block = working_cipher_block.

          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_cipher_block ).

          origin_plain_block = origin_cipher_block BIT-XOR converter_block.

          e_data = e_data && origin_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = origin_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_ofb.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).
          converter_block = working_cipher_block.

          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_cipher_block ).

          origin_plain_block = origin_cipher_block BIT-XOR converter_block.

          e_data = e_data && origin_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = working_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_ctr.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).
          converter_block = working_cipher_block.

          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          converted_plain_block = origin_plain_block BIT-XOR converter_block.

          e_data = e_data && converted_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = get_counter_increment( working_plain_block ).
        ENDWHILE.

      WHEN mc_encryption_mode_ecb OR ''.
        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = working_cipher_block ).

          rijndael->decrypt_xstring(
            EXPORTING
              i_data  = working_cipher_block
              i_key   = i_key
            IMPORTING
              e_data  = working_plain_block ).

          e_data = e_data && working_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
        ENDWHILE.

    ENDCASE.

  ENDMETHOD.                    "decrypt_xstring


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>ENCRYPT_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_INITIALIZATION_VECTOR        TYPE        XSTRING(optional)
* | [--->] I_ENCRYPTION_MODE              TYPE        CHAR10(optional)
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD encrypt_xstring.
    DATA: rijndael                TYPE REF TO zcl_rijndael_utility.
    DATA: data_length_in_byte     TYPE int4,
          number_of_blocks        TYPE int4,
          block_sequence_cursor   TYPE int4 VALUE 0.
    DATA: working_plain_block     TYPE xstring,
          working_cipher_block    TYPE xstring,
          origin_plain_block      TYPE xstring,
          converted_plain_block   TYPE xstring,
          origin_cipher_block     TYPE xstring,
          converted_cipher_block  TYPE xstring,
          converter_block         TYPE xstring.

    IF i_encryption_mode = mc_encryption_mode_cbc
          OR i_encryption_mode = mc_encryption_mode_pcbc
          OR i_encryption_mode = mc_encryption_mode_cfb
          OR i_encryption_mode = mc_encryption_mode_ofb
          OR i_encryption_mode = mc_encryption_mode_ctr.
      IF is_valid_iv_xstring( i_initialization_vector ) = abap_false.
        RAISE EXCEPTION TYPE cx_me_illegal_argument
          EXPORTING
            name  = 'I_INITIALIZATION_VECTOR'
            value = 'Incorrect Initialization Vector length'.
      ENDIF.

    ELSEIF i_encryption_mode = mc_encryption_mode_ecb
          OR i_encryption_mode IS INITIAL.
      "Nothing, default is ECB mode

    ELSE.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_ENCRYPTION_MODE'
          value = 'Incorrect Encryption Mode'.    

    ENDIF.

    CLEAR e_data.

    rijndael = get_rijndael( i_key = i_key ).

    "Prepare some data
    data_length_in_byte = xstrlen( i_data ).
    number_of_blocks = ceil( '1.0' * data_length_in_byte * zcl_rijndael_utility=>mc_factor_bit_byte / mc_block_length_in_bit ).

    CASE i_encryption_mode.
      WHEN mc_encryption_mode_cbc.
        converter_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          working_plain_block = origin_plain_block BIT-XOR converter_block.

          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).

          e_data = e_data && working_cipher_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          converter_block = working_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_pcbc.
        converter_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          working_plain_block = origin_plain_block BIT-XOR converter_block.

          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).

          e_data = e_data && working_cipher_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          converter_block = working_cipher_block BIT-XOR working_plain_block.
        ENDWHILE.

      WHEN mc_encryption_mode_cfb.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          converter_block = origin_plain_block.

          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).

          converted_cipher_block = working_cipher_block BIT-XOR converter_block.

          e_data = e_data && converted_cipher_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = converted_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_ofb.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          converter_block = origin_plain_block.

          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).

          converted_cipher_block = working_cipher_block BIT-XOR converter_block.

          e_data = e_data && converted_cipher_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = working_cipher_block.
        ENDWHILE.

      WHEN mc_encryption_mode_ctr.
        working_plain_block = i_initialization_vector.

        WHILE block_sequence_cursor < number_of_blocks.
          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).
          converter_block = working_cipher_block.

          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = origin_plain_block ).

          converted_plain_block = origin_plain_block BIT-XOR converter_block.

          e_data = e_data && converted_plain_block.

          block_sequence_cursor = block_sequence_cursor + 1.
          working_plain_block = get_counter_increment( working_plain_block ).
        ENDWHILE.

      WHEN mc_encryption_mode_ecb OR ''.
        WHILE block_sequence_cursor < number_of_blocks.
          get_blockdata_in_xstring(
            EXPORTING
              i_data                  = i_data
              i_data_length_in_byte   = data_length_in_byte
              i_block_length_in_byte  = mc_block_length_in_byte
              i_block_sequence_number = block_sequence_cursor
            IMPORTING
              e_block_data            = working_plain_block ).

          rijndael->encrypt_xstring(
            EXPORTING
              i_data  = working_plain_block
              i_key   = i_key
            IMPORTING
              e_data  = working_cipher_block ).

          e_data = e_data && working_cipher_block.

          block_sequence_cursor = block_sequence_cursor + 1.
        ENDWHILE.

    ENDCASE.

  ENDMETHOD.                    "encrypt_xstring


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Protected Method ZCL_AES_UTILITY=>GET_BLOCKDATA_IN_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_DATA_LENGTH_IN_BYTE          TYPE        INT4
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4
* | [--->] I_BLOCK_SEQUENCE_NUMBER        TYPE        INT4
* | [<---] E_BLOCK_DATA                   TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD get_blockdata_in_xstring.
    DATA: offset_in_byte                  TYPE int4,
          target_block_length_in_byte     TYPE int4.

    offset_in_byte = i_block_sequence_number * i_block_length_in_byte.
    target_block_length_in_byte = i_data_length_in_byte - offset_in_byte.
    IF target_block_length_in_byte >= i_block_length_in_byte.
      target_block_length_in_byte = i_block_length_in_byte.
    ENDIF.

    e_block_data = i_data+offset_in_byte(target_block_length_in_byte).

    WHILE target_block_length_in_byte < i_block_length_in_byte.
      e_block_data = e_block_data && '00'.
      target_block_length_in_byte = target_block_length_in_byte + 1.
    ENDWHILE.

  ENDMETHOD.                    "get_blockdata_in_xstring


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES_UTILITY=>GET_COUNTER_INCREMENT
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [<-()] R_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD get_counter_increment.
    DATA: offset          TYPE int4,
          length          TYPE int4,
          cursor          TYPE x LENGTH 1,
          one             TYPE x LENGTH 1 VALUE '01'..

    length = xstrlen( i_data ).
    offset = length - 1.
    WHILE offset >= 0.
      cursor = i_data+offset(1).
      cursor = cursor + one.
      r_data = cursor && r_data.

      IF cursor <> '00'.
        EXIT.
      ENDIF.

      offset = offset - 1.
    ENDWHILE.

    IF offset >= 0.
      r_data = i_data+0(offset) && r_data.
    ENDIF.

  ENDMETHOD.                    "get_counter_increment


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
* | Static Public Method ZCL_AES_UTILITY=>IS_VALID_IV_XSTRING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_INITIALIZATION_VECTOR        TYPE        XSTRING
* | [<-()] R_VALID                        TYPE        BOOLE_D
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD is_valid_iv_xstring.
    DATA: iv_length_in_bit   TYPE int4.

    iv_length_in_bit = xstrlen( i_initialization_vector ) * zcl_rijndael_utility=>mc_factor_bit_byte.

    IF iv_length_in_bit = mc_block_length_in_bit.
      r_valid = abap_true.
    ENDIF.

  ENDMETHOD.                    "is_valid_iv_xstring


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
ENDCLASS.                    "ZCL_AES_UTILITY IMPLEMENTATION
