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
    CONSTANTS mc_block_length_in_bit TYPE int4 VALUE 128 ##NO_TEXT.
    CONSTANTS mc_block_length_in_byte TYPE int4 VALUE 16 ##NO_TEXT.
    CONSTANTS mc_key_length_in_bit_128 TYPE int4 VALUE 128 ##NO_TEXT.
    CONSTANTS mc_key_length_in_bit_192 TYPE int4 VALUE 192 ##NO_TEXT.
    CONSTANTS mc_key_length_in_bit_256 TYPE int4 VALUE 256 ##NO_TEXT.
    CONSTANTS mc_encryption_mode_ecb TYPE char10 VALUE 'ECB' ##NO_TEXT.
    CONSTANTS mc_encryption_mode_cbc TYPE char10 VALUE 'CBC' ##NO_TEXT.
    CONSTANTS mc_encryption_mode_pcbc TYPE char10 VALUE 'PCBC' ##NO_TEXT.
    CONSTANTS mc_encryption_mode_cfb TYPE char10 VALUE 'CFB' ##NO_TEXT.
    CONSTANTS mc_encryption_mode_ofb TYPE char10 VALUE 'OFB' ##NO_TEXT.
    CONSTANTS mc_encryption_mode_ctr TYPE char10 VALUE 'CTR' ##NO_TEXT.
    CONSTANTS mc_padding_standard_none TYPE char10 VALUE 'NONE' ##NO_TEXT.
    CONSTANTS mc_padding_standard_pkcs_7 TYPE char10 VALUE 'PKCS7' ##NO_TEXT.
    CLASS-DATA:
      mt_raw16 TYPE TABLE OF zif_aes_mode=>ty_raw16 .

    CLASS-METHODS is_valid_iv_xstring
      IMPORTING
        !i_initialization_vector TYPE xstring
      RETURNING
        VALUE(r_valid)           TYPE boole_d .
    CLASS-METHODS encrypt_xstring
      IMPORTING
        !i_key                   TYPE xstring
        !i_data                  TYPE xstring
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_padding_standard      TYPE char10 OPTIONAL
        !i_encryption_mode       TYPE char10 OPTIONAL
      EXPORTING
        !e_data                  TYPE xstring .
    CLASS-METHODS decrypt_xstring
      IMPORTING
        !i_key                   TYPE xstring
        !i_data                  TYPE xstring
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_padding_standard      TYPE char10 OPTIONAL
        !i_encryption_mode       TYPE char10 OPTIONAL
      EXPORTING
        !e_data                  TYPE xstring .
    CLASS-METHODS encrypt_raw16_table
      IMPORTING
        !i_key                   TYPE xstring
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_encryption_mode       TYPE char10 OPTIONAL
        !i_padding_standard      TYPE char10 OPTIONAL
        !i_data_length_in_byte   TYPE int4
      EXPORTING
        !et_data                 LIKE mt_raw16
      CHANGING
        !ct_data                 LIKE mt_raw16 .
    CLASS-METHODS decrypt_raw16_table
      IMPORTING
        !i_key                   TYPE xstring
        !i_initialization_vector TYPE xstring
        !i_encryption_mode       TYPE char10
        !i_padding_standard      TYPE char10
        !it_data                 LIKE mt_raw16
      EXPORTING
        !e_data_length_in_byte   TYPE int4
        !et_data                 LIKE mt_raw16 .
    CLASS-METHODS convert_xstring_to_raw16_table
      IMPORTING
        !i_data                TYPE xstring
      EXPORTING
        !e_data_length_in_byte TYPE int4
        !et_raw16_table        LIKE mt_raw16 .
    CLASS-METHODS convert_raw16_table_to_xstring
      IMPORTING
        !i_data_length_in_byte TYPE int4
        !it_raw16_table        LIKE mt_raw16
      EXPORTING
        !e_data                TYPE xstring .
    CLASS-METHODS validate_encryption_mode
      IMPORTING
        !i_initialization_vector TYPE xstring OPTIONAL
        !i_encryption_mode       TYPE char10 OPTIONAL .
    CLASS-METHODS validate_padding_standard
      IMPORTING
        !i_padding_standard TYPE char10 OPTIONAL .
    CLASS-METHODS validate_raw16_table_size
      IMPORTING
        !i_data_length_in_byte TYPE int4
        !it_data               LIKE mt_raw16 .
    CLASS-METHODS add_padding_raw16_table
      IMPORTING
        !i_data_length_in_byte TYPE int4
        !io_padding_utility    TYPE REF TO zcl_byte_padding_utility
      CHANGING
        !ct_data               LIKE mt_raw16 .
    CLASS-METHODS remove_padding_raw16_table
      IMPORTING
        !io_padding_utility    TYPE REF TO zcl_byte_padding_utility
      EXPORTING
        !e_data_length_in_byte TYPE int4
      CHANGING
        !ct_data               LIKE mt_raw16 .
  PROTECTED SECTION.

*"* protected components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!
    CLASS-DATA mo_rijndael_128_128 TYPE REF TO zcl_rijndael_utility .
    CLASS-DATA mo_rijndael_128_192 TYPE REF TO zcl_rijndael_utility .
    CLASS-DATA mo_rijndael_128_256 TYPE REF TO zcl_rijndael_utility .
    CLASS-DATA mo_padding_utility_none TYPE REF TO zcl_byte_padding_utility .
    CLASS-DATA mo_padding_utility_pkcs_5 TYPE REF TO zcl_byte_padding_utility .
    CLASS-DATA mo_padding_utility_pkcs_7 TYPE REF TO zcl_byte_padding_utility .
    CLASS-DATA mo_aes_mode_cbc TYPE REF TO zif_aes_mode .
    CLASS-DATA mo_aes_mode_pcbc TYPE REF TO zif_aes_mode .
    CLASS-DATA mo_aes_mode_ofb TYPE REF TO zif_aes_mode .
    CLASS-DATA mo_aes_mode_cfb TYPE REF TO zif_aes_mode .
    CLASS-DATA mo_aes_mode_ctr TYPE REF TO zif_aes_mode .
    CLASS-DATA mo_aes_mode_ecb TYPE REF TO zif_aes_mode .

    CLASS-METHODS get_rijndael
      IMPORTING
        !i_key            TYPE xstring
      RETURNING
        VALUE(r_rajndael) TYPE REF TO zcl_rijndael_utility .
    CLASS-METHODS get_padding_utility
      IMPORTING
        !i_padding_standard      TYPE char10 OPTIONAL
      RETURNING
        VALUE(r_padding_utility) TYPE REF TO zcl_byte_padding_utility .
    CLASS-METHODS get_aes_mode
      IMPORTING
        !i_encryption_mode TYPE char10
      RETURNING
        VALUE(r_aes_mode)  TYPE REF TO zif_aes_mode .
  PRIVATE SECTION.
*"* private components of class ZCL_AES_UTILITY
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_AES_UTILITY IMPLEMENTATION.


  METHOD add_padding_raw16_table.
    DATA: lv_last_line_length       TYPE int4,
          lv_last_line_number       TYPE int4,
          lv_line_before_padding    TYPE xstring,
          lv_line_after_padding     TYPE xstring,
          lv_padding_length_in_byte TYPE int4.

    FIELD-SYMBOLS: <raw16>          TYPE zif_aes_mode=>ty_raw16.

    lv_last_line_length = i_data_length_in_byte MOD mc_block_length_in_byte.

    IF lv_last_line_length = 0.
      io_padding_utility->add_padding(
        EXPORTING
          i_block_length_in_byte    = mc_block_length_in_byte
          i_data                    = lv_line_before_padding
        IMPORTING
          e_padding_length_in_byte  = lv_padding_length_in_byte
          e_data                    = lv_line_after_padding ).

      IF lv_padding_length_in_byte > 0.
        APPEND INITIAL LINE TO ct_data ASSIGNING <raw16>.
        <raw16> = lv_line_after_padding.
      ENDIF.

    ELSE.
      lv_last_line_number = lines( ct_data ).
      READ TABLE ct_data INDEX lv_last_line_number ASSIGNING <raw16>.
      lv_line_before_padding = <raw16>+0(lv_last_line_length).

      io_padding_utility->add_padding(
      EXPORTING
        i_block_length_in_byte    = mc_block_length_in_byte
        i_data                    = lv_line_before_padding
      IMPORTING
        e_padding_length_in_byte  = lv_padding_length_in_byte
        e_data                    = lv_line_after_padding ).

      <raw16> = lv_line_after_padding.

    ENDIF.

  ENDMETHOD.                    "add_padding_raw16_table


  METHOD convert_raw16_table_to_xstring.
    DATA: lv_last_line_length   TYPE int4.
    FIELD-SYMBOLS: <raw16>      TYPE zif_aes_mode=>ty_raw16.

    CLEAR e_data.

    IF i_data_length_in_byte <= 0.
      RETURN.
    ENDIF.

    lv_last_line_length = ( i_data_length_in_byte - 1 ) MOD mc_block_length_in_byte + 1.

    LOOP AT it_raw16_table ASSIGNING <raw16>.
      AT LAST.
        e_data = e_data && <raw16>(lv_last_line_length).
        EXIT.
      ENDAT.

      e_data = e_data && <raw16>.
    ENDLOOP.

  ENDMETHOD.                    "convert_raw16_table_to_xstring


  METHOD convert_xstring_to_raw16_table.
    DATA: lv_input_length     TYPE int4,
          lv_number_of_blocks TYPE int4,
          lv_block_cursor     TYPE int4,
          lv_offset           TYPE int4.

    FIELD-SYMBOLS: <raw16>      TYPE zif_aes_mode=>ty_raw16.

    CLEAR et_raw16_table.

    lv_input_length = xstrlen( i_data ).
    lv_number_of_blocks = ceil( '1.0' * lv_input_length / mc_block_length_in_byte ).

    lv_block_cursor = 1.
    lv_offset = 0.
    WHILE lv_block_cursor <= lv_number_of_blocks.
      APPEND INITIAL LINE TO et_raw16_table ASSIGNING <raw16>.

      IF lv_block_cursor < lv_number_of_blocks.
        <raw16> = i_data+lv_offset(mc_block_length_in_byte).
      ELSE.
        <raw16> = i_data+lv_offset.
      ENDIF.

      lv_block_cursor = lv_block_cursor + 1.
      lv_offset = lv_offset + mc_block_length_in_byte.
    ENDWHILE.

    e_data_length_in_byte = lv_input_length.

  ENDMETHOD.                    "convert_xstring_to_raw16_table


  METHOD decrypt_raw16_table.
    DATA: rijndael                TYPE REF TO zcl_rijndael_utility.
    DATA: padding_utility         TYPE REF TO zcl_byte_padding_utility.
    DATA: aes_mode                TYPE REF TO zif_aes_mode.

    CLEAR et_data.

    validate_encryption_mode(
        i_encryption_mode       = i_encryption_mode
        i_initialization_vector = i_initialization_vector ).

    validate_padding_standard( i_padding_standard ).

    rijndael = get_rijndael( i_key ).
    padding_utility = get_padding_utility( i_padding_standard ).
    aes_mode = get_aes_mode( i_encryption_mode ).

    aes_mode->decrypt_raw16_table(
      EXPORTING
        io_rijndael             = rijndael
        i_key                   = i_key
        i_initialization_vector = i_initialization_vector
        it_data                 = it_data
      IMPORTING
        et_data                 = et_data ).

    remove_padding_raw16_table(
      EXPORTING
        io_padding_utility      = padding_utility
      IMPORTING
        e_data_length_in_byte   = e_data_length_in_byte
      CHANGING
        ct_data                 = et_data ).

  ENDMETHOD.                    "DECRYPT_RAW16_TABLE


  METHOD decrypt_xstring.
    DATA: lt_plain_raw16          LIKE mt_raw16,
          lt_cipher_raw16         LIKE mt_raw16,
          lv_plain_length_in_byte TYPE int4.

    CLEAR e_data.

    convert_xstring_to_raw16_table(
      EXPORTING
        i_data      = i_data
      IMPORTING
        et_raw16_table        = lt_cipher_raw16 ).

    decrypt_raw16_table(
      EXPORTING
        i_encryption_mode       = i_encryption_mode
        i_initialization_vector = i_initialization_vector
        i_padding_standard      = i_padding_standard
        i_key                   = i_key
        it_data                 = lt_cipher_raw16
      IMPORTING
        e_data_length_in_byte   = lv_plain_length_in_byte
        et_data                 = lt_plain_raw16 ).

    convert_raw16_table_to_xstring(
      EXPORTING
        it_raw16_table          = lt_plain_raw16
        i_data_length_in_byte   = lv_plain_length_in_byte
      IMPORTING
        e_data                  = e_data ).

  ENDMETHOD.                    "decrypt_xstring


  METHOD encrypt_raw16_table.
    DATA: rijndael                TYPE REF TO zcl_rijndael_utility.
    DATA: padding_utility         TYPE REF TO zcl_byte_padding_utility.
    DATA: aes_mode                TYPE REF TO zif_aes_mode.

    CLEAR et_data.

    validate_encryption_mode(
        i_encryption_mode       = i_encryption_mode
        i_initialization_vector = i_initialization_vector ).

    validate_padding_standard( i_padding_standard ).

    validate_raw16_table_size(
        it_data                 = ct_data
        i_data_length_in_byte   = i_data_length_in_byte ).

    rijndael = get_rijndael( i_key ).
    padding_utility = get_padding_utility( i_padding_standard ).
    aes_mode = get_aes_mode( i_encryption_mode ).

    add_padding_raw16_table(
      EXPORTING
        i_data_length_in_byte   = i_data_length_in_byte
        io_padding_utility      = padding_utility
      CHANGING
        ct_data                 = ct_data ).

    aes_mode->encrypt_raw16_table(
      EXPORTING
        io_rijndael             = rijndael
        i_key                   = i_key
        i_initialization_vector = i_initialization_vector
        it_data                 = ct_data
      IMPORTING
        et_data                 = et_data ).

  ENDMETHOD.                    "encrypt_raw16_table


  METHOD encrypt_xstring.
    DATA: lt_plain_raw16           LIKE mt_raw16,
          lt_cipher_raw16          LIKE mt_raw16,
          lv_plain_length_in_byte  TYPE int4,
          lv_cipher_length_in_byte TYPE int4.

    CLEAR e_data.

    convert_xstring_to_raw16_table(
      EXPORTING
        i_data      = i_data
      IMPORTING
        e_data_length_in_byte = lv_plain_length_in_byte
        et_raw16_table        = lt_plain_raw16 ).

    encrypt_raw16_table(
      EXPORTING
        i_data_length_in_byte   = lv_plain_length_in_byte
        i_encryption_mode       = i_encryption_mode
        i_initialization_vector = i_initialization_vector
        i_padding_standard      = i_padding_standard
        i_key                   = i_key
      IMPORTING
        et_data                 = lt_cipher_raw16
      CHANGING
        ct_data                 = lt_plain_raw16 ).

    lv_cipher_length_in_byte = lines( lt_cipher_raw16 ) * mc_block_length_in_byte.

    convert_raw16_table_to_xstring(
      EXPORTING
        it_raw16_table          = lt_cipher_raw16
        i_data_length_in_byte   = lv_cipher_length_in_byte
      IMPORTING
        e_data                  = e_data ).

  ENDMETHOD.                    "encrypt_xstring


  METHOD get_aes_mode.
    CASE i_encryption_mode.
      WHEN space OR mc_encryption_mode_ecb.
        IF mo_aes_mode_ecb IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_ecb TYPE zcl_aes_mode_ecb.
        ENDIF.
        r_aes_mode = mo_aes_mode_ecb.

      WHEN mc_encryption_mode_cbc.
        IF mo_aes_mode_cbc IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_cbc TYPE zcl_aes_mode_cbc.
        ENDIF.
        r_aes_mode = mo_aes_mode_cbc.

      WHEN mc_encryption_mode_pcbc.
        IF mo_aes_mode_pcbc IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_pcbc TYPE zcl_aes_mode_pcbc.
        ENDIF.
        r_aes_mode = mo_aes_mode_pcbc.

      WHEN mc_encryption_mode_cfb.
        IF mo_aes_mode_cfb IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_cfb TYPE zcl_aes_mode_cfb.
        ENDIF.
        r_aes_mode = mo_aes_mode_cfb.

      WHEN mc_encryption_mode_ofb.
        IF mo_aes_mode_ofb IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_ofb TYPE zcl_aes_mode_ofb.
        ENDIF.
        r_aes_mode = mo_aes_mode_ofb.

      WHEN mc_encryption_mode_ctr.
        IF mo_aes_mode_ctr IS NOT BOUND.
          CREATE OBJECT mo_aes_mode_ctr TYPE zcl_aes_mode_ctr.
        ENDIF.
        r_aes_mode = mo_aes_mode_ctr.

    ENDCASE.

  ENDMETHOD.                    "get_aes_mode


  METHOD get_padding_utility.
    CASE i_padding_standard.
      WHEN space OR zcl_byte_padding_utility=>mc_padding_standard_none.
        IF mo_padding_utility_none IS NOT BOUND.
          mo_padding_utility_none = zcl_byte_padding_utility=>get_byte_padding_utility( i_padding_standard ).
        ENDIF.
        r_padding_utility = mo_padding_utility_none.

      WHEN zcl_byte_padding_utility=>mc_padding_standard_pkcs_5.
        IF mo_padding_utility_pkcs_5 IS NOT BOUND.
          mo_padding_utility_pkcs_5 = zcl_byte_padding_utility=>get_byte_padding_utility( i_padding_standard ).
        ENDIF.
        r_padding_utility = mo_padding_utility_pkcs_5.

      WHEN zcl_byte_padding_utility=>mc_padding_standard_pkcs_7.
        IF mo_padding_utility_pkcs_7 IS NOT BOUND.
          mo_padding_utility_pkcs_7 = zcl_byte_padding_utility=>get_byte_padding_utility( i_padding_standard ).
        ENDIF.
        r_padding_utility = mo_padding_utility_pkcs_7.

    ENDCASE.
  ENDMETHOD.                    "get_padding_utility


  METHOD get_rijndael.
    DATA: key_length_in_bit   TYPE int4.

    key_length_in_bit = xstrlen( i_key ) * zcl_rijndael_utility=>mc_factor_bit_byte.

    IF key_length_in_bit = mc_key_length_in_bit_128.
      IF mo_rijndael_128_128 IS NOT BOUND.
        CREATE OBJECT mo_rijndael_128_128
          EXPORTING
            i_key_length_in_bit   = mc_key_length_in_bit_128
            i_block_length_in_bit = mc_block_length_in_bit.
      ENDIF.

      r_rajndael = mo_rijndael_128_128.

    ELSEIF key_length_in_bit = mc_key_length_in_bit_192.
      IF mo_rijndael_128_192 IS NOT BOUND.
        CREATE OBJECT mo_rijndael_128_192
          EXPORTING
            i_key_length_in_bit   = mc_key_length_in_bit_192
            i_block_length_in_bit = mc_block_length_in_bit.
      ENDIF.

      r_rajndael = mo_rijndael_128_192.

    ELSEIF key_length_in_bit = mc_key_length_in_bit_256.
      IF mo_rijndael_128_256 IS NOT BOUND.
        CREATE OBJECT mo_rijndael_128_256
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


  METHOD is_valid_iv_xstring.
    DATA: iv_length_in_bit   TYPE int4.

    iv_length_in_bit = xstrlen( i_initialization_vector ) * zcl_rijndael_utility=>mc_factor_bit_byte.

    IF iv_length_in_bit = mc_block_length_in_bit.
      r_valid = abap_true.
    ENDIF.

  ENDMETHOD.                    "is_valid_iv_xstring


  METHOD remove_padding_raw16_table.
    DATA: lv_padding_length      TYPE int4,
          lv_last_line_number    TYPE int4,
          lv_line_before_padding TYPE xstring,
          lv_line_after_padding  TYPE xstring.

    FIELD-SYMBOLS: <raw16> TYPE zif_aes_mode=>ty_raw16.

    CLEAR e_data_length_in_byte.

    lv_last_line_number = lines( ct_data ).
    IF lv_last_line_number <= 0.
      RETURN.
    ENDIF.

    READ TABLE ct_data INDEX lv_last_line_number ASSIGNING <raw16>.
    lv_line_after_padding = <raw16>.

    io_padding_utility->remove_padding(
      EXPORTING
        i_block_length_in_byte    = mc_block_length_in_byte
        i_data                    = lv_line_after_padding
      IMPORTING
        e_padding_length_in_byte  = lv_padding_length
        e_data                    = lv_line_before_padding ).

    IF lv_line_before_padding IS INITIAL.
      DELETE ct_data INDEX lv_last_line_number.
    ELSE.
      <raw16> = lv_line_before_padding.
    ENDIF.

    e_data_length_in_byte = lv_last_line_number * mc_block_length_in_byte - lv_padding_length.

  ENDMETHOD.                    "remove_padding_raw16_table


  METHOD validate_encryption_mode.

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

  ENDMETHOD.                    "validate_encryption_mode


  METHOD validate_padding_standard.

    IF  i_padding_standard IS NOT INITIAL AND
        i_padding_standard <> zcl_byte_padding_utility=>mc_padding_standard_none AND
        i_padding_standard <> zcl_byte_padding_utility=>mc_padding_standard_pkcs_5 AND
        i_padding_standard <> zcl_byte_padding_utility=>mc_padding_standard_pkcs_7.

      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_PADDING_STANDARD'
          value = 'Unsupported padding standard'.

    ENDIF.

  ENDMETHOD.                    "validate_padding_standard


  METHOD validate_raw16_table_size.
    DATA: lv_line_of_raw16_table  TYPE int4.

    lv_line_of_raw16_table = lines( it_data ).

    IF  i_data_length_in_byte > lv_line_of_raw16_table * mc_block_length_in_byte OR
        i_data_length_in_byte <= ( lv_line_of_raw16_table - 1 ) * mc_block_length_in_byte.

      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_DATA_LENGTH_IN_BYTE'
          value = 'Data length and table size do not match.'.

    ENDIF.

  ENDMETHOD.                    "validate_raw16_table_size
ENDCLASS.
