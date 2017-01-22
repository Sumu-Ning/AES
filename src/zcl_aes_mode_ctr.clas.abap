*----------------------------------------------------------------------*
*       CLASS ZCL_AES_MODE_CTR DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_aes_mode_ctr DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.

    INTERFACES zif_aes_mode .
  PROTECTED SECTION.

    METHODS get_counter_increment
      IMPORTING
        !i_data TYPE xstring
      RETURNING
        value(r_data) TYPE xstring .
  PRIVATE SECTION.
ENDCLASS.



CLASS ZCL_AES_MODE_CTR IMPLEMENTATION.


  METHOD get_counter_increment.

    CONSTANTS: zero TYPE x LENGTH 1 VALUE '00',
               one  TYPE x LENGTH 1 VALUE '01'.

    DATA: offset TYPE int4,
          length TYPE int4,
          cursor TYPE x LENGTH 1.

    length = xstrlen( i_data ).
    offset = length - 1.
    WHILE offset >= 0.
      cursor = i_data+offset(1).
      cursor = cursor + one.
      r_data = cursor && r_data.

      IF cursor <> zero.
        EXIT.
      ENDIF.

      offset = offset - 1.
    ENDWHILE.

    IF offset >= 0.
      r_data = i_data+0(offset) && r_data.
    ENDIF.

  ENDMETHOD.                    "get_counter_increment


  METHOD zif_aes_mode~decrypt_raw16_table.
    DATA: converter_block       TYPE xstring,
          origin_plain_block    TYPE xstring,
          working_plain_block   TYPE xstring,
          working_cipher_block  TYPE xstring,
          converted_plain_block TYPE xstring.

    FIELD-SYMBOLS:  <raw16>       TYPE zif_aes_mode=>ty_raw16.


    CLEAR et_data.

    working_plain_block = i_initialization_vector.

    LOOP AT it_data INTO origin_plain_block.
      io_rijndael->encrypt_xstring(
        EXPORTING
          i_data  = working_plain_block
          i_key   = i_key
        IMPORTING
          e_data  = working_cipher_block ).

      converter_block = working_cipher_block.

      converted_plain_block = origin_plain_block BIT-XOR converter_block.

      APPEND INITIAL LINE TO et_data ASSIGNING <raw16>.
      <raw16> = converted_plain_block.

      working_plain_block = get_counter_increment( working_plain_block ).
    ENDLOOP.

  ENDMETHOD.                    "zif_aes_mode~decrypt_raw16_table


  METHOD zif_aes_mode~encrypt_raw16_table.
    DATA: converter_block       TYPE xstring,
          origin_plain_block    TYPE xstring,
          working_plain_block   TYPE xstring,
          working_cipher_block  TYPE xstring,
          converted_plain_block TYPE xstring.

    FIELD-SYMBOLS:  <raw16>       TYPE zif_aes_mode=>ty_raw16.


    CLEAR et_data.

    working_plain_block = i_initialization_vector.

    LOOP AT it_data INTO origin_plain_block.
      io_rijndael->encrypt_xstring(
        EXPORTING
          i_data  = working_plain_block
          i_key   = i_key
        IMPORTING
          e_data  = working_cipher_block ).

      converter_block = working_cipher_block.

      converted_plain_block = origin_plain_block BIT-XOR converter_block.

      APPEND INITIAL LINE TO et_data ASSIGNING <raw16>.
      <raw16> = converted_plain_block.

      working_plain_block = get_counter_increment( working_plain_block ).
    ENDLOOP.

  ENDMETHOD.                    "zif_aes_mode~encrypt_raw16_table
ENDCLASS.
