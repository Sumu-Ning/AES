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
ENDCLASS.                    "ZCL_AES_MODE_CTR DEFINITION



*----------------------------------------------------------------------*
*       CLASS ZCL_AES_MODE_CTR IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_aes_mode_ctr IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Protected Method ZCL_AES_MODE_CTR->GET_COUNTER_INCREMENT
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
* | Instance Public Method ZCL_AES_MODE_CTR->ZIF_AES_MODE~DECRYPT_RAW16_TABLE
* +-------------------------------------------------------------------------------------------------+
* | [--->] IO_RIJNDAEL                    TYPE REF TO ZCL_RIJNDAEL_UTILITY
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_INITIALIZATION_VECTOR        TYPE        XSTRING
* | [--->] IT_DATA                        LIKE        MT_RAW16
* | [<---] ET_DATA                        LIKE        MT_RAW16
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD zif_aes_mode~decrypt_raw16_table.
    DATA: converter_block         TYPE xstring,
          origin_plain_block      TYPE xstring,
          working_plain_block     TYPE xstring,
          working_cipher_block    TYPE xstring,
          converted_plain_block   TYPE xstring.

    FIELD-SYMBOLS:  <raw16>       TYPE raw16.

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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_AES_MODE_CTR->ZIF_AES_MODE~ENCRYPT_RAW16_TABLE
* +-------------------------------------------------------------------------------------------------+
* | [--->] IO_RIJNDAEL                    TYPE REF TO ZCL_RIJNDAEL_UTILITY
* | [--->] I_KEY                          TYPE        XSTRING
* | [--->] I_INITIALIZATION_VECTOR        TYPE        XSTRING
* | [--->] IT_DATA                        LIKE        MT_RAW16
* | [<---] ET_DATA                        LIKE        MT_RAW16
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD zif_aes_mode~encrypt_raw16_table.
    DATA: converter_block         TYPE xstring,
          origin_plain_block      TYPE xstring,
          working_plain_block     TYPE xstring,
          working_cipher_block    TYPE xstring,
          converted_plain_block   TYPE xstring.

    FIELD-SYMBOLS:  <raw16>       TYPE raw16.

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
ENDCLASS.                    "ZCL_AES_MODE_CTR IMPLEMENTATION