*----------------------------------------------------------------------*
*       CLASS ZCL_PADDING_UTILITY_PKCS_7 DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_padding_utility_pkcs_7 DEFINITION
  PUBLIC
  INHERITING FROM zcl_byte_padding_utility
  CREATE PUBLIC .

  PUBLIC SECTION.

    CONSTANTS mc_block_size_in_byte_min TYPE int4 VALUE 1.  "#EC NOTEXT
    CONSTANTS mc_block_size_in_byte_max TYPE int4 VALUE 255. "#EC NOTEXT

    METHODS validate_block_length
      IMPORTING
        !i_block_length_in_byte TYPE int4 OPTIONAL .

    METHODS add_padding
      REDEFINITION .
    METHODS remove_padding
      REDEFINITION .
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.                    "ZCL_PADDING_UTILITY_PKCS_7 DEFINITION



*----------------------------------------------------------------------*
*       CLASS ZCL_PADDING_UTILITY_PKCS_7 IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_padding_utility_pkcs_7 IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_PADDING_UTILITY_PKCS_7->ADD_PADDING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4(optional)
* | [<---] E_PADDING_LENGTH_IN_BYTE       TYPE        INT4
* | [<---] E_PADDING                      TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD add_padding.

    DATA: lv_data_length        TYPE int4,
          lv_padding_x          TYPE x.

    validate_block_length( i_block_length_in_byte = i_block_length_in_byte ).

    lv_data_length = xstrlen( i_data ).
    e_padding_length_in_byte = i_block_length_in_byte - lv_data_length MOD i_block_length_in_byte.

    lv_padding_x = e_padding_length_in_byte.
    CLEAR e_padding.
    DO e_padding_length_in_byte TIMES.
      e_padding = e_padding && lv_padding_x.
    ENDDO.

    IF e_data IS SUPPLIED.
      e_data = i_data && e_padding.
    ENDIF.

  ENDMETHOD.                    "add_padding


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_PADDING_UTILITY_PKCS_7->REMOVE_PADDING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4(optional)
* | [<---] E_PADDING_LENGTH_IN_BYTE       TYPE        INT4
* | [<---] E_PADDING                      TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD remove_padding.

    DATA: lv_data_length        TYPE int4,
          lv_data_length_minus1 TYPE int4,
          lv_data_length_raw    TYPE int4,
          lv_padding_x          TYPE x,
          lv_padding_length     TYPE int4,
          lv_padding            TYPE xstring,
          lv_padding_validation TYPE xstring.

    validate_block_length( i_block_length_in_byte = i_block_length_in_byte ).

    lv_data_length = xstrlen( i_data ).
    IF lv_data_length MOD i_block_length_in_byte <> 0.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_DATA'
          value = 'Length of input data is not multiple of block length.'.
    ENDIF.

    lv_data_length_minus1 = lv_data_length - 1.
    lv_padding_x = i_data+lv_data_length_minus1(1).
    lv_padding_length = lv_padding_x.

    DO lv_padding_length TIMES.
      lv_padding = lv_padding && lv_padding_x.
    ENDDO.

    lv_data_length_raw = lv_data_length - lv_padding_length.
    IF lv_data_length_raw < 0.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_DATA'
          value = 'Input data is not valid PKCS #7 padded data.'.
    ENDIF.

    lv_padding_validation = i_data+lv_data_length_raw(lv_padding_length).
    IF lv_padding <> lv_padding_validation.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_DATA'
          value = 'Input data is not valid PKCS #7 padded data.'.
    ENDIF.

    e_padding_length_in_byte = lv_padding_length.
    e_padding = lv_padding.
    IF e_data IS SUPPLIED.
      e_data = i_data+0(lv_data_length_raw).
    ENDIF.

  ENDMETHOD.                    "remove_padding


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_PADDING_UTILITY_PKCS_7->VALIDATE_BLOCK_LENGTH
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4(optional)
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD validate_block_length.

    IF  i_block_length_in_byte < mc_block_size_in_byte_min OR
        i_block_length_in_byte > mc_block_size_in_byte_max.

      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_BLOCK_LENGTH_IN_BYTE'
          value = 'PKCS #7 needs a block length between 1 byte and 255 bytes inclusive.'.

    ENDIF.

  ENDMETHOD.                    "validate_block_length
ENDCLASS.                    "ZCL_PADDING_UTILITY_PKCS_7 IMPLEMENTATION