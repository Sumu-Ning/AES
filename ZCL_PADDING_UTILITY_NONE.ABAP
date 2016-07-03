*----------------------------------------------------------------------*
*       CLASS ZCL_PADDING_UTILITY_NONE DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_padding_utility_none DEFINITION
  PUBLIC
  INHERITING FROM zcl_byte_padding_utility
  CREATE PUBLIC .

  PUBLIC SECTION.

    METHODS add_padding
      REDEFINITION .
    METHODS remove_padding
      REDEFINITION .
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.                    "ZCL_PADDING_UTILITY_NONE DEFINITION



*----------------------------------------------------------------------*
*       CLASS ZCL_PADDING_UTILITY_NONE IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_padding_utility_none IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_PADDING_UTILITY_NONE->ADD_PADDING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4(optional)
* | [<---] E_PADDING_LENGTH_IN_BYTE       TYPE        INT4
* | [<---] E_PADDING                      TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD add_padding.

    e_padding_length_in_byte = 0.
    e_padding = ''.
    IF e_data IS SUPPLIED.
      e_data = i_data.
    ENDIF.

  ENDMETHOD.                    "add_padding


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_PADDING_UTILITY_NONE->REMOVE_PADDING
* +-------------------------------------------------------------------------------------------------+
* | [--->] I_DATA                         TYPE        XSTRING
* | [--->] I_BLOCK_LENGTH_IN_BYTE         TYPE        INT4(optional)
* | [<---] E_PADDING_LENGTH_IN_BYTE       TYPE        INT4
* | [<---] E_PADDING                      TYPE        XSTRING
* | [<---] E_DATA                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD remove_padding.

    e_padding_length_in_byte = 0.
    e_padding = ''.
    IF e_data IS SUPPLIED.
      e_data = i_data.
    ENDIF.

  ENDMETHOD.                    "remove_padding
ENDCLASS.                    "ZCL_PADDING_UTILITY_NONE IMPLEMENTATION