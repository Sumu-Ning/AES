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
ENDCLASS.



CLASS ZCL_PADDING_UTILITY_NONE IMPLEMENTATION.


  METHOD add_padding.

    e_padding_length_in_byte = 0.
    e_padding = ''.
    IF e_data IS SUPPLIED.
      e_data = i_data.
    ENDIF.

  ENDMETHOD.                    "add_padding


  METHOD remove_padding.

    e_padding_length_in_byte = 0.
    e_padding = ''.
    IF e_data IS SUPPLIED.
      e_data = i_data.
    ENDIF.

  ENDMETHOD.                    "remove_padding
ENDCLASS.
