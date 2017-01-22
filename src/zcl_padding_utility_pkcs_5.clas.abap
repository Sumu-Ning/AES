*----------------------------------------------------------------------*
*       CLASS ZCL_PADDING_UTILITY_PKCS_5 DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_padding_utility_pkcs_5 DEFINITION
  PUBLIC
  INHERITING FROM zcl_padding_utility_pkcs_7
  CREATE PUBLIC .

  PUBLIC SECTION.

    CONSTANTS mc_block_size_in_byte TYPE int4 VALUE 8.      "#EC NOTEXT

    METHODS add_padding
      REDEFINITION .
    METHODS remove_padding
      REDEFINITION .
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS ZCL_PADDING_UTILITY_PKCS_5 IMPLEMENTATION.


  METHOD add_padding.

    super->add_padding(
      EXPORTING
        i_data                    = i_data
        i_block_length_in_byte    = mc_block_size_in_byte
      IMPORTING
        e_padding_length_in_byte  = e_padding_length_in_byte
        e_padding                 = e_padding
        e_data                    = e_data ).

  ENDMETHOD.                    "add_padding


  METHOD remove_padding.

    super->remove_padding(
      EXPORTING
        i_data                    = i_data
        i_block_length_in_byte    = mc_block_size_in_byte
      IMPORTING
        e_padding_length_in_byte  = e_padding_length_in_byte
        e_padding                 = e_padding
        e_data                    = e_data ).

  ENDMETHOD.                    "remove_padding
ENDCLASS.
