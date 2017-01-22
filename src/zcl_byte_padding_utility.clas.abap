*----------------------------------------------------------------------*
*       CLASS ZCL_BYTE_PADDING_UTILITY DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS zcl_byte_padding_utility DEFINITION
  PUBLIC
  ABSTRACT
  CREATE PUBLIC .

  PUBLIC SECTION.

    CONSTANTS mc_padding_standard_pkcs_5 TYPE char10 VALUE 'PKCS5'. "#EC NOTEXT
    CONSTANTS mc_padding_standard_pkcs_7 TYPE char10 VALUE 'PKCS7'. "#EC NOTEXT
    CONSTANTS mc_padding_standard_none TYPE char10 VALUE 'NONE'. "#EC NOTEXT

    METHODS add_padding
      IMPORTING
        !i_data TYPE xstring
        !i_block_length_in_byte TYPE int4 OPTIONAL
      EXPORTING
        !e_padding_length_in_byte TYPE int4
        !e_padding TYPE xstring
        !e_data TYPE xstring .
    METHODS remove_padding
      IMPORTING
        !i_data TYPE xstring
        !i_block_length_in_byte TYPE int4 OPTIONAL
      EXPORTING
        !e_padding_length_in_byte TYPE int4
        !e_padding TYPE xstring
        !e_data TYPE xstring .
    CLASS-METHODS get_byte_padding_utility
      IMPORTING
        !i_padding_standard TYPE char10 DEFAULT mc_padding_standard_none
      RETURNING
        value(r_byte_padding_utility) TYPE REF TO zcl_byte_padding_utility .
    CLASS-METHODS validate_padding_standard
      IMPORTING
        !i_padding_standard TYPE char10 OPTIONAL .
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.



CLASS ZCL_BYTE_PADDING_UTILITY IMPLEMENTATION.


  METHOD add_padding.
    ASSERT 0 = 1. " method to be implemented in subclasses
  ENDMETHOD.                    "ADD_PADDING


  METHOD get_byte_padding_utility.
    validate_padding_standard( i_padding_standard ).

    CASE i_padding_standard.
      WHEN mc_padding_standard_pkcs_5.
        CREATE OBJECT
          r_byte_padding_utility TYPE zcl_padding_utility_pkcs_5.
      WHEN mc_padding_standard_pkcs_7.
        CREATE OBJECT
          r_byte_padding_utility TYPE zcl_padding_utility_pkcs_7.
      WHEN space OR mc_padding_standard_none.
        CREATE OBJECT
          r_byte_padding_utility TYPE zcl_padding_utility_none.
    ENDCASE.

  ENDMETHOD.                    "GET_PADDING_UTILITY


  METHOD remove_padding.
    ASSERT 0 = 1. " method to be implemented in subclasses
  ENDMETHOD.                    "REMOVE_PADDING


  METHOD validate_padding_standard.
    IF  i_padding_standard IS NOT INITIAL AND
        i_padding_standard <> mc_padding_standard_none AND
        i_padding_standard <> mc_padding_standard_pkcs_5 AND
        i_padding_standard <> mc_padding_standard_pkcs_7.

      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_PADDING_STANDARD'
          value = 'Unsupported padding standard'.

    ENDIF.

  ENDMETHOD.                    "validate_padding_standard
ENDCLASS.
