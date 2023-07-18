
CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_cut TYPE REF TO zcl_padding_utility_pkcs_7.
    METHODS add_padding FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD add_padding.

    DATA lv_length  TYPE i.
    DATA lv_padding TYPE xstring.
    DATA lv_data    TYPE xstring.

    CREATE OBJECT mo_cut.

    mo_cut->add_padding(
      EXPORTING
        i_data                   = '6BC1'
        i_block_length_in_byte   = 16
      IMPORTING
        e_padding_length_in_byte = lv_length
        e_padding                = lv_padding
        e_data                   = lv_data ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_length
      exp = 14 ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_padding
      exp = '0E0E0E0E0E0E0E0E0E0E0E0E0E0E' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_data
      exp = '6BC10E0E0E0E0E0E0E0E0E0E0E0E0E0E' ).

  ENDMETHOD.

ENDCLASS.
