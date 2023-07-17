
CLASS ltcl_test DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS FINAL.

  PRIVATE SECTION.
    DATA mo_cut TYPE REF TO zcl_rijndael_utility.

    METHODS decrypt FOR TESTING RAISING cx_static_check.
    METHODS encrypt FOR TESTING RAISING cx_static_check.
ENDCLASS.


CLASS ltcl_test IMPLEMENTATION.

  METHOD decrypt.

    DATA lv_plain TYPE xstring.

    CREATE OBJECT mo_cut
      EXPORTING
        i_key_length_in_bit   = zcl_rijndael_utility=>mc_length_in_bit_128
        i_block_length_in_bit = zcl_rijndael_utility=>mc_length_in_bit_128.

    mo_cut->decrypt_xstring(
      EXPORTING
        i_data = '7649ABAC8119B246CEE98E9B12E9197D'
        i_key  = '2B7E151628AED2A6ABF7158809CF4F3C'
      IMPORTING
        e_data = lv_plain ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_plain
      exp = '6BC0BCE12A459991E134741A7F9E1925' ).

  ENDMETHOD.

  METHOD encrypt.

    DATA lv_cipher TYPE xstring.

    CREATE OBJECT mo_cut
      EXPORTING
        i_key_length_in_bit   = zcl_rijndael_utility=>mc_length_in_bit_128
        i_block_length_in_bit = zcl_rijndael_utility=>mc_length_in_bit_128.

    mo_cut->encrypt_xstring(
      EXPORTING
        i_data = '6BC0BCE12A459991E134741A7F9E1925'
        i_key  = '2B7E151628AED2A6ABF7158809CF4F3C'
      IMPORTING
        e_data = lv_cipher ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_cipher
      exp = '7649ABAC8119B246CEE98E9B12E9197D' ).

  ENDMETHOD.

ENDCLASS.
