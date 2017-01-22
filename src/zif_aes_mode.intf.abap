*----------------------------------------------------------------------*
*       INTERFACE ZIF_AES_MODE
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
INTERFACE zif_aes_mode
  PUBLIC .

  types: ty_raw16 type x length 16.

  CLASS-DATA:
    mt_raw16 TYPE TABLE OF ty_raw16 .

  METHODS decrypt_raw16_table
    IMPORTING
      !io_rijndael TYPE REF TO zcl_rijndael_utility
      !i_key TYPE xstring
      !i_initialization_vector TYPE xstring
      !it_data LIKE mt_raw16
    EXPORTING
      !et_data LIKE mt_raw16 .
  METHODS encrypt_raw16_table
    IMPORTING
      !io_rijndael TYPE REF TO zcl_rijndael_utility
      !i_key TYPE xstring
      !i_initialization_vector TYPE xstring
      !it_data LIKE mt_raw16
    EXPORTING
      !et_data LIKE mt_raw16 .
ENDINTERFACE.                    "ZIF_AES_MODE
