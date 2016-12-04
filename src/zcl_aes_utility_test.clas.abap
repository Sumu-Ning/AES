*----------------------------------------------------------------------*
*       CLASS zcl_aes_utility_test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
*"* public components of class ZCL_AES_UTILITY_TEST
*"* do not include other source files here!!!
class ZCL_AES_UTILITY_TEST definition
  public
  abstract
  final
  create public
  for testing
  duration short
  risk level harmless .

public section.
  PROTECTED SECTION.
*"* protected components of class ZCL_AES_UTILITY_TEST
*"* do not include other source files here!!!
  PRIVATE SECTION.

*"* private components of class ZCL_AES_UTILITY_TEST
*"* do not include other source files here!!!
    DATA key TYPE xstring .
    DATA iv TYPE xstring .
    DATA mode TYPE char10 .
    DATA plaintext TYPE xstring .
    DATA ciphertext TYPE xstring .
    DATA test TYPE xstring .
    DATA padding TYPE char10 .

    METHODS test_ecb_128_encrypt
    FOR TESTING .
    METHODS test_ecb_128_decrypt
    FOR TESTING .
    METHODS test_ecb_192_encrypt
    FOR TESTING .
    METHODS test_ecb_192_decrypt
    FOR TESTING .
    METHODS test_ecb_256_encrypt
    FOR TESTING .
    METHODS test_ecb_256_decrypt
    FOR TESTING .
    METHODS test_cbc_128_encrypt
    FOR TESTING .
    METHODS test_cbc_128_decrypt
    FOR TESTING .
    METHODS test_cbc_192_encrypt
    FOR TESTING .
    METHODS test_cbc_192_decrypt
    FOR TESTING .
    METHODS test_cbc_256_encrypt
    FOR TESTING .
    METHODS test_cbc_256_decrypt
    FOR TESTING .
    METHODS test_cfb_128_encrypt
    FOR TESTING .
    METHODS test_cfb_128_decrypt
    FOR TESTING .
    METHODS test_cfb_192_encrypt
    FOR TESTING .
    METHODS test_cfb_192_decrypt
    FOR TESTING .
    METHODS test_cfb_256_encrypt
    FOR TESTING .
    METHODS test_cfb_256_decrypt
    FOR TESTING .
    METHODS test_ofb_128_encrypt
    FOR TESTING .
    METHODS test_ofb_128_decrypt
    FOR TESTING .
    METHODS test_ofb_192_encrypt
    FOR TESTING .
    METHODS test_ofb_192_decrypt
    FOR TESTING .
    METHODS test_ofb_256_encrypt
    FOR TESTING .
    METHODS test_ofb_256_decrypt
    FOR TESTING .
    METHODS test_ctr_128_encrypt
    FOR TESTING .
    METHODS test_ctr_128_decrypt
    FOR TESTING .
    METHODS test_ctr_192_encrypt
    FOR TESTING .
    METHODS test_ctr_192_decrypt
    FOR TESTING .
    METHODS test_ctr_256_encrypt
    FOR TESTING .
    METHODS test_ctr_256_decrypt
    FOR TESTING .
    METHODS test_cbc_128_pkcs7_encrypt
    FOR TESTING .
    METHODS test_cbc_128_pkcs7_decrypt
    FOR TESTING .
    METHODS test_ecb_128_pkcs7_encrypt
    FOR TESTING .
    METHODS test_ecb_128_pkcs7_decrypt
    FOR TESTING .
    METHODS test_ctr_128_pkcs7_encrypt
    FOR TESTING .
    METHODS test_ctr_128_pkcs7_decrypt
    FOR TESTING .
    METHODS test_cbc_128_none_encrypt
    FOR TESTING .
    METHODS test_cbc_128_none_decrypt
    FOR TESTING .
    METHODS test_ecb_128_none_encrypt
    FOR TESTING .
    METHODS test_ecb_128_none_decrypt
    FOR TESTING .
    METHODS test_ctr_128_none_encrypt
    FOR TESTING .
    METHODS test_ctr_128_none_decrypt
    FOR TESTING .
ENDCLASS.



CLASS ZCL_AES_UTILITY_TEST IMPLEMENTATION.


  METHOD test_cbc_128_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B273BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CBC_128_DECRYPT


  METHOD test_cbc_128_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B273BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_cbc_128_encrypt


  METHOD test_cbc_128_none_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC10000000000000000000000000000'.
    ciphertext  = 'B32191BE73A0734F9860F492DB27BD70'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D0000000000000000000000000000'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197DE8E3BF84D5F1949C956D94ED33C36F85'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_cbc_128_none_decrypt


  METHOD test_cbc_128_none_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = 'B32191BE73A0734F9860F492DB27BD70'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197DE8E3BF84D5F1949C956D94ED33C36F85'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_cbc_128_none_encrypt


  METHOD test_cbc_128_pkcs7_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = 'C84AF0B613435D5D9182801A9BD9320B'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1'.
    ciphertext  = 'A727B3BFAEC6ED7521595FB326CDF5CA'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197D813A1616DA05E0FEC242A20F1C5B77AA'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_cbc_128_pkcs7_decrypt


  METHOD test_cbc_128_pkcs7_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = 'C84AF0B613435D5D9182801A9BD9320B'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = 'A727B3BFAEC6ED7521595FB326CDF5CA'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '7649ABAC8119B246CEE98E9B12E9197D813A1616DA05E0FEC242A20F1C5B77AA'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_cbc_128_pkcs7_encrypt


  METHOD test_cbc_192_decrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '4F021DB243BC633D7178183A9FA071E8B4D9ADA9AD7DEDF4E5E738763F69145A571B242012FB7AE07FA9BAAC3DF102E008B0E27988598881D920A9E64F5615CD'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CBC_192_DECRYPT


  METHOD test_cbc_192_encrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '4F021DB243BC633D7178183A9FA071E8B4D9ADA9AD7DEDF4E5E738763F69145A571B242012FB7AE07FA9BAAC3DF102E008B0E27988598881D920A9E64F5615CD'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CBC_192_ENCRYPT


  METHOD test_cbc_256_decrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CBC_256_DECRYPT


  METHOD test_cbc_256_encrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cbc.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CBC_256_ENCRYPT


  METHOD test_cfb_128_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CFB_128_DECRYPT


  METHOD test_cfb_128_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CFB_128_ENCRYPT


  METHOD test_cfb_192_decrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'CDC80D6FDDF18CAB34C25909C99A417467CE7F7F81173621961A2B70171D3D7A2E1E8A1DD59B88B1C8E60FED1EFAC4C9C05F9F9CA9834FA042AE8FBA584B09FF'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CFB_192_DECRYPT


  METHOD test_cfb_192_encrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'CDC80D6FDDF18CAB34C25909C99A417467CE7F7F81173621961A2B70171D3D7A2E1E8A1DD59B88B1C8E60FED1EFAC4C9C05F9F9CA9834FA042AE8FBA584B09FF'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CFB_192_ENCRYPT


  METHOD test_cfb_256_decrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CFB_256_DECRYPT


  METHOD test_cfb_256_encrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471'.
    mode        = zcl_aes_utility=>mc_encryption_mode_cfb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CFB_256_ENCRYPT


  METHOD test_ctr_128_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CTR_128_DECRYPT


  METHOD test_ctr_128_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CTR_128_ENCRYPT


  METHOD test_ctr_128_none_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC10000000000000000000000000000'.
    ciphertext  = '3B3F67CC996D32B6DA0937E99BAFEC60'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D0000000000000000000000000000'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A010C8E4E87E393AADA314BE47BF7A35F'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_ctr_128_none_decrypt


  METHOD test_ctr_128_none_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = '3B3F67CC996D32B6DA0937E99BAFEC60'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A010C8E4E87E393AADA314BE47BF7A35F'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ctr_128_none_encrypt


  METHOD test_ctr_128_pkcs7_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = '40EE77DC897D22A6CA1927F98BBFFC70'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1'.
    ciphertext  = '3B3F69C297633CB8D40739E795A1E26E'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A010C804089ED9DA4D43F45EA75F9AD51'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_ctr_128_pkcs7_decrypt


  METHOD test_ctr_128_pkcs7_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = '40EE77DC897D22A6CA1927F98BBFFC70'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = '3B3F69C297633CB8D40739E795A1E26E'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A010C804089ED9DA4D43F45EA75F9AD51'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ctr_128_pkcs7_encrypt


  METHOD test_ctr_192_decrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '1ABC932417521CA24F2B0459FE7E6E0B090339EC0AA6FAEFD5CCC2C6F4CE8E941E36B26BD1EBC670D1BD1D665620ABF74F78A7F6D29809585A97DAEC58C6B050'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CTR_192_DECRYPT


  METHOD test_ctr_192_encrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '1ABC932417521CA24F2B0459FE7E6E0B090339EC0AA6FAEFD5CCC2C6F4CE8E941E36B26BD1EBC670D1BD1D665620ABF74F78A7F6D29809585A97DAEC58C6B050'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CTR_192_ENCRYPT


  METHOD test_ctr_256_decrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_CTR_256_DECRYPT


  METHOD test_ctr_256_encrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ctr.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_CTR_256_ENCRYPT


  METHOD test_ecb_128_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_ECB_128_DECRYPT


  METHOD test_ecb_128_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ecb_128_encryption


  METHOD test_ecb_128_none_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC10000000000000000000000000000'.
    ciphertext  = 'A40AB377966BAE2F190D0183A0565DD8'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D0000000000000000000000000000'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF975EA06D0C199A4F545F30C4F7DB97AD93'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_ecb_128_none_decrypt


  METHOD test_ecb_128_none_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.
    padding     = zcl_aes_utility=>mc_padding_standard_none.

    plaintext   = ''.
    ciphertext  = ''.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = 'A40AB377966BAE2F190D0183A0565DD8'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF975EA06D0C199A4F545F30C4F7DB97AD93'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ecb_128_none_encrypt


  METHOD test_ecb_128_pkcs7_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = 'A254BE88E037DDD9D79FB6411C3F9DF8'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1'.
    ciphertext  = '3DD9B756926018FAF1FE43AB6545256C'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF97B23DD7754AAA5B9FFE7D3CC5E7BBD386'.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "test_ecb_128_pkcs7_decrypt


  METHOD test_ecb_128_pkcs7_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.
    padding     = zcl_aes_utility=>mc_padding_standard_pkcs_7.

    plaintext   = ''.
    ciphertext  = 'A254BE88E037DDD9D79FB6411C3F9DF8'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1'.
    ciphertext  = '3DD9B756926018FAF1FE43AB6545256C'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D'.
    ciphertext  = '3AD77BB40D7A3660A89ECAF32466EF97B23DD7754AAA5B9FFE7D3CC5E7BBD386'.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
        i_padding_standard      = padding
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ecb_128_pkcs7_encrypt


  METHOD test_ecb_192_decrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'BD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFEF7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_ECB_192_DECRYPT


  METHOD test_ecb_192_encrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'BD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFEF7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ecb_192_encrypt


  METHOD test_ecb_256_decrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_ECB_256_DECRYPT


  METHOD test_ecb_256_encrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ecb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
*        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "test_ecb_256_encrypt


  METHOD test_ofb_128_decrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A7789508D16918F03F53C52DAC54ED8259740051E9C5FECF64344F7A82260EDCC304C6528F659C77866A510D9C1D6AE5E'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_OFB_128_DECRYPT


  METHOD test_ofb_128_encrypt.
    key         = '2B7E151628AED2A6ABF7158809CF4F3C'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = '3B3FD92EB72DAD20333449F8E83CFB4A7789508D16918F03F53C52DAC54ED8259740051E9C5FECF64344F7A82260EDCC304C6528F659C77866A510D9C1D6AE5E'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_OFB_128_ENCRYPT


  METHOD test_ofb_192_decrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'CDC80D6FDDF18CAB34C25909C99A4174FCC28B8D4C63837C09E81700C11004018D9A9AEAC0F6596F559C6D4DAF59A5F26D9F200857CA6C3E9CAC524BD9ACC92A'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_OFB_192_DECRYPT


  METHOD test_ofb_192_encrypt.
    key         = '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'CDC80D6FDDF18CAB34C25909C99A4174FCC28B8D4C63837C09E81700C11004018D9A9AEAC0F6596F559C6D4DAF59A5F26D9F200857CA6C3E9CAC524BD9ACC92A'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_OFB_192_ENCRYPT


  METHOD test_ofb_256_decrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'DC7E84BFDA79164B7ECD8486985D38604FEBDC6740D20B3AC88F6AD82A4FB08D71AB47A086E86EEDF39D1C5BBA97C4080126141D67F37BE8538F5A8BE740E484'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>decrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = ciphertext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = plaintext ).

  ENDMETHOD.                    "TEST_OFB_256_DECRYPT


  METHOD test_ofb_256_encrypt.
    key         = '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'.
    iv          = '000102030405060708090A0B0C0D0E0F'.
    plaintext   = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'.
    ciphertext  = 'DC7E84BFDA79164B7ECD8486985D38604FEBDC6740D20B3AC88F6AD82A4FB08D71AB47A086E86EEDF39D1C5BBA97C4080126141D67F37BE8538F5A8BE740E484'.
    mode        = zcl_aes_utility=>mc_encryption_mode_ofb.

    zcl_aes_utility=>encrypt_xstring(
      EXPORTING
        i_key                   = key
        i_data                  = plaintext
        i_initialization_vector = iv
        i_encryption_mode       = mode
      IMPORTING
        e_data                  = test ).

    cl_abap_unit_assert=>assert_equals( act = test exp = ciphertext ).

  ENDMETHOD.                    "TEST_OFB_256_ENCRYPT
ENDCLASS.