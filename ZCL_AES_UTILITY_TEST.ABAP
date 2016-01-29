CLASS zcl_aes_utility_test DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC
  FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS .

  PUBLIC SECTION.
*"* public components of class ZCL_AES_UTILITY_TEST
*"* do not include other source files here!!!
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

    METHODS test_ecb_128_encrypt FOR TESTING.
    METHODS test_ecb_128_decrypt FOR TESTING.
    METHODS test_ecb_192_encrypt FOR TESTING.
    METHODS test_ecb_192_decrypt FOR TESTING.
    METHODS test_ecb_256_encrypt FOR TESTING.
    METHODS test_ecb_256_decrypt FOR TESTING.
    METHODS test_cbc_128_encrypt FOR TESTING.
    METHODS test_cbc_128_decrypt FOR TESTING.
    METHODS test_cbc_192_encrypt FOR TESTING.
    METHODS test_cbc_192_decrypt FOR TESTING.
    METHODS test_cbc_256_encrypt FOR TESTING.
    METHODS test_cbc_256_decrypt FOR TESTING.
    METHODS test_cfb_128_encrypt FOR TESTING.
    METHODS test_cfb_128_decrypt FOR TESTING.
    METHODS test_cfb_192_encrypt FOR TESTING.
    METHODS test_cfb_192_decrypt FOR TESTING.
    METHODS test_cfb_256_encrypt FOR TESTING.
    METHODS test_cfb_256_decrypt FOR TESTING.
    METHODS test_ofb_128_encrypt FOR TESTING.
    METHODS test_ofb_128_decrypt FOR TESTING.
    METHODS test_ofb_192_encrypt FOR TESTING.
    METHODS test_ofb_192_decrypt FOR TESTING.
    METHODS test_ofb_256_encrypt FOR TESTING.
    METHODS test_ofb_256_decrypt FOR TESTING.
    METHODS test_ctr_128_encrypt FOR TESTING.
    METHODS test_ctr_128_decrypt FOR TESTING.
    METHODS test_ctr_192_encrypt FOR TESTING.
    METHODS test_ctr_192_decrypt FOR TESTING.
    METHODS test_ctr_256_encrypt FOR TESTING.
    METHODS test_ctr_256_decrypt FOR TESTING.
ENDCLASS.



CLASS ZCL_AES_UTILITY_TEST IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_128_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_128_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_192_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_192_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_256_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CBC_256_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_128_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_128_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_192_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_192_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_256_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CFB_256_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_128_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_128_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_192_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_192_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_256_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_CTR_256_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_128_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_128_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_192_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_192_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_256_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_ECB_256_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_128_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_128_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_192_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_192_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_256_DECRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Private Method ZCL_AES_UTILITY_TEST->TEST_OFB_256_ENCRYPT
* +-------------------------------------------------------------------------------------------------+
* +--------------------------------------------------------------------------------------</SIGNATURE>
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
