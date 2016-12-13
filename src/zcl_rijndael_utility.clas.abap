class ZCL_RIJNDAEL_UTILITY definition
  public
  create public .

public section.
*"* public components of class ZCL_RIJNDAEL_UTILITY
*"* do not include other source files here!!!

  constants MC_FACTOR_BIT_BYTE type INT4 value 8. "#EC NOTEXT
  constants MC_FACTOR_BIT_WORD type INT4 value 32. "#EC NOTEXT
  constants MC_FACTOR_BYTE_WORD type INT4 value 4. "#EC NOTEXT
  constants MC_LENGTH_IN_BIT_128 type INT4 value 128. "#EC NOTEXT
  constants MC_LENGTH_IN_BIT_160 type INT4 value 160. "#EC NOTEXT
  constants MC_LENGTH_IN_BIT_192 type INT4 value 192. "#EC NOTEXT
  constants MC_LENGTH_IN_BIT_224 type INT4 value 224. "#EC NOTEXT
  constants MC_LENGTH_IN_BIT_256 type INT4 value 256. "#EC NOTEXT
  constants MC_LENGTH_IN_BYTE_16 type INT4 value 16. "#EC NOTEXT
  constants MC_LENGTH_IN_BYTE_20 type INT4 value 20. "#EC NOTEXT
  constants MC_LENGTH_IN_BYTE_24 type INT4 value 24. "#EC NOTEXT
  constants MC_LENGTH_IN_BYTE_28 type INT4 value 28. "#EC NOTEXT
  constants MC_LENGTH_IN_BYTE_32 type INT4 value 32. "#EC NOTEXT
  constants MC_LENGTH_IN_WORD_4 type INT4 value 4. "#EC NOTEXT
  constants MC_LENGTH_IN_WORD_5 type INT4 value 5. "#EC NOTEXT
  constants MC_LENGTH_IN_WORD_6 type INT4 value 6. "#EC NOTEXT
  constants MC_LENGTH_IN_WORD_7 type INT4 value 7. "#EC NOTEXT
  constants MC_LENGTH_IN_WORD_8 type INT4 value 8. "#EC NOTEXT

  class-methods CLASS_CONSTRUCTOR .
  methods CONSTRUCTOR
    importing
      !I_KEY_LENGTH_IN_BIT type INT4
      !I_BLOCK_LENGTH_IN_BIT type INT4 .
  methods DECRYPT_XSTRING
    importing
      !I_KEY type XSTRING
      !I_DATA type XSTRING
    exporting
      !E_DATA type XSTRING .
  methods ENCRYPT_XSTRING
    importing
      !I_KEY type XSTRING
      !I_DATA type XSTRING
    exporting
      !E_DATA type XSTRING .
  methods IS_VALID_KEY_XSTRING
    importing
      !I_KEY type XSTRING
    returning
      value(R_VALID) type BOOLE_D .
  PROTECTED SECTION.
*"* protected components of class ZCL_RIJNDAEL_UTILITY
*"* do not include other source files here!!!

    CLASS-DATA:
      mt_multiplication_lookup_11 TYPE TABLE OF x .
    CLASS-DATA:
      mt_multiplication_lookup_13 TYPE TABLE OF x .
    CLASS-DATA:
      mt_multiplication_lookup_14 TYPE TABLE OF x .
    CLASS-DATA:
      mt_multiplication_lookup_2 TYPE TABLE OF x .
    CLASS-DATA:
      mt_multiplication_lookup_3 TYPE TABLE OF x .
    CLASS-DATA:
      mt_multiplication_lookup_9 TYPE TABLE OF x .
    CLASS-DATA:
      mt_rcon TYPE TABLE OF x .
    CLASS-DATA:
      mt_row_shift_4 TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_4_inv TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_5 TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_5_inv TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_6 TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_6_inv TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_7 TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_7_inv TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_8 TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_row_shift_8_inv TYPE TABLE OF int4 .
    CLASS-DATA:
      mt_sbox TYPE TABLE OF x .
    CLASS-DATA:
      mt_sbox_inv TYPE TABLE OF x .
    CLASS-DATA:
      mt_x TYPE TABLE OF x .
    DATA m_block_length_in_bit TYPE int4 .
    DATA m_block_length_in_byte TYPE int4 .
    DATA m_block_length_in_word TYPE int4 .
    DATA m_key_length_in_bit TYPE int4 .
    DATA m_key_length_in_byte TYPE int4 .
    DATA m_key_length_in_word TYPE int4 .
    DATA m_round TYPE int4 .
    DATA m_row_shift_c1 TYPE int4 .
    DATA m_row_shift_c2 TYPE int4 .
    DATA m_row_shift_c3 TYPE int4 .

    CLASS-METHODS _get_multiplication_11
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _get_multiplication_13
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _get_multiplication_14
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _get_multiplication_2
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _get_multiplication_3
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _get_multiplication_9
      IMPORTING
        !i_x TYPE x
      RETURNING
        value(r_x) TYPE hextyp .
    CLASS-METHODS _rcon
      IMPORTING
        !i_number TYPE int4
      EXPORTING
        !e_array LIKE mt_x .
    CLASS-METHODS _sbox
      CHANGING
        value(c_x) TYPE x .
    CLASS-METHODS _sbox_inv
      CHANGING
        !c_x TYPE x .
    METHODS array_copy
      IMPORTING
        !i_source LIKE mt_x
        !i_start_index TYPE int4
        !i_end_index TYPE int4
        !i_dest_start_index TYPE int4 DEFAULT 1
      CHANGING
        !c_destination LIKE mt_x .
    METHODS array_mix_columns
      CHANGING
        !c_array LIKE mt_x .
    METHODS array_mix_columns_inv
      CHANGING
        !c_array LIKE mt_x .
    METHODS array_sbox
      IMPORTING
        !i_start_index TYPE int4 OPTIONAL
        !i_end_index TYPE int4 OPTIONAL
      CHANGING
        !c_data LIKE mt_x .
    METHODS array_sbox_inv
      IMPORTING
        !i_start_index TYPE int4 OPTIONAL
        !i_end_index TYPE int4 OPTIONAL
      CHANGING
        !c_data LIKE mt_x .
    METHODS array_shift_rows
      CHANGING
        !c_array LIKE mt_x .
    METHODS array_shift_rows_inv
      CHANGING
        !c_array LIKE mt_x .
    METHODS array_xor
      IMPORTING
        !i_array LIKE mt_x
        !i_i_array_start_index TYPE int4
        !i_c_array_start_index TYPE int4
        !i_length_by_byte TYPE int4
      CHANGING
        !c_array LIKE mt_x .
    METHODS calculate_round_key_array
      IMPORTING
        !i_key TYPE xstring
      EXPORTING
        !e_round_key_array LIKE mt_x .
    METHODS convert_array_to_xstring
      IMPORTING
        !i_array LIKE mt_x
        !i_start_index TYPE int4 OPTIONAL
        !i_end_index TYPE int4 OPTIONAL
      EXPORTING
        !e_xstring TYPE xstring .
    METHODS convert_xstring_to_array
      IMPORTING
        !i_xstring TYPE xstring
        !i_length_in_byte TYPE int4 OPTIONAL
      EXPORTING
        !e_array LIKE mt_x .
  PRIVATE SECTION.
*"* private components of class ZCL_RIJNDAEL_UTILITY
*"* do not include other source files here!!!

    CLASS-METHODS _build_multiplication .
    CLASS-METHODS _build_rcon .
    CLASS-METHODS _build_row_shift .
    CLASS-METHODS _build_row_shift_inv .
    CLASS-METHODS _build_sbox .
    CLASS-METHODS _build_sbox_inv .
ENDCLASS.



CLASS ZCL_RIJNDAEL_UTILITY IMPLEMENTATION.


  METHOD array_copy.
    DATA: dest_cursor       TYPE int4.
    FIELD-SYMBOLS:  <fs_x>  TYPE x.

    dest_cursor = i_dest_start_index.

    LOOP AT i_source FROM i_start_index TO i_end_index ASSIGNING <fs_x>.
      INSERT <fs_x> INTO c_destination INDEX dest_cursor.
      dest_cursor = dest_cursor + 1.
    ENDLOOP.
  ENDMETHOD.                    "array_copy


  METHOD array_mix_columns.
    DATA: array_length_in_word  TYPE int4,
          cursor                TYPE int4,
          word_offset           TYPE int4,
          temp_array            TYPE TABLE OF x,
          temp_x_1              TYPE x,
          temp_x_2              TYPE x,
          temp_x_3              TYPE x,
          temp_x_4              TYPE x,
          new_x                 TYPE x.

    array_length_in_word = lines( c_array ) / mc_factor_byte_word.
    cursor = 0.
    WHILE cursor < array_length_in_word.
      word_offset = cursor * mc_factor_byte_word.
      READ TABLE c_array INDEX word_offset + 1 INTO temp_x_1.
      READ TABLE c_array INDEX word_offset + 2 INTO temp_x_2.
      READ TABLE c_array INDEX word_offset + 3 INTO temp_x_3.
      READ TABLE c_array INDEX word_offset + 4 INTO temp_x_4.

      new_x = _get_multiplication_2( temp_x_1 ) BIT-XOR _get_multiplication_3( temp_x_2 ) BIT-XOR temp_x_3 BIT-XOR temp_x_4.
      APPEND new_x TO temp_array.
      new_x = temp_x_1 BIT-XOR _get_multiplication_2( temp_x_2 ) BIT-XOR _get_multiplication_3( temp_x_3 ) BIT-XOR temp_x_4.
      APPEND new_x TO temp_array.
      new_x = temp_x_1 BIT-XOR temp_x_2 BIT-XOR _get_multiplication_2( temp_x_3 ) BIT-XOR _get_multiplication_3( temp_x_4 ).
      APPEND new_x TO temp_array.
      new_x = _get_multiplication_3( temp_x_1 ) BIT-XOR temp_x_2 BIT-XOR temp_x_3 BIT-XOR _get_multiplication_2( temp_x_4 ).
      APPEND new_x TO temp_array.

      cursor = cursor + 1.
    ENDWHILE.

    c_array[] = temp_array[].

  ENDMETHOD.                    "array_mix_columns


  METHOD array_mix_columns_inv.
    DATA: array_length_in_word  TYPE int4,
          cursor                TYPE int4,
          word_offset           TYPE int4,
          temp_array            TYPE TABLE OF x,
          temp_x_1              TYPE x,
          temp_x_2              TYPE x,
          temp_x_3              TYPE x,
          temp_x_4              TYPE x,
          new_x                 TYPE x.

    array_length_in_word = lines( c_array ) / mc_factor_byte_word.
    cursor = 0.
    WHILE cursor < array_length_in_word.
      word_offset = cursor * mc_factor_byte_word.
      READ TABLE c_array INDEX word_offset + 1 INTO temp_x_1.
      READ TABLE c_array INDEX word_offset + 2 INTO temp_x_2.
      READ TABLE c_array INDEX word_offset + 3 INTO temp_x_3.
      READ TABLE c_array INDEX word_offset + 4 INTO temp_x_4.

      new_x = _get_multiplication_14( temp_x_1 ) BIT-XOR _get_multiplication_11( temp_x_2 ) BIT-XOR _get_multiplication_13( temp_x_3 ) BIT-XOR _get_multiplication_9( temp_x_4 ).
      APPEND new_x TO temp_array.
      new_x = _get_multiplication_9( temp_x_1 ) BIT-XOR _get_multiplication_14( temp_x_2 ) BIT-XOR _get_multiplication_11( temp_x_3 ) BIT-XOR _get_multiplication_13( temp_x_4 ).
      APPEND new_x TO temp_array.
      new_x = _get_multiplication_13( temp_x_1 ) BIT-XOR _get_multiplication_9( temp_x_2 ) BIT-XOR _get_multiplication_14( temp_x_3 ) BIT-XOR _get_multiplication_11( temp_x_4 ).
      APPEND new_x TO temp_array.
      new_x = _get_multiplication_11( temp_x_1 ) BIT-XOR _get_multiplication_13( temp_x_2 ) BIT-XOR _get_multiplication_9( temp_x_3 ) BIT-XOR _get_multiplication_14( temp_x_4 ).
      APPEND new_x TO temp_array.

      cursor = cursor + 1.
    ENDWHILE.

    c_array[] = temp_array[].

  ENDMETHOD.                    "array_mix_columns_inv


  METHOD array_sbox.
    DATA: start_index       TYPE int4,
          end_index         TYPE int4,
          length_in_byte    TYPE int4.

    FIELD-SYMBOLS:  <fs_x>  TYPE x.

    start_index = i_start_index.
    end_index = i_end_index.

    length_in_byte = lines( c_data ).

    IF start_index IS INITIAL OR start_index < 0.
      start_index = 1.
    ENDIF.

    IF end_index IS INITIAL OR end_index > length_in_byte.
      end_index = length_in_byte.
    ENDIF.

    IF start_index <= end_index.
      LOOP AT c_data ASSIGNING <fs_x> FROM start_index TO end_index.
        _sbox(
          CHANGING
            c_x = <fs_x>
        ).
      ENDLOOP.
    ENDIF.
  ENDMETHOD.                    "ARRAY_SBOX


  METHOD array_sbox_inv.
    DATA: start_index       TYPE int4,
          end_index         TYPE int4,
          length_in_byte    TYPE int4.

    FIELD-SYMBOLS:  <fs_x>  TYPE x.

    start_index = i_start_index.
    end_index = i_end_index.

    length_in_byte = lines( c_data ).

    IF start_index IS INITIAL OR start_index < 0.
      start_index = 1.
    ENDIF.

    IF end_index IS INITIAL OR end_index > length_in_byte.
      end_index = length_in_byte.
    ENDIF.

    IF start_index <= end_index.
      LOOP AT c_data ASSIGNING <fs_x> FROM start_index TO end_index.
        _sbox_inv(
          CHANGING
            c_x = <fs_x>
        ).
      ENDLOOP.
    ENDIF.
  ENDMETHOD.                    "ARRAY_SOBX_INV


  METHOD array_shift_rows.
    DATA: array_length_in_byte    TYPE int4,
          number_of_blocks        TYPE int4,
          block_cursor            TYPE int4,
          block_offset            TYPE int4,
          temp_array              TYPE TABLE OF x,
          shift_row_lookup_table  TYPE TABLE OF int4,
          cursor                  TYPE int4,
          index_from              TYPE int4.

    FIELD-SYMBOLS: <fs_x>         TYPE x.

    "c_array strucutre (by table index, each element is a byte)
    "<---- Block --- >   <---- Block --- >   <---- Block --- >
    "01 05 09 13 17 21   25 29 33 37 41 45   49 ...
    "02 06 10 14 18 22   26 30 34 38 42 46   50 ...
    "03 07 11 15 19 23   27 31 35 39 43 47   51 ...
    "04 08 12 16 20 24   28 32 36 40 44 48   52 ...

    "After shift, each row inside one block moves left c0, c1, c2, c3 elements, c0 is always 0
    "Take c1 = 1, c2 = 2, c3 = 3 for example, for block width 6 (in word)
    "<---- Block --- >   <---- Block --- >   <---- Block --- >
    "01 05 09 13 17 21   25 29 33 37 41 45   49 ...
    "06 10 14 18 22 02   30 34 38 42 46 26   54 ...
    "11 15 19 23 03 07   35 39 43 47 27 31   59 ...
    "16 20 24 04 08 12   40 44 48 28 32 36   64 ...

    CASE m_block_length_in_word.
      WHEN 4.
        shift_row_lookup_table = mt_row_shift_4.
      WHEN 5.
        shift_row_lookup_table = mt_row_shift_5.
      WHEN 6.
        shift_row_lookup_table = mt_row_shift_6.
      WHEN 7.
        shift_row_lookup_table = mt_row_shift_7.
      WHEN 8.
        shift_row_lookup_table = mt_row_shift_8.
    ENDCASE.

    array_length_in_byte = lines( c_array ).
    number_of_blocks = array_length_in_byte / mc_factor_byte_word / m_block_length_in_word.

    block_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      block_offset = block_cursor * m_block_length_in_byte.

      CLEAR temp_array.
      cursor = 1.
      WHILE cursor <= m_block_length_in_byte.
        READ TABLE shift_row_lookup_table INDEX cursor INTO index_from.
        index_from = index_from + block_offset.
        READ TABLE c_array INDEX index_from ASSIGNING <fs_x>.
        APPEND <fs_x> TO temp_array.
        cursor = cursor + 1.
      ENDWHILE.

      LOOP AT c_array FROM block_offset + 1 TO block_offset + m_block_length_in_byte ASSIGNING <fs_x>.
        READ TABLE temp_array INDEX sy-tabix - block_offset INTO <fs_x>.
      ENDLOOP.

      block_cursor = block_cursor + 1.
    ENDWHILE.

  ENDMETHOD.                    "array_shift_rows


  METHOD array_shift_rows_inv.
    DATA: array_length_in_byte    TYPE int4,
          number_of_blocks        TYPE int4,
          block_cursor            TYPE int4,
          block_offset            TYPE int4,
          temp_array              TYPE TABLE OF x,
          shift_row_lookup_table  TYPE TABLE OF int4,
          cursor                  TYPE int4,
          index_from              TYPE int4.

    FIELD-SYMBOLS: <fs_x>         TYPE x.

    CASE m_block_length_in_word.
      WHEN 4.
        shift_row_lookup_table = mt_row_shift_4_inv.
      WHEN 5.
        shift_row_lookup_table = mt_row_shift_5_inv.
      WHEN 6.
        shift_row_lookup_table = mt_row_shift_6_inv.
      WHEN 7.
        shift_row_lookup_table = mt_row_shift_7_inv.
      WHEN 8.
        shift_row_lookup_table = mt_row_shift_8_inv.
    ENDCASE.

    array_length_in_byte = lines( c_array ).
    number_of_blocks = array_length_in_byte / mc_factor_byte_word / m_block_length_in_word.

    block_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      block_offset = block_cursor * m_block_length_in_byte.

      CLEAR temp_array.
      cursor = 1.
      WHILE cursor <= m_block_length_in_byte.
        READ TABLE shift_row_lookup_table INDEX cursor INTO index_from.
        index_from = index_from + block_offset.
        READ TABLE c_array INDEX index_from ASSIGNING <fs_x>.
        APPEND <fs_x> TO temp_array.
        cursor = cursor + 1.
      ENDWHILE.

      LOOP AT c_array FROM block_offset + 1 TO block_offset + m_block_length_in_byte ASSIGNING <fs_x>.
        READ TABLE temp_array INDEX sy-tabix - block_offset INTO <fs_x>.
      ENDLOOP.

      block_cursor = block_cursor + 1.
    ENDWHILE.

  ENDMETHOD.                    "array_shift_rows_inv


  METHOD array_xor.
    DATA: i_array_cursor            TYPE int4.
    FIELD-SYMBOLS:  <fs_i_array>    TYPE x,
                    <fs_c_array>    TYPE x.

    i_array_cursor = i_i_array_start_index.

    LOOP AT c_array FROM i_c_array_start_index TO i_c_array_start_index + i_length_by_byte - 1 ASSIGNING <fs_c_array>.
      READ TABLE i_array ASSIGNING <fs_i_array> INDEX i_array_cursor.
      <fs_c_array> = <fs_c_array> BIT-XOR <fs_i_array>.
      i_array_cursor = i_array_cursor + 1.
    ENDLOOP.
  ENDMETHOD.                    "array_xor


  METHOD calculate_round_key_array.
    DATA: cursor              TYPE int4,
          temp_word           TYPE TABLE OF x,
          rcon                TYPE TABLE OF x.

    FIELD-SYMBOLS:  <fs_x>    TYPE x.

    CLEAR e_round_key_array.

    convert_xstring_to_array(
      EXPORTING
        i_xstring = i_key
      IMPORTING
        e_array = e_round_key_array ).

    cursor = m_key_length_in_word.
    WHILE cursor < m_key_length_in_word * ( m_round + 1 ).
      CLEAR temp_word.
      array_copy(
        EXPORTING
          i_source            = e_round_key_array
          i_start_index       = ( cursor - 1 ) * mc_factor_byte_word + 1
          i_end_index         = ( cursor - 1 ) * mc_factor_byte_word + 4
          i_dest_start_index  = 1
        CHANGING
          c_destination       = temp_word ).

      IF cursor MOD m_key_length_in_word = 0.
        READ TABLE temp_word INDEX 1 ASSIGNING <fs_x>.
        APPEND <fs_x> TO temp_word.
        DELETE temp_word INDEX 1.

        array_sbox(
          CHANGING
            c_data  = temp_word ).

        _rcon(
          EXPORTING
            i_number  = cursor / m_key_length_in_word
          IMPORTING
            e_array   = rcon ).

        array_xor(
          EXPORTING
            i_array   = rcon
            i_i_array_start_index = 1
            i_c_array_start_index = 1
            i_length_by_byte = 4
          CHANGING
            c_array = temp_word ).
      ELSEIF m_key_length_in_word > 6 AND cursor MOD m_key_length_in_word = 4.
        array_sbox(
          CHANGING
            c_data = temp_word ).
      ENDIF.

      array_copy(
        EXPORTING
          i_source            = e_round_key_array
          i_start_index       = ( cursor - m_key_length_in_word ) * mc_factor_byte_word + 1
          i_end_index         = ( cursor - m_key_length_in_word ) * mc_factor_byte_word + 4
          i_dest_start_index  = cursor * mc_factor_byte_word + 1
        CHANGING
          c_destination       = e_round_key_array ).

      array_xor(
        EXPORTING
          i_array               = temp_word
          i_i_array_start_index = 1
          i_length_by_byte      = 4
          i_c_array_start_index = cursor * mc_factor_byte_word + 1
        CHANGING
          c_array               = e_round_key_array ).
      cursor = cursor + 1.
    ENDWHILE.

  ENDMETHOD.                    "calculate_round_key_array


  METHOD class_constructor.
    "Build lookup for Subbyte conversion
    _build_sbox( ).
    _build_sbox_inv( ).

    "Build lookup for Rcon
    _build_rcon( ).

    "Build lookup for Row shift
    _build_row_shift( ).
    _build_row_shift_inv( ).

    "Build coefficient * Byte lookupused for Column Mix
    _build_multiplication( ).
  ENDMETHOD.                    "class_constructor


  METHOD constructor.
    IF i_key_length_in_bit <> mc_length_in_bit_128
        AND i_key_length_in_bit <> mc_length_in_bit_160
        AND i_key_length_in_bit <> mc_length_in_bit_192
        AND i_key_length_in_bit <> mc_length_in_bit_224
        AND i_key_length_in_bit <> mc_length_in_bit_256.
      "Don't know what good exception class to use ...
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_KEY_LENGTH_IN_BIT'
          value = 'Incorrect key length'.
    ENDIF.

    IF i_block_length_in_bit <> mc_length_in_bit_128
        AND i_block_length_in_bit <> mc_length_in_bit_160
        AND i_block_length_in_bit <> mc_length_in_bit_192
        AND i_block_length_in_bit <> mc_length_in_bit_224
        AND i_block_length_in_bit <> mc_length_in_bit_256.
      "Don't know what good exception class to use ...
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_BLOCK_LENGTH_IN_BIT'
          value = 'Incorrect key length'.
    ENDIF.

    m_key_length_in_bit = i_key_length_in_bit.
    m_key_length_in_byte = m_key_length_in_bit / mc_factor_bit_byte.
    m_key_length_in_word = m_key_length_in_byte / mc_factor_byte_word.

    m_block_length_in_bit = i_block_length_in_bit.
    m_block_length_in_byte = m_block_length_in_bit / mc_factor_bit_byte.
    m_block_length_in_word = m_block_length_in_byte / mc_factor_byte_word.

    IF m_key_length_in_word > m_block_length_in_word.
      m_round = m_key_length_in_word + 6.
    ELSE.
      m_round = m_block_length_in_word + 6.
    ENDIF.

    "Actually not needed any more, just leave here for documentation purpose ...
    IF m_key_length_in_word <= mc_length_in_word_6.
      m_row_shift_c1 = 1.
      m_row_shift_c2 = 2.
      m_row_shift_c3 = 3.
    ELSEIF m_key_length_in_word = 7.
      m_row_shift_c1 = 1.
      m_row_shift_c2 = 2.
      m_row_shift_c3 = 4.
    ELSEIF m_key_length_in_word = 8.
      m_row_shift_c1 = 1.
      m_row_shift_c2 = 3.
      m_row_shift_c3 = 4.
    ENDIF.
  ENDMETHOD.                    "constructor


  METHOD convert_array_to_xstring.
    DATA: start_index   TYPE int4,
          end_index     TYPE int4.

    FIELD-SYMBOLS:  <fs_x>  TYPE x.

    CLEAR e_xstring.

    start_index = i_start_index.
    end_index = i_end_index.

    IF start_index IS INITIAL OR start_index <= 0.
      start_index = 1.
    ENDIF.

    IF end_index IS INITIAL.
      end_index = lines( i_array ).
    ENDIF.

    LOOP AT i_array FROM start_index TO end_index ASSIGNING <fs_x>.
      e_xstring = e_xstring && <fs_x>.
    ENDLOOP.

  ENDMETHOD.                    "convert_array_to_xstring


  METHOD convert_xstring_to_array.
    DATA: xstring_length_in_byte  TYPE int4,
          cursor                  TYPE int4.

    CLEAR e_array.

    xstring_length_in_byte = xstrlen( i_xstring ).
    cursor = 0.
    WHILE cursor < xstring_length_in_byte.
      APPEND i_xstring+cursor(1) TO e_array.
      cursor = cursor + 1.
    ENDWHILE.

    IF i_length_in_byte IS NOT INITIAL AND cursor < i_length_in_byte.
      WHILE cursor < i_length_in_byte.
        APPEND '00' TO e_array.
        cursor = cursor + 1.
      ENDWHILE.
    ENDIF.

  ENDMETHOD.                    "convert_xstring_to_xarray


  METHOD decrypt_xstring.
    DATA: data_length_in_byte TYPE int4,
          number_of_blocks    TYPE int4,
          block_cursor        TYPE int4,
          data_array          TYPE TABLE OF x,
          round_key_array     TYPE TABLE OF x,
          round_cursor        TYPE int4.

    IF is_valid_key_xstring( i_key ) = abap_false.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_KEY'
          value = 'Incorrect key length'.
    ENDIF.

    "Prepare some data
    data_length_in_byte = xstrlen( i_data ).
    number_of_blocks = ceil( '1.0' * data_length_in_byte / m_block_length_in_byte ).

    "Prepare temp data storage to work on
    convert_xstring_to_array(
      EXPORTING
        i_xstring = i_data
        i_length_in_byte = number_of_blocks * m_block_length_in_byte
      IMPORTING
        e_array = data_array ).

    "Calculate all round keys
    calculate_round_key_array(
      EXPORTING
        i_key = i_key
      IMPORTING
        e_round_key_array = round_key_array ).


    "Final round
    round_cursor = m_round.
    "Round key addition
    block_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      array_xor(
        EXPORTING
          i_array = round_key_array
          i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
          i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
          i_length_by_byte = m_block_length_in_byte
        CHANGING
          c_array = data_array
      ).
      block_cursor = block_cursor + 1.
    ENDWHILE.

    "Shift Rows:
    array_shift_rows_inv(
      CHANGING
        c_array = data_array
    ).

    "Sub Byte:
    array_sbox_inv(
      CHANGING
        c_data = data_array
    ).

    "Middle n - 1 rounds
    round_cursor = m_round - 1.
    WHILE round_cursor > 0.
      "Round key addition
      block_cursor = 0.
      WHILE block_cursor < number_of_blocks.
        array_xor(
          EXPORTING
            i_array = round_key_array
            i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
            i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
            i_length_by_byte = m_block_length_in_byte
          CHANGING
            c_array = data_array
        ).
        block_cursor = block_cursor + 1.
      ENDWHILE.

      "Mix Columns:
      array_mix_columns_inv(
        CHANGING
          c_array = data_array
      ).

      "Shift Rows:
      array_shift_rows_inv(
        CHANGING
          c_array = data_array
      ).

      "Sub Byte:
      array_sbox_inv(
        CHANGING
          c_data = data_array
      ).

      round_cursor = round_cursor - 1.
    ENDWHILE.

    "Initial round key addition
    block_cursor = 0.
    round_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      array_xor(
        EXPORTING
          i_array = round_key_array
          i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
          i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
          i_length_by_byte = m_block_length_in_byte
        CHANGING
          c_array = data_array
      ).
      block_cursor = block_cursor + 1.
    ENDWHILE.

    convert_array_to_xstring(
      EXPORTING
        i_array = data_array
      IMPORTING
        e_xstring = e_data
    ).
  ENDMETHOD.                    "ENCRYPT_XSTRING


  METHOD encrypt_xstring.
    DATA: data_length_in_byte TYPE int4,
          number_of_blocks    TYPE int4,
          block_cursor        TYPE int4,
          data_array          TYPE TABLE OF x,
          round_key_array     TYPE TABLE OF x,
          round_cursor        TYPE int4.

    IF is_valid_key_xstring( i_key ) = abap_false.
      RAISE EXCEPTION TYPE cx_me_illegal_argument
        EXPORTING
          name  = 'I_KEY'
          value = 'Incorrect key length'.
    ENDIF.

    "Prepare some data
    data_length_in_byte = xstrlen( i_data ).
    number_of_blocks = ceil( '1.0' * data_length_in_byte / m_block_length_in_byte ).

    "Prepare temp data storage to work on
    convert_xstring_to_array(
      EXPORTING
        i_xstring = i_data
        i_length_in_byte = number_of_blocks * m_block_length_in_byte
      IMPORTING
        e_array = data_array ).

    "Calculate all round keys
    calculate_round_key_array(
      EXPORTING
        i_key = i_key
      IMPORTING
        e_round_key_array = round_key_array ).

    "Initial round key addition
    block_cursor = 0.
    round_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      array_xor(
        EXPORTING
          i_array = round_key_array
          i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
          i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
          i_length_by_byte = m_block_length_in_byte
        CHANGING
          c_array = data_array
      ).
      block_cursor = block_cursor + 1.
    ENDWHILE.

    "Middle n - 1 rounds
    round_cursor = 1.
    WHILE round_cursor < m_round.
      "Sub Byte:
      array_sbox(
        CHANGING
          c_data = data_array
      ).

      "Shift Rows:
      array_shift_rows(
        CHANGING
          c_array = data_array
      ).

      "Mix Columns:
      array_mix_columns(
        CHANGING
          c_array = data_array
      ).

      "Round key addition
      block_cursor = 0.
      WHILE block_cursor < number_of_blocks.
        array_xor(
          EXPORTING
            i_array = round_key_array
            i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
            i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
            i_length_by_byte = m_block_length_in_byte
          CHANGING
            c_array = data_array
        ).
        block_cursor = block_cursor + 1.
      ENDWHILE.

      round_cursor = round_cursor + 1.
    ENDWHILE.

    "Final round
    round_cursor = m_round.
    "Sub Byte:
    array_sbox(
      CHANGING
        c_data = data_array
    ).

    "Shift Rows:
    array_shift_rows(
      CHANGING
        c_array = data_array
    ).

    "Round key addition
    block_cursor = 0.
    WHILE block_cursor < number_of_blocks.
      array_xor(
        EXPORTING
          i_array = round_key_array
          i_i_array_start_index = round_cursor * m_block_length_in_byte + 1
          i_c_array_start_index = block_cursor * m_block_length_in_byte + 1
          i_length_by_byte = m_block_length_in_byte
        CHANGING
          c_array = data_array
      ).
      block_cursor = block_cursor + 1.
    ENDWHILE.

    convert_array_to_xstring(
      EXPORTING
        i_array = data_array
      IMPORTING
        e_xstring = e_data
    ).
  ENDMETHOD.                    "ENCRYPT_XSTRING


  METHOD is_valid_key_xstring.
    IF xstrlen( i_key ) = m_key_length_in_byte.
      r_valid = abap_true.
    ELSE.
      r_valid = abap_false.
    ENDIF.
  ENDMETHOD.                    "IS_VALID_KEY


  METHOD _build_multiplication.
    "Build Multiplication Table for 2
    APPEND '00' TO mt_multiplication_lookup_2.
    APPEND '02' TO mt_multiplication_lookup_2.
    APPEND '04' TO mt_multiplication_lookup_2.
    APPEND '06' TO mt_multiplication_lookup_2.
    APPEND '08' TO mt_multiplication_lookup_2.
    APPEND '0A' TO mt_multiplication_lookup_2.
    APPEND '0C' TO mt_multiplication_lookup_2.
    APPEND '0E' TO mt_multiplication_lookup_2.
    APPEND '10' TO mt_multiplication_lookup_2.
    APPEND '12' TO mt_multiplication_lookup_2.
    APPEND '14' TO mt_multiplication_lookup_2.
    APPEND '16' TO mt_multiplication_lookup_2.
    APPEND '18' TO mt_multiplication_lookup_2.
    APPEND '1A' TO mt_multiplication_lookup_2.
    APPEND '1C' TO mt_multiplication_lookup_2.
    APPEND '1E' TO mt_multiplication_lookup_2.
    APPEND '20' TO mt_multiplication_lookup_2.
    APPEND '22' TO mt_multiplication_lookup_2.
    APPEND '24' TO mt_multiplication_lookup_2.
    APPEND '26' TO mt_multiplication_lookup_2.
    APPEND '28' TO mt_multiplication_lookup_2.
    APPEND '2A' TO mt_multiplication_lookup_2.
    APPEND '2C' TO mt_multiplication_lookup_2.
    APPEND '2E' TO mt_multiplication_lookup_2.
    APPEND '30' TO mt_multiplication_lookup_2.
    APPEND '32' TO mt_multiplication_lookup_2.
    APPEND '34' TO mt_multiplication_lookup_2.
    APPEND '36' TO mt_multiplication_lookup_2.
    APPEND '38' TO mt_multiplication_lookup_2.
    APPEND '3A' TO mt_multiplication_lookup_2.
    APPEND '3C' TO mt_multiplication_lookup_2.
    APPEND '3E' TO mt_multiplication_lookup_2.
    APPEND '40' TO mt_multiplication_lookup_2.
    APPEND '42' TO mt_multiplication_lookup_2.
    APPEND '44' TO mt_multiplication_lookup_2.
    APPEND '46' TO mt_multiplication_lookup_2.
    APPEND '48' TO mt_multiplication_lookup_2.
    APPEND '4A' TO mt_multiplication_lookup_2.
    APPEND '4C' TO mt_multiplication_lookup_2.
    APPEND '4E' TO mt_multiplication_lookup_2.
    APPEND '50' TO mt_multiplication_lookup_2.
    APPEND '52' TO mt_multiplication_lookup_2.
    APPEND '54' TO mt_multiplication_lookup_2.
    APPEND '56' TO mt_multiplication_lookup_2.
    APPEND '58' TO mt_multiplication_lookup_2.
    APPEND '5A' TO mt_multiplication_lookup_2.
    APPEND '5C' TO mt_multiplication_lookup_2.
    APPEND '5E' TO mt_multiplication_lookup_2.
    APPEND '60' TO mt_multiplication_lookup_2.
    APPEND '62' TO mt_multiplication_lookup_2.
    APPEND '64' TO mt_multiplication_lookup_2.
    APPEND '66' TO mt_multiplication_lookup_2.
    APPEND '68' TO mt_multiplication_lookup_2.
    APPEND '6A' TO mt_multiplication_lookup_2.
    APPEND '6C' TO mt_multiplication_lookup_2.
    APPEND '6E' TO mt_multiplication_lookup_2.
    APPEND '70' TO mt_multiplication_lookup_2.
    APPEND '72' TO mt_multiplication_lookup_2.
    APPEND '74' TO mt_multiplication_lookup_2.
    APPEND '76' TO mt_multiplication_lookup_2.
    APPEND '78' TO mt_multiplication_lookup_2.
    APPEND '7A' TO mt_multiplication_lookup_2.
    APPEND '7C' TO mt_multiplication_lookup_2.
    APPEND '7E' TO mt_multiplication_lookup_2.
    APPEND '80' TO mt_multiplication_lookup_2.
    APPEND '82' TO mt_multiplication_lookup_2.
    APPEND '84' TO mt_multiplication_lookup_2.
    APPEND '86' TO mt_multiplication_lookup_2.
    APPEND '88' TO mt_multiplication_lookup_2.
    APPEND '8A' TO mt_multiplication_lookup_2.
    APPEND '8C' TO mt_multiplication_lookup_2.
    APPEND '8E' TO mt_multiplication_lookup_2.
    APPEND '90' TO mt_multiplication_lookup_2.
    APPEND '92' TO mt_multiplication_lookup_2.
    APPEND '94' TO mt_multiplication_lookup_2.
    APPEND '96' TO mt_multiplication_lookup_2.
    APPEND '98' TO mt_multiplication_lookup_2.
    APPEND '9A' TO mt_multiplication_lookup_2.
    APPEND '9C' TO mt_multiplication_lookup_2.
    APPEND '9E' TO mt_multiplication_lookup_2.
    APPEND 'A0' TO mt_multiplication_lookup_2.
    APPEND 'A2' TO mt_multiplication_lookup_2.
    APPEND 'A4' TO mt_multiplication_lookup_2.
    APPEND 'A6' TO mt_multiplication_lookup_2.
    APPEND 'A8' TO mt_multiplication_lookup_2.
    APPEND 'AA' TO mt_multiplication_lookup_2.
    APPEND 'AC' TO mt_multiplication_lookup_2.
    APPEND 'AE' TO mt_multiplication_lookup_2.
    APPEND 'B0' TO mt_multiplication_lookup_2.
    APPEND 'B2' TO mt_multiplication_lookup_2.
    APPEND 'B4' TO mt_multiplication_lookup_2.
    APPEND 'B6' TO mt_multiplication_lookup_2.
    APPEND 'B8' TO mt_multiplication_lookup_2.
    APPEND 'BA' TO mt_multiplication_lookup_2.
    APPEND 'BC' TO mt_multiplication_lookup_2.
    APPEND 'BE' TO mt_multiplication_lookup_2.
    APPEND 'C0' TO mt_multiplication_lookup_2.
    APPEND 'C2' TO mt_multiplication_lookup_2.
    APPEND 'C4' TO mt_multiplication_lookup_2.
    APPEND 'C6' TO mt_multiplication_lookup_2.
    APPEND 'C8' TO mt_multiplication_lookup_2.
    APPEND 'CA' TO mt_multiplication_lookup_2.
    APPEND 'CC' TO mt_multiplication_lookup_2.
    APPEND 'CE' TO mt_multiplication_lookup_2.
    APPEND 'D0' TO mt_multiplication_lookup_2.
    APPEND 'D2' TO mt_multiplication_lookup_2.
    APPEND 'D4' TO mt_multiplication_lookup_2.
    APPEND 'D6' TO mt_multiplication_lookup_2.
    APPEND 'D8' TO mt_multiplication_lookup_2.
    APPEND 'DA' TO mt_multiplication_lookup_2.
    APPEND 'DC' TO mt_multiplication_lookup_2.
    APPEND 'DE' TO mt_multiplication_lookup_2.
    APPEND 'E0' TO mt_multiplication_lookup_2.
    APPEND 'E2' TO mt_multiplication_lookup_2.
    APPEND 'E4' TO mt_multiplication_lookup_2.
    APPEND 'E6' TO mt_multiplication_lookup_2.
    APPEND 'E8' TO mt_multiplication_lookup_2.
    APPEND 'EA' TO mt_multiplication_lookup_2.
    APPEND 'EC' TO mt_multiplication_lookup_2.
    APPEND 'EE' TO mt_multiplication_lookup_2.
    APPEND 'F0' TO mt_multiplication_lookup_2.
    APPEND 'F2' TO mt_multiplication_lookup_2.
    APPEND 'F4' TO mt_multiplication_lookup_2.
    APPEND 'F6' TO mt_multiplication_lookup_2.
    APPEND 'F8' TO mt_multiplication_lookup_2.
    APPEND 'FA' TO mt_multiplication_lookup_2.
    APPEND 'FC' TO mt_multiplication_lookup_2.
    APPEND 'FE' TO mt_multiplication_lookup_2.
    APPEND '1B' TO mt_multiplication_lookup_2.
    APPEND '19' TO mt_multiplication_lookup_2.
    APPEND '1F' TO mt_multiplication_lookup_2.
    APPEND '1D' TO mt_multiplication_lookup_2.
    APPEND '13' TO mt_multiplication_lookup_2.
    APPEND '11' TO mt_multiplication_lookup_2.
    APPEND '17' TO mt_multiplication_lookup_2.
    APPEND '15' TO mt_multiplication_lookup_2.
    APPEND '0B' TO mt_multiplication_lookup_2.
    APPEND '09' TO mt_multiplication_lookup_2.
    APPEND '0F' TO mt_multiplication_lookup_2.
    APPEND '0D' TO mt_multiplication_lookup_2.
    APPEND '03' TO mt_multiplication_lookup_2.
    APPEND '01' TO mt_multiplication_lookup_2.
    APPEND '07' TO mt_multiplication_lookup_2.
    APPEND '05' TO mt_multiplication_lookup_2.
    APPEND '3B' TO mt_multiplication_lookup_2.
    APPEND '39' TO mt_multiplication_lookup_2.
    APPEND '3F' TO mt_multiplication_lookup_2.
    APPEND '3D' TO mt_multiplication_lookup_2.
    APPEND '33' TO mt_multiplication_lookup_2.
    APPEND '31' TO mt_multiplication_lookup_2.
    APPEND '37' TO mt_multiplication_lookup_2.
    APPEND '35' TO mt_multiplication_lookup_2.
    APPEND '2B' TO mt_multiplication_lookup_2.
    APPEND '29' TO mt_multiplication_lookup_2.
    APPEND '2F' TO mt_multiplication_lookup_2.
    APPEND '2D' TO mt_multiplication_lookup_2.
    APPEND '23' TO mt_multiplication_lookup_2.
    APPEND '21' TO mt_multiplication_lookup_2.
    APPEND '27' TO mt_multiplication_lookup_2.
    APPEND '25' TO mt_multiplication_lookup_2.
    APPEND '5B' TO mt_multiplication_lookup_2.
    APPEND '59' TO mt_multiplication_lookup_2.
    APPEND '5F' TO mt_multiplication_lookup_2.
    APPEND '5D' TO mt_multiplication_lookup_2.
    APPEND '53' TO mt_multiplication_lookup_2.
    APPEND '51' TO mt_multiplication_lookup_2.
    APPEND '57' TO mt_multiplication_lookup_2.
    APPEND '55' TO mt_multiplication_lookup_2.
    APPEND '4B' TO mt_multiplication_lookup_2.
    APPEND '49' TO mt_multiplication_lookup_2.
    APPEND '4F' TO mt_multiplication_lookup_2.
    APPEND '4D' TO mt_multiplication_lookup_2.
    APPEND '43' TO mt_multiplication_lookup_2.
    APPEND '41' TO mt_multiplication_lookup_2.
    APPEND '47' TO mt_multiplication_lookup_2.
    APPEND '45' TO mt_multiplication_lookup_2.
    APPEND '7B' TO mt_multiplication_lookup_2.
    APPEND '79' TO mt_multiplication_lookup_2.
    APPEND '7F' TO mt_multiplication_lookup_2.
    APPEND '7D' TO mt_multiplication_lookup_2.
    APPEND '73' TO mt_multiplication_lookup_2.
    APPEND '71' TO mt_multiplication_lookup_2.
    APPEND '77' TO mt_multiplication_lookup_2.
    APPEND '75' TO mt_multiplication_lookup_2.
    APPEND '6B' TO mt_multiplication_lookup_2.
    APPEND '69' TO mt_multiplication_lookup_2.
    APPEND '6F' TO mt_multiplication_lookup_2.
    APPEND '6D' TO mt_multiplication_lookup_2.
    APPEND '63' TO mt_multiplication_lookup_2.
    APPEND '61' TO mt_multiplication_lookup_2.
    APPEND '67' TO mt_multiplication_lookup_2.
    APPEND '65' TO mt_multiplication_lookup_2.
    APPEND '9B' TO mt_multiplication_lookup_2.
    APPEND '99' TO mt_multiplication_lookup_2.
    APPEND '9F' TO mt_multiplication_lookup_2.
    APPEND '9D' TO mt_multiplication_lookup_2.
    APPEND '93' TO mt_multiplication_lookup_2.
    APPEND '91' TO mt_multiplication_lookup_2.
    APPEND '97' TO mt_multiplication_lookup_2.
    APPEND '95' TO mt_multiplication_lookup_2.
    APPEND '8B' TO mt_multiplication_lookup_2.
    APPEND '89' TO mt_multiplication_lookup_2.
    APPEND '8F' TO mt_multiplication_lookup_2.
    APPEND '8D' TO mt_multiplication_lookup_2.
    APPEND '83' TO mt_multiplication_lookup_2.
    APPEND '81' TO mt_multiplication_lookup_2.
    APPEND '87' TO mt_multiplication_lookup_2.
    APPEND '85' TO mt_multiplication_lookup_2.
    APPEND 'BB' TO mt_multiplication_lookup_2.
    APPEND 'B9' TO mt_multiplication_lookup_2.
    APPEND 'BF' TO mt_multiplication_lookup_2.
    APPEND 'BD' TO mt_multiplication_lookup_2.
    APPEND 'B3' TO mt_multiplication_lookup_2.
    APPEND 'B1' TO mt_multiplication_lookup_2.
    APPEND 'B7' TO mt_multiplication_lookup_2.
    APPEND 'B5' TO mt_multiplication_lookup_2.
    APPEND 'AB' TO mt_multiplication_lookup_2.
    APPEND 'A9' TO mt_multiplication_lookup_2.
    APPEND 'AF' TO mt_multiplication_lookup_2.
    APPEND 'AD' TO mt_multiplication_lookup_2.
    APPEND 'A3' TO mt_multiplication_lookup_2.
    APPEND 'A1' TO mt_multiplication_lookup_2.
    APPEND 'A7' TO mt_multiplication_lookup_2.
    APPEND 'A5' TO mt_multiplication_lookup_2.
    APPEND 'DB' TO mt_multiplication_lookup_2.
    APPEND 'D9' TO mt_multiplication_lookup_2.
    APPEND 'DF' TO mt_multiplication_lookup_2.
    APPEND 'DD' TO mt_multiplication_lookup_2.
    APPEND 'D3' TO mt_multiplication_lookup_2.
    APPEND 'D1' TO mt_multiplication_lookup_2.
    APPEND 'D7' TO mt_multiplication_lookup_2.
    APPEND 'D5' TO mt_multiplication_lookup_2.
    APPEND 'CB' TO mt_multiplication_lookup_2.
    APPEND 'C9' TO mt_multiplication_lookup_2.
    APPEND 'CF' TO mt_multiplication_lookup_2.
    APPEND 'CD' TO mt_multiplication_lookup_2.
    APPEND 'C3' TO mt_multiplication_lookup_2.
    APPEND 'C1' TO mt_multiplication_lookup_2.
    APPEND 'C7' TO mt_multiplication_lookup_2.
    APPEND 'C5' TO mt_multiplication_lookup_2.
    APPEND 'FB' TO mt_multiplication_lookup_2.
    APPEND 'F9' TO mt_multiplication_lookup_2.
    APPEND 'FF' TO mt_multiplication_lookup_2.
    APPEND 'FD' TO mt_multiplication_lookup_2.
    APPEND 'F3' TO mt_multiplication_lookup_2.
    APPEND 'F1' TO mt_multiplication_lookup_2.
    APPEND 'F7' TO mt_multiplication_lookup_2.
    APPEND 'F5' TO mt_multiplication_lookup_2.
    APPEND 'EB' TO mt_multiplication_lookup_2.
    APPEND 'E9' TO mt_multiplication_lookup_2.
    APPEND 'EF' TO mt_multiplication_lookup_2.
    APPEND 'ED' TO mt_multiplication_lookup_2.
    APPEND 'E3' TO mt_multiplication_lookup_2.
    APPEND 'E1' TO mt_multiplication_lookup_2.
    APPEND 'E7' TO mt_multiplication_lookup_2.
    APPEND 'E5' TO mt_multiplication_lookup_2.

    "Build Multiplication Table for 3
    APPEND '00' TO mt_multiplication_lookup_3.
    APPEND '03' TO mt_multiplication_lookup_3.
    APPEND '06' TO mt_multiplication_lookup_3.
    APPEND '05' TO mt_multiplication_lookup_3.
    APPEND '0C' TO mt_multiplication_lookup_3.
    APPEND '0F' TO mt_multiplication_lookup_3.
    APPEND '0A' TO mt_multiplication_lookup_3.
    APPEND '09' TO mt_multiplication_lookup_3.
    APPEND '18' TO mt_multiplication_lookup_3.
    APPEND '1B' TO mt_multiplication_lookup_3.
    APPEND '1E' TO mt_multiplication_lookup_3.
    APPEND '1D' TO mt_multiplication_lookup_3.
    APPEND '14' TO mt_multiplication_lookup_3.
    APPEND '17' TO mt_multiplication_lookup_3.
    APPEND '12' TO mt_multiplication_lookup_3.
    APPEND '11' TO mt_multiplication_lookup_3.
    APPEND '30' TO mt_multiplication_lookup_3.
    APPEND '33' TO mt_multiplication_lookup_3.
    APPEND '36' TO mt_multiplication_lookup_3.
    APPEND '35' TO mt_multiplication_lookup_3.
    APPEND '3C' TO mt_multiplication_lookup_3.
    APPEND '3F' TO mt_multiplication_lookup_3.
    APPEND '3A' TO mt_multiplication_lookup_3.
    APPEND '39' TO mt_multiplication_lookup_3.
    APPEND '28' TO mt_multiplication_lookup_3.
    APPEND '2B' TO mt_multiplication_lookup_3.
    APPEND '2E' TO mt_multiplication_lookup_3.
    APPEND '2D' TO mt_multiplication_lookup_3.
    APPEND '24' TO mt_multiplication_lookup_3.
    APPEND '27' TO mt_multiplication_lookup_3.
    APPEND '22' TO mt_multiplication_lookup_3.
    APPEND '21' TO mt_multiplication_lookup_3.
    APPEND '60' TO mt_multiplication_lookup_3.
    APPEND '63' TO mt_multiplication_lookup_3.
    APPEND '66' TO mt_multiplication_lookup_3.
    APPEND '65' TO mt_multiplication_lookup_3.
    APPEND '6C' TO mt_multiplication_lookup_3.
    APPEND '6F' TO mt_multiplication_lookup_3.
    APPEND '6A' TO mt_multiplication_lookup_3.
    APPEND '69' TO mt_multiplication_lookup_3.
    APPEND '78' TO mt_multiplication_lookup_3.
    APPEND '7B' TO mt_multiplication_lookup_3.
    APPEND '7E' TO mt_multiplication_lookup_3.
    APPEND '7D' TO mt_multiplication_lookup_3.
    APPEND '74' TO mt_multiplication_lookup_3.
    APPEND '77' TO mt_multiplication_lookup_3.
    APPEND '72' TO mt_multiplication_lookup_3.
    APPEND '71' TO mt_multiplication_lookup_3.
    APPEND '50' TO mt_multiplication_lookup_3.
    APPEND '53' TO mt_multiplication_lookup_3.
    APPEND '56' TO mt_multiplication_lookup_3.
    APPEND '55' TO mt_multiplication_lookup_3.
    APPEND '5C' TO mt_multiplication_lookup_3.
    APPEND '5F' TO mt_multiplication_lookup_3.
    APPEND '5A' TO mt_multiplication_lookup_3.
    APPEND '59' TO mt_multiplication_lookup_3.
    APPEND '48' TO mt_multiplication_lookup_3.
    APPEND '4B' TO mt_multiplication_lookup_3.
    APPEND '4E' TO mt_multiplication_lookup_3.
    APPEND '4D' TO mt_multiplication_lookup_3.
    APPEND '44' TO mt_multiplication_lookup_3.
    APPEND '47' TO mt_multiplication_lookup_3.
    APPEND '42' TO mt_multiplication_lookup_3.
    APPEND '41' TO mt_multiplication_lookup_3.
    APPEND 'C0' TO mt_multiplication_lookup_3.
    APPEND 'C3' TO mt_multiplication_lookup_3.
    APPEND 'C6' TO mt_multiplication_lookup_3.
    APPEND 'C5' TO mt_multiplication_lookup_3.
    APPEND 'CC' TO mt_multiplication_lookup_3.
    APPEND 'CF' TO mt_multiplication_lookup_3.
    APPEND 'CA' TO mt_multiplication_lookup_3.
    APPEND 'C9' TO mt_multiplication_lookup_3.
    APPEND 'D8' TO mt_multiplication_lookup_3.
    APPEND 'DB' TO mt_multiplication_lookup_3.
    APPEND 'DE' TO mt_multiplication_lookup_3.
    APPEND 'DD' TO mt_multiplication_lookup_3.
    APPEND 'D4' TO mt_multiplication_lookup_3.
    APPEND 'D7' TO mt_multiplication_lookup_3.
    APPEND 'D2' TO mt_multiplication_lookup_3.
    APPEND 'D1' TO mt_multiplication_lookup_3.
    APPEND 'F0' TO mt_multiplication_lookup_3.
    APPEND 'F3' TO mt_multiplication_lookup_3.
    APPEND 'F6' TO mt_multiplication_lookup_3.
    APPEND 'F5' TO mt_multiplication_lookup_3.
    APPEND 'FC' TO mt_multiplication_lookup_3.
    APPEND 'FF' TO mt_multiplication_lookup_3.
    APPEND 'FA' TO mt_multiplication_lookup_3.
    APPEND 'F9' TO mt_multiplication_lookup_3.
    APPEND 'E8' TO mt_multiplication_lookup_3.
    APPEND 'EB' TO mt_multiplication_lookup_3.
    APPEND 'EE' TO mt_multiplication_lookup_3.
    APPEND 'ED' TO mt_multiplication_lookup_3.
    APPEND 'E4' TO mt_multiplication_lookup_3.
    APPEND 'E7' TO mt_multiplication_lookup_3.
    APPEND 'E2' TO mt_multiplication_lookup_3.
    APPEND 'E1' TO mt_multiplication_lookup_3.
    APPEND 'A0' TO mt_multiplication_lookup_3.
    APPEND 'A3' TO mt_multiplication_lookup_3.
    APPEND 'A6' TO mt_multiplication_lookup_3.
    APPEND 'A5' TO mt_multiplication_lookup_3.
    APPEND 'AC' TO mt_multiplication_lookup_3.
    APPEND 'AF' TO mt_multiplication_lookup_3.
    APPEND 'AA' TO mt_multiplication_lookup_3.
    APPEND 'A9' TO mt_multiplication_lookup_3.
    APPEND 'B8' TO mt_multiplication_lookup_3.
    APPEND 'BB' TO mt_multiplication_lookup_3.
    APPEND 'BE' TO mt_multiplication_lookup_3.
    APPEND 'BD' TO mt_multiplication_lookup_3.
    APPEND 'B4' TO mt_multiplication_lookup_3.
    APPEND 'B7' TO mt_multiplication_lookup_3.
    APPEND 'B2' TO mt_multiplication_lookup_3.
    APPEND 'B1' TO mt_multiplication_lookup_3.
    APPEND '90' TO mt_multiplication_lookup_3.
    APPEND '93' TO mt_multiplication_lookup_3.
    APPEND '96' TO mt_multiplication_lookup_3.
    APPEND '95' TO mt_multiplication_lookup_3.
    APPEND '9C' TO mt_multiplication_lookup_3.
    APPEND '9F' TO mt_multiplication_lookup_3.
    APPEND '9A' TO mt_multiplication_lookup_3.
    APPEND '99' TO mt_multiplication_lookup_3.
    APPEND '88' TO mt_multiplication_lookup_3.
    APPEND '8B' TO mt_multiplication_lookup_3.
    APPEND '8E' TO mt_multiplication_lookup_3.
    APPEND '8D' TO mt_multiplication_lookup_3.
    APPEND '84' TO mt_multiplication_lookup_3.
    APPEND '87' TO mt_multiplication_lookup_3.
    APPEND '82' TO mt_multiplication_lookup_3.
    APPEND '81' TO mt_multiplication_lookup_3.
    APPEND '9B' TO mt_multiplication_lookup_3.
    APPEND '98' TO mt_multiplication_lookup_3.
    APPEND '9D' TO mt_multiplication_lookup_3.
    APPEND '9E' TO mt_multiplication_lookup_3.
    APPEND '97' TO mt_multiplication_lookup_3.
    APPEND '94' TO mt_multiplication_lookup_3.
    APPEND '91' TO mt_multiplication_lookup_3.
    APPEND '92' TO mt_multiplication_lookup_3.
    APPEND '83' TO mt_multiplication_lookup_3.
    APPEND '80' TO mt_multiplication_lookup_3.
    APPEND '85' TO mt_multiplication_lookup_3.
    APPEND '86' TO mt_multiplication_lookup_3.
    APPEND '8F' TO mt_multiplication_lookup_3.
    APPEND '8C' TO mt_multiplication_lookup_3.
    APPEND '89' TO mt_multiplication_lookup_3.
    APPEND '8A' TO mt_multiplication_lookup_3.
    APPEND 'AB' TO mt_multiplication_lookup_3.
    APPEND 'A8' TO mt_multiplication_lookup_3.
    APPEND 'AD' TO mt_multiplication_lookup_3.
    APPEND 'AE' TO mt_multiplication_lookup_3.
    APPEND 'A7' TO mt_multiplication_lookup_3.
    APPEND 'A4' TO mt_multiplication_lookup_3.
    APPEND 'A1' TO mt_multiplication_lookup_3.
    APPEND 'A2' TO mt_multiplication_lookup_3.
    APPEND 'B3' TO mt_multiplication_lookup_3.
    APPEND 'B0' TO mt_multiplication_lookup_3.
    APPEND 'B5' TO mt_multiplication_lookup_3.
    APPEND 'B6' TO mt_multiplication_lookup_3.
    APPEND 'BF' TO mt_multiplication_lookup_3.
    APPEND 'BC' TO mt_multiplication_lookup_3.
    APPEND 'B9' TO mt_multiplication_lookup_3.
    APPEND 'BA' TO mt_multiplication_lookup_3.
    APPEND 'FB' TO mt_multiplication_lookup_3.
    APPEND 'F8' TO mt_multiplication_lookup_3.
    APPEND 'FD' TO mt_multiplication_lookup_3.
    APPEND 'FE' TO mt_multiplication_lookup_3.
    APPEND 'F7' TO mt_multiplication_lookup_3.
    APPEND 'F4' TO mt_multiplication_lookup_3.
    APPEND 'F1' TO mt_multiplication_lookup_3.
    APPEND 'F2' TO mt_multiplication_lookup_3.
    APPEND 'E3' TO mt_multiplication_lookup_3.
    APPEND 'E0' TO mt_multiplication_lookup_3.
    APPEND 'E5' TO mt_multiplication_lookup_3.
    APPEND 'E6' TO mt_multiplication_lookup_3.
    APPEND 'EF' TO mt_multiplication_lookup_3.
    APPEND 'EC' TO mt_multiplication_lookup_3.
    APPEND 'E9' TO mt_multiplication_lookup_3.
    APPEND 'EA' TO mt_multiplication_lookup_3.
    APPEND 'CB' TO mt_multiplication_lookup_3.
    APPEND 'C8' TO mt_multiplication_lookup_3.
    APPEND 'CD' TO mt_multiplication_lookup_3.
    APPEND 'CE' TO mt_multiplication_lookup_3.
    APPEND 'C7' TO mt_multiplication_lookup_3.
    APPEND 'C4' TO mt_multiplication_lookup_3.
    APPEND 'C1' TO mt_multiplication_lookup_3.
    APPEND 'C2' TO mt_multiplication_lookup_3.
    APPEND 'D3' TO mt_multiplication_lookup_3.
    APPEND 'D0' TO mt_multiplication_lookup_3.
    APPEND 'D5' TO mt_multiplication_lookup_3.
    APPEND 'D6' TO mt_multiplication_lookup_3.
    APPEND 'DF' TO mt_multiplication_lookup_3.
    APPEND 'DC' TO mt_multiplication_lookup_3.
    APPEND 'D9' TO mt_multiplication_lookup_3.
    APPEND 'DA' TO mt_multiplication_lookup_3.
    APPEND '5B' TO mt_multiplication_lookup_3.
    APPEND '58' TO mt_multiplication_lookup_3.
    APPEND '5D' TO mt_multiplication_lookup_3.
    APPEND '5E' TO mt_multiplication_lookup_3.
    APPEND '57' TO mt_multiplication_lookup_3.
    APPEND '54' TO mt_multiplication_lookup_3.
    APPEND '51' TO mt_multiplication_lookup_3.
    APPEND '52' TO mt_multiplication_lookup_3.
    APPEND '43' TO mt_multiplication_lookup_3.
    APPEND '40' TO mt_multiplication_lookup_3.
    APPEND '45' TO mt_multiplication_lookup_3.
    APPEND '46' TO mt_multiplication_lookup_3.
    APPEND '4F' TO mt_multiplication_lookup_3.
    APPEND '4C' TO mt_multiplication_lookup_3.
    APPEND '49' TO mt_multiplication_lookup_3.
    APPEND '4A' TO mt_multiplication_lookup_3.
    APPEND '6B' TO mt_multiplication_lookup_3.
    APPEND '68' TO mt_multiplication_lookup_3.
    APPEND '6D' TO mt_multiplication_lookup_3.
    APPEND '6E' TO mt_multiplication_lookup_3.
    APPEND '67' TO mt_multiplication_lookup_3.
    APPEND '64' TO mt_multiplication_lookup_3.
    APPEND '61' TO mt_multiplication_lookup_3.
    APPEND '62' TO mt_multiplication_lookup_3.
    APPEND '73' TO mt_multiplication_lookup_3.
    APPEND '70' TO mt_multiplication_lookup_3.
    APPEND '75' TO mt_multiplication_lookup_3.
    APPEND '76' TO mt_multiplication_lookup_3.
    APPEND '7F' TO mt_multiplication_lookup_3.
    APPEND '7C' TO mt_multiplication_lookup_3.
    APPEND '79' TO mt_multiplication_lookup_3.
    APPEND '7A' TO mt_multiplication_lookup_3.
    APPEND '3B' TO mt_multiplication_lookup_3.
    APPEND '38' TO mt_multiplication_lookup_3.
    APPEND '3D' TO mt_multiplication_lookup_3.
    APPEND '3E' TO mt_multiplication_lookup_3.
    APPEND '37' TO mt_multiplication_lookup_3.
    APPEND '34' TO mt_multiplication_lookup_3.
    APPEND '31' TO mt_multiplication_lookup_3.
    APPEND '32' TO mt_multiplication_lookup_3.
    APPEND '23' TO mt_multiplication_lookup_3.
    APPEND '20' TO mt_multiplication_lookup_3.
    APPEND '25' TO mt_multiplication_lookup_3.
    APPEND '26' TO mt_multiplication_lookup_3.
    APPEND '2F' TO mt_multiplication_lookup_3.
    APPEND '2C' TO mt_multiplication_lookup_3.
    APPEND '29' TO mt_multiplication_lookup_3.
    APPEND '2A' TO mt_multiplication_lookup_3.
    APPEND '0B' TO mt_multiplication_lookup_3.
    APPEND '08' TO mt_multiplication_lookup_3.
    APPEND '0D' TO mt_multiplication_lookup_3.
    APPEND '0E' TO mt_multiplication_lookup_3.
    APPEND '07' TO mt_multiplication_lookup_3.
    APPEND '04' TO mt_multiplication_lookup_3.
    APPEND '01' TO mt_multiplication_lookup_3.
    APPEND '02' TO mt_multiplication_lookup_3.
    APPEND '13' TO mt_multiplication_lookup_3.
    APPEND '10' TO mt_multiplication_lookup_3.
    APPEND '15' TO mt_multiplication_lookup_3.
    APPEND '16' TO mt_multiplication_lookup_3.
    APPEND '1F' TO mt_multiplication_lookup_3.
    APPEND '1C' TO mt_multiplication_lookup_3.
    APPEND '19' TO mt_multiplication_lookup_3.
    APPEND '1A' TO mt_multiplication_lookup_3.

    "Build Multiplication Table for 9
    APPEND '00' TO mt_multiplication_lookup_9.
    APPEND '09' TO mt_multiplication_lookup_9.
    APPEND '12' TO mt_multiplication_lookup_9.
    APPEND '1B' TO mt_multiplication_lookup_9.
    APPEND '24' TO mt_multiplication_lookup_9.
    APPEND '2D' TO mt_multiplication_lookup_9.
    APPEND '36' TO mt_multiplication_lookup_9.
    APPEND '3F' TO mt_multiplication_lookup_9.
    APPEND '48' TO mt_multiplication_lookup_9.
    APPEND '41' TO mt_multiplication_lookup_9.
    APPEND '5A' TO mt_multiplication_lookup_9.
    APPEND '53' TO mt_multiplication_lookup_9.
    APPEND '6C' TO mt_multiplication_lookup_9.
    APPEND '65' TO mt_multiplication_lookup_9.
    APPEND '7E' TO mt_multiplication_lookup_9.
    APPEND '77' TO mt_multiplication_lookup_9.
    APPEND '90' TO mt_multiplication_lookup_9.
    APPEND '99' TO mt_multiplication_lookup_9.
    APPEND '82' TO mt_multiplication_lookup_9.
    APPEND '8B' TO mt_multiplication_lookup_9.
    APPEND 'B4' TO mt_multiplication_lookup_9.
    APPEND 'BD' TO mt_multiplication_lookup_9.
    APPEND 'A6' TO mt_multiplication_lookup_9.
    APPEND 'AF' TO mt_multiplication_lookup_9.
    APPEND 'D8' TO mt_multiplication_lookup_9.
    APPEND 'D1' TO mt_multiplication_lookup_9.
    APPEND 'CA' TO mt_multiplication_lookup_9.
    APPEND 'C3' TO mt_multiplication_lookup_9.
    APPEND 'FC' TO mt_multiplication_lookup_9.
    APPEND 'F5' TO mt_multiplication_lookup_9.
    APPEND 'EE' TO mt_multiplication_lookup_9.
    APPEND 'E7' TO mt_multiplication_lookup_9.
    APPEND '3B' TO mt_multiplication_lookup_9.
    APPEND '32' TO mt_multiplication_lookup_9.
    APPEND '29' TO mt_multiplication_lookup_9.
    APPEND '20' TO mt_multiplication_lookup_9.
    APPEND '1F' TO mt_multiplication_lookup_9.
    APPEND '16' TO mt_multiplication_lookup_9.
    APPEND '0D' TO mt_multiplication_lookup_9.
    APPEND '04' TO mt_multiplication_lookup_9.
    APPEND '73' TO mt_multiplication_lookup_9.
    APPEND '7A' TO mt_multiplication_lookup_9.
    APPEND '61' TO mt_multiplication_lookup_9.
    APPEND '68' TO mt_multiplication_lookup_9.
    APPEND '57' TO mt_multiplication_lookup_9.
    APPEND '5E' TO mt_multiplication_lookup_9.
    APPEND '45' TO mt_multiplication_lookup_9.
    APPEND '4C' TO mt_multiplication_lookup_9.
    APPEND 'AB' TO mt_multiplication_lookup_9.
    APPEND 'A2' TO mt_multiplication_lookup_9.
    APPEND 'B9' TO mt_multiplication_lookup_9.
    APPEND 'B0' TO mt_multiplication_lookup_9.
    APPEND '8F' TO mt_multiplication_lookup_9.
    APPEND '86' TO mt_multiplication_lookup_9.
    APPEND '9D' TO mt_multiplication_lookup_9.
    APPEND '94' TO mt_multiplication_lookup_9.
    APPEND 'E3' TO mt_multiplication_lookup_9.
    APPEND 'EA' TO mt_multiplication_lookup_9.
    APPEND 'F1' TO mt_multiplication_lookup_9.
    APPEND 'F8' TO mt_multiplication_lookup_9.
    APPEND 'C7' TO mt_multiplication_lookup_9.
    APPEND 'CE' TO mt_multiplication_lookup_9.
    APPEND 'D5' TO mt_multiplication_lookup_9.
    APPEND 'DC' TO mt_multiplication_lookup_9.
    APPEND '76' TO mt_multiplication_lookup_9.
    APPEND '7F' TO mt_multiplication_lookup_9.
    APPEND '64' TO mt_multiplication_lookup_9.
    APPEND '6D' TO mt_multiplication_lookup_9.
    APPEND '52' TO mt_multiplication_lookup_9.
    APPEND '5B' TO mt_multiplication_lookup_9.
    APPEND '40' TO mt_multiplication_lookup_9.
    APPEND '49' TO mt_multiplication_lookup_9.
    APPEND '3E' TO mt_multiplication_lookup_9.
    APPEND '37' TO mt_multiplication_lookup_9.
    APPEND '2C' TO mt_multiplication_lookup_9.
    APPEND '25' TO mt_multiplication_lookup_9.
    APPEND '1A' TO mt_multiplication_lookup_9.
    APPEND '13' TO mt_multiplication_lookup_9.
    APPEND '08' TO mt_multiplication_lookup_9.
    APPEND '01' TO mt_multiplication_lookup_9.
    APPEND 'E6' TO mt_multiplication_lookup_9.
    APPEND 'EF' TO mt_multiplication_lookup_9.
    APPEND 'F4' TO mt_multiplication_lookup_9.
    APPEND 'FD' TO mt_multiplication_lookup_9.
    APPEND 'C2' TO mt_multiplication_lookup_9.
    APPEND 'CB' TO mt_multiplication_lookup_9.
    APPEND 'D0' TO mt_multiplication_lookup_9.
    APPEND 'D9' TO mt_multiplication_lookup_9.
    APPEND 'AE' TO mt_multiplication_lookup_9.
    APPEND 'A7' TO mt_multiplication_lookup_9.
    APPEND 'BC' TO mt_multiplication_lookup_9.
    APPEND 'B5' TO mt_multiplication_lookup_9.
    APPEND '8A' TO mt_multiplication_lookup_9.
    APPEND '83' TO mt_multiplication_lookup_9.
    APPEND '98' TO mt_multiplication_lookup_9.
    APPEND '91' TO mt_multiplication_lookup_9.
    APPEND '4D' TO mt_multiplication_lookup_9.
    APPEND '44' TO mt_multiplication_lookup_9.
    APPEND '5F' TO mt_multiplication_lookup_9.
    APPEND '56' TO mt_multiplication_lookup_9.
    APPEND '69' TO mt_multiplication_lookup_9.
    APPEND '60' TO mt_multiplication_lookup_9.
    APPEND '7B' TO mt_multiplication_lookup_9.
    APPEND '72' TO mt_multiplication_lookup_9.
    APPEND '05' TO mt_multiplication_lookup_9.
    APPEND '0C' TO mt_multiplication_lookup_9.
    APPEND '17' TO mt_multiplication_lookup_9.
    APPEND '1E' TO mt_multiplication_lookup_9.
    APPEND '21' TO mt_multiplication_lookup_9.
    APPEND '28' TO mt_multiplication_lookup_9.
    APPEND '33' TO mt_multiplication_lookup_9.
    APPEND '3A' TO mt_multiplication_lookup_9.
    APPEND 'DD' TO mt_multiplication_lookup_9.
    APPEND 'D4' TO mt_multiplication_lookup_9.
    APPEND 'CF' TO mt_multiplication_lookup_9.
    APPEND 'C6' TO mt_multiplication_lookup_9.
    APPEND 'F9' TO mt_multiplication_lookup_9.
    APPEND 'F0' TO mt_multiplication_lookup_9.
    APPEND 'EB' TO mt_multiplication_lookup_9.
    APPEND 'E2' TO mt_multiplication_lookup_9.
    APPEND '95' TO mt_multiplication_lookup_9.
    APPEND '9C' TO mt_multiplication_lookup_9.
    APPEND '87' TO mt_multiplication_lookup_9.
    APPEND '8E' TO mt_multiplication_lookup_9.
    APPEND 'B1' TO mt_multiplication_lookup_9.
    APPEND 'B8' TO mt_multiplication_lookup_9.
    APPEND 'A3' TO mt_multiplication_lookup_9.
    APPEND 'AA' TO mt_multiplication_lookup_9.
    APPEND 'EC' TO mt_multiplication_lookup_9.
    APPEND 'E5' TO mt_multiplication_lookup_9.
    APPEND 'FE' TO mt_multiplication_lookup_9.
    APPEND 'F7' TO mt_multiplication_lookup_9.
    APPEND 'C8' TO mt_multiplication_lookup_9.
    APPEND 'C1' TO mt_multiplication_lookup_9.
    APPEND 'DA' TO mt_multiplication_lookup_9.
    APPEND 'D3' TO mt_multiplication_lookup_9.
    APPEND 'A4' TO mt_multiplication_lookup_9.
    APPEND 'AD' TO mt_multiplication_lookup_9.
    APPEND 'B6' TO mt_multiplication_lookup_9.
    APPEND 'BF' TO mt_multiplication_lookup_9.
    APPEND '80' TO mt_multiplication_lookup_9.
    APPEND '89' TO mt_multiplication_lookup_9.
    APPEND '92' TO mt_multiplication_lookup_9.
    APPEND '9B' TO mt_multiplication_lookup_9.
    APPEND '7C' TO mt_multiplication_lookup_9.
    APPEND '75' TO mt_multiplication_lookup_9.
    APPEND '6E' TO mt_multiplication_lookup_9.
    APPEND '67' TO mt_multiplication_lookup_9.
    APPEND '58' TO mt_multiplication_lookup_9.
    APPEND '51' TO mt_multiplication_lookup_9.
    APPEND '4A' TO mt_multiplication_lookup_9.
    APPEND '43' TO mt_multiplication_lookup_9.
    APPEND '34' TO mt_multiplication_lookup_9.
    APPEND '3D' TO mt_multiplication_lookup_9.
    APPEND '26' TO mt_multiplication_lookup_9.
    APPEND '2F' TO mt_multiplication_lookup_9.
    APPEND '10' TO mt_multiplication_lookup_9.
    APPEND '19' TO mt_multiplication_lookup_9.
    APPEND '02' TO mt_multiplication_lookup_9.
    APPEND '0B' TO mt_multiplication_lookup_9.
    APPEND 'D7' TO mt_multiplication_lookup_9.
    APPEND 'DE' TO mt_multiplication_lookup_9.
    APPEND 'C5' TO mt_multiplication_lookup_9.
    APPEND 'CC' TO mt_multiplication_lookup_9.
    APPEND 'F3' TO mt_multiplication_lookup_9.
    APPEND 'FA' TO mt_multiplication_lookup_9.
    APPEND 'E1' TO mt_multiplication_lookup_9.
    APPEND 'E8' TO mt_multiplication_lookup_9.
    APPEND '9F' TO mt_multiplication_lookup_9.
    APPEND '96' TO mt_multiplication_lookup_9.
    APPEND '8D' TO mt_multiplication_lookup_9.
    APPEND '84' TO mt_multiplication_lookup_9.
    APPEND 'BB' TO mt_multiplication_lookup_9.
    APPEND 'B2' TO mt_multiplication_lookup_9.
    APPEND 'A9' TO mt_multiplication_lookup_9.
    APPEND 'A0' TO mt_multiplication_lookup_9.
    APPEND '47' TO mt_multiplication_lookup_9.
    APPEND '4E' TO mt_multiplication_lookup_9.
    APPEND '55' TO mt_multiplication_lookup_9.
    APPEND '5C' TO mt_multiplication_lookup_9.
    APPEND '63' TO mt_multiplication_lookup_9.
    APPEND '6A' TO mt_multiplication_lookup_9.
    APPEND '71' TO mt_multiplication_lookup_9.
    APPEND '78' TO mt_multiplication_lookup_9.
    APPEND '0F' TO mt_multiplication_lookup_9.
    APPEND '06' TO mt_multiplication_lookup_9.
    APPEND '1D' TO mt_multiplication_lookup_9.
    APPEND '14' TO mt_multiplication_lookup_9.
    APPEND '2B' TO mt_multiplication_lookup_9.
    APPEND '22' TO mt_multiplication_lookup_9.
    APPEND '39' TO mt_multiplication_lookup_9.
    APPEND '30' TO mt_multiplication_lookup_9.
    APPEND '9A' TO mt_multiplication_lookup_9.
    APPEND '93' TO mt_multiplication_lookup_9.
    APPEND '88' TO mt_multiplication_lookup_9.
    APPEND '81' TO mt_multiplication_lookup_9.
    APPEND 'BE' TO mt_multiplication_lookup_9.
    APPEND 'B7' TO mt_multiplication_lookup_9.
    APPEND 'AC' TO mt_multiplication_lookup_9.
    APPEND 'A5' TO mt_multiplication_lookup_9.
    APPEND 'D2' TO mt_multiplication_lookup_9.
    APPEND 'DB' TO mt_multiplication_lookup_9.
    APPEND 'C0' TO mt_multiplication_lookup_9.
    APPEND 'C9' TO mt_multiplication_lookup_9.
    APPEND 'F6' TO mt_multiplication_lookup_9.
    APPEND 'FF' TO mt_multiplication_lookup_9.
    APPEND 'E4' TO mt_multiplication_lookup_9.
    APPEND 'ED' TO mt_multiplication_lookup_9.
    APPEND '0A' TO mt_multiplication_lookup_9.
    APPEND '03' TO mt_multiplication_lookup_9.
    APPEND '18' TO mt_multiplication_lookup_9.
    APPEND '11' TO mt_multiplication_lookup_9.
    APPEND '2E' TO mt_multiplication_lookup_9.
    APPEND '27' TO mt_multiplication_lookup_9.
    APPEND '3C' TO mt_multiplication_lookup_9.
    APPEND '35' TO mt_multiplication_lookup_9.
    APPEND '42' TO mt_multiplication_lookup_9.
    APPEND '4B' TO mt_multiplication_lookup_9.
    APPEND '50' TO mt_multiplication_lookup_9.
    APPEND '59' TO mt_multiplication_lookup_9.
    APPEND '66' TO mt_multiplication_lookup_9.
    APPEND '6F' TO mt_multiplication_lookup_9.
    APPEND '74' TO mt_multiplication_lookup_9.
    APPEND '7D' TO mt_multiplication_lookup_9.
    APPEND 'A1' TO mt_multiplication_lookup_9.
    APPEND 'A8' TO mt_multiplication_lookup_9.
    APPEND 'B3' TO mt_multiplication_lookup_9.
    APPEND 'BA' TO mt_multiplication_lookup_9.
    APPEND '85' TO mt_multiplication_lookup_9.
    APPEND '8C' TO mt_multiplication_lookup_9.
    APPEND '97' TO mt_multiplication_lookup_9.
    APPEND '9E' TO mt_multiplication_lookup_9.
    APPEND 'E9' TO mt_multiplication_lookup_9.
    APPEND 'E0' TO mt_multiplication_lookup_9.
    APPEND 'FB' TO mt_multiplication_lookup_9.
    APPEND 'F2' TO mt_multiplication_lookup_9.
    APPEND 'CD' TO mt_multiplication_lookup_9.
    APPEND 'C4' TO mt_multiplication_lookup_9.
    APPEND 'DF' TO mt_multiplication_lookup_9.
    APPEND 'D6' TO mt_multiplication_lookup_9.
    APPEND '31' TO mt_multiplication_lookup_9.
    APPEND '38' TO mt_multiplication_lookup_9.
    APPEND '23' TO mt_multiplication_lookup_9.
    APPEND '2A' TO mt_multiplication_lookup_9.
    APPEND '15' TO mt_multiplication_lookup_9.
    APPEND '1C' TO mt_multiplication_lookup_9.
    APPEND '07' TO mt_multiplication_lookup_9.
    APPEND '0E' TO mt_multiplication_lookup_9.
    APPEND '79' TO mt_multiplication_lookup_9.
    APPEND '70' TO mt_multiplication_lookup_9.
    APPEND '6B' TO mt_multiplication_lookup_9.
    APPEND '62' TO mt_multiplication_lookup_9.
    APPEND '5D' TO mt_multiplication_lookup_9.
    APPEND '54' TO mt_multiplication_lookup_9.
    APPEND '4F' TO mt_multiplication_lookup_9.
    APPEND '46' TO mt_multiplication_lookup_9.

    "Build Multiplication Table for 11
    APPEND '00' TO mt_multiplication_lookup_11.
    APPEND '0B' TO mt_multiplication_lookup_11.
    APPEND '16' TO mt_multiplication_lookup_11.
    APPEND '1D' TO mt_multiplication_lookup_11.
    APPEND '2C' TO mt_multiplication_lookup_11.
    APPEND '27' TO mt_multiplication_lookup_11.
    APPEND '3A' TO mt_multiplication_lookup_11.
    APPEND '31' TO mt_multiplication_lookup_11.
    APPEND '58' TO mt_multiplication_lookup_11.
    APPEND '53' TO mt_multiplication_lookup_11.
    APPEND '4E' TO mt_multiplication_lookup_11.
    APPEND '45' TO mt_multiplication_lookup_11.
    APPEND '74' TO mt_multiplication_lookup_11.
    APPEND '7F' TO mt_multiplication_lookup_11.
    APPEND '62' TO mt_multiplication_lookup_11.
    APPEND '69' TO mt_multiplication_lookup_11.
    APPEND 'B0' TO mt_multiplication_lookup_11.
    APPEND 'BB' TO mt_multiplication_lookup_11.
    APPEND 'A6' TO mt_multiplication_lookup_11.
    APPEND 'AD' TO mt_multiplication_lookup_11.
    APPEND '9C' TO mt_multiplication_lookup_11.
    APPEND '97' TO mt_multiplication_lookup_11.
    APPEND '8A' TO mt_multiplication_lookup_11.
    APPEND '81' TO mt_multiplication_lookup_11.
    APPEND 'E8' TO mt_multiplication_lookup_11.
    APPEND 'E3' TO mt_multiplication_lookup_11.
    APPEND 'FE' TO mt_multiplication_lookup_11.
    APPEND 'F5' TO mt_multiplication_lookup_11.
    APPEND 'C4' TO mt_multiplication_lookup_11.
    APPEND 'CF' TO mt_multiplication_lookup_11.
    APPEND 'D2' TO mt_multiplication_lookup_11.
    APPEND 'D9' TO mt_multiplication_lookup_11.
    APPEND '7B' TO mt_multiplication_lookup_11.
    APPEND '70' TO mt_multiplication_lookup_11.
    APPEND '6D' TO mt_multiplication_lookup_11.
    APPEND '66' TO mt_multiplication_lookup_11.
    APPEND '57' TO mt_multiplication_lookup_11.
    APPEND '5C' TO mt_multiplication_lookup_11.
    APPEND '41' TO mt_multiplication_lookup_11.
    APPEND '4A' TO mt_multiplication_lookup_11.
    APPEND '23' TO mt_multiplication_lookup_11.
    APPEND '28' TO mt_multiplication_lookup_11.
    APPEND '35' TO mt_multiplication_lookup_11.
    APPEND '3E' TO mt_multiplication_lookup_11.
    APPEND '0F' TO mt_multiplication_lookup_11.
    APPEND '04' TO mt_multiplication_lookup_11.
    APPEND '19' TO mt_multiplication_lookup_11.
    APPEND '12' TO mt_multiplication_lookup_11.
    APPEND 'CB' TO mt_multiplication_lookup_11.
    APPEND 'C0' TO mt_multiplication_lookup_11.
    APPEND 'DD' TO mt_multiplication_lookup_11.
    APPEND 'D6' TO mt_multiplication_lookup_11.
    APPEND 'E7' TO mt_multiplication_lookup_11.
    APPEND 'EC' TO mt_multiplication_lookup_11.
    APPEND 'F1' TO mt_multiplication_lookup_11.
    APPEND 'FA' TO mt_multiplication_lookup_11.
    APPEND '93' TO mt_multiplication_lookup_11.
    APPEND '98' TO mt_multiplication_lookup_11.
    APPEND '85' TO mt_multiplication_lookup_11.
    APPEND '8E' TO mt_multiplication_lookup_11.
    APPEND 'BF' TO mt_multiplication_lookup_11.
    APPEND 'B4' TO mt_multiplication_lookup_11.
    APPEND 'A9' TO mt_multiplication_lookup_11.
    APPEND 'A2' TO mt_multiplication_lookup_11.
    APPEND 'F6' TO mt_multiplication_lookup_11.
    APPEND 'FD' TO mt_multiplication_lookup_11.
    APPEND 'E0' TO mt_multiplication_lookup_11.
    APPEND 'EB' TO mt_multiplication_lookup_11.
    APPEND 'DA' TO mt_multiplication_lookup_11.
    APPEND 'D1' TO mt_multiplication_lookup_11.
    APPEND 'CC' TO mt_multiplication_lookup_11.
    APPEND 'C7' TO mt_multiplication_lookup_11.
    APPEND 'AE' TO mt_multiplication_lookup_11.
    APPEND 'A5' TO mt_multiplication_lookup_11.
    APPEND 'B8' TO mt_multiplication_lookup_11.
    APPEND 'B3' TO mt_multiplication_lookup_11.
    APPEND '82' TO mt_multiplication_lookup_11.
    APPEND '89' TO mt_multiplication_lookup_11.
    APPEND '94' TO mt_multiplication_lookup_11.
    APPEND '9F' TO mt_multiplication_lookup_11.
    APPEND '46' TO mt_multiplication_lookup_11.
    APPEND '4D' TO mt_multiplication_lookup_11.
    APPEND '50' TO mt_multiplication_lookup_11.
    APPEND '5B' TO mt_multiplication_lookup_11.
    APPEND '6A' TO mt_multiplication_lookup_11.
    APPEND '61' TO mt_multiplication_lookup_11.
    APPEND '7C' TO mt_multiplication_lookup_11.
    APPEND '77' TO mt_multiplication_lookup_11.
    APPEND '1E' TO mt_multiplication_lookup_11.
    APPEND '15' TO mt_multiplication_lookup_11.
    APPEND '08' TO mt_multiplication_lookup_11.
    APPEND '03' TO mt_multiplication_lookup_11.
    APPEND '32' TO mt_multiplication_lookup_11.
    APPEND '39' TO mt_multiplication_lookup_11.
    APPEND '24' TO mt_multiplication_lookup_11.
    APPEND '2F' TO mt_multiplication_lookup_11.
    APPEND '8D' TO mt_multiplication_lookup_11.
    APPEND '86' TO mt_multiplication_lookup_11.
    APPEND '9B' TO mt_multiplication_lookup_11.
    APPEND '90' TO mt_multiplication_lookup_11.
    APPEND 'A1' TO mt_multiplication_lookup_11.
    APPEND 'AA' TO mt_multiplication_lookup_11.
    APPEND 'B7' TO mt_multiplication_lookup_11.
    APPEND 'BC' TO mt_multiplication_lookup_11.
    APPEND 'D5' TO mt_multiplication_lookup_11.
    APPEND 'DE' TO mt_multiplication_lookup_11.
    APPEND 'C3' TO mt_multiplication_lookup_11.
    APPEND 'C8' TO mt_multiplication_lookup_11.
    APPEND 'F9' TO mt_multiplication_lookup_11.
    APPEND 'F2' TO mt_multiplication_lookup_11.
    APPEND 'EF' TO mt_multiplication_lookup_11.
    APPEND 'E4' TO mt_multiplication_lookup_11.
    APPEND '3D' TO mt_multiplication_lookup_11.
    APPEND '36' TO mt_multiplication_lookup_11.
    APPEND '2B' TO mt_multiplication_lookup_11.
    APPEND '20' TO mt_multiplication_lookup_11.
    APPEND '11' TO mt_multiplication_lookup_11.
    APPEND '1A' TO mt_multiplication_lookup_11.
    APPEND '07' TO mt_multiplication_lookup_11.
    APPEND '0C' TO mt_multiplication_lookup_11.
    APPEND '65' TO mt_multiplication_lookup_11.
    APPEND '6E' TO mt_multiplication_lookup_11.
    APPEND '73' TO mt_multiplication_lookup_11.
    APPEND '78' TO mt_multiplication_lookup_11.
    APPEND '49' TO mt_multiplication_lookup_11.
    APPEND '42' TO mt_multiplication_lookup_11.
    APPEND '5F' TO mt_multiplication_lookup_11.
    APPEND '54' TO mt_multiplication_lookup_11.
    APPEND 'F7' TO mt_multiplication_lookup_11.
    APPEND 'FC' TO mt_multiplication_lookup_11.
    APPEND 'E1' TO mt_multiplication_lookup_11.
    APPEND 'EA' TO mt_multiplication_lookup_11.
    APPEND 'DB' TO mt_multiplication_lookup_11.
    APPEND 'D0' TO mt_multiplication_lookup_11.
    APPEND 'CD' TO mt_multiplication_lookup_11.
    APPEND 'C6' TO mt_multiplication_lookup_11.
    APPEND 'AF' TO mt_multiplication_lookup_11.
    APPEND 'A4' TO mt_multiplication_lookup_11.
    APPEND 'B9' TO mt_multiplication_lookup_11.
    APPEND 'B2' TO mt_multiplication_lookup_11.
    APPEND '83' TO mt_multiplication_lookup_11.
    APPEND '88' TO mt_multiplication_lookup_11.
    APPEND '95' TO mt_multiplication_lookup_11.
    APPEND '9E' TO mt_multiplication_lookup_11.
    APPEND '47' TO mt_multiplication_lookup_11.
    APPEND '4C' TO mt_multiplication_lookup_11.
    APPEND '51' TO mt_multiplication_lookup_11.
    APPEND '5A' TO mt_multiplication_lookup_11.
    APPEND '6B' TO mt_multiplication_lookup_11.
    APPEND '60' TO mt_multiplication_lookup_11.
    APPEND '7D' TO mt_multiplication_lookup_11.
    APPEND '76' TO mt_multiplication_lookup_11.
    APPEND '1F' TO mt_multiplication_lookup_11.
    APPEND '14' TO mt_multiplication_lookup_11.
    APPEND '09' TO mt_multiplication_lookup_11.
    APPEND '02' TO mt_multiplication_lookup_11.
    APPEND '33' TO mt_multiplication_lookup_11.
    APPEND '38' TO mt_multiplication_lookup_11.
    APPEND '25' TO mt_multiplication_lookup_11.
    APPEND '2E' TO mt_multiplication_lookup_11.
    APPEND '8C' TO mt_multiplication_lookup_11.
    APPEND '87' TO mt_multiplication_lookup_11.
    APPEND '9A' TO mt_multiplication_lookup_11.
    APPEND '91' TO mt_multiplication_lookup_11.
    APPEND 'A0' TO mt_multiplication_lookup_11.
    APPEND 'AB' TO mt_multiplication_lookup_11.
    APPEND 'B6' TO mt_multiplication_lookup_11.
    APPEND 'BD' TO mt_multiplication_lookup_11.
    APPEND 'D4' TO mt_multiplication_lookup_11.
    APPEND 'DF' TO mt_multiplication_lookup_11.
    APPEND 'C2' TO mt_multiplication_lookup_11.
    APPEND 'C9' TO mt_multiplication_lookup_11.
    APPEND 'F8' TO mt_multiplication_lookup_11.
    APPEND 'F3' TO mt_multiplication_lookup_11.
    APPEND 'EE' TO mt_multiplication_lookup_11.
    APPEND 'E5' TO mt_multiplication_lookup_11.
    APPEND '3C' TO mt_multiplication_lookup_11.
    APPEND '37' TO mt_multiplication_lookup_11.
    APPEND '2A' TO mt_multiplication_lookup_11.
    APPEND '21' TO mt_multiplication_lookup_11.
    APPEND '10' TO mt_multiplication_lookup_11.
    APPEND '1B' TO mt_multiplication_lookup_11.
    APPEND '06' TO mt_multiplication_lookup_11.
    APPEND '0D' TO mt_multiplication_lookup_11.
    APPEND '64' TO mt_multiplication_lookup_11.
    APPEND '6F' TO mt_multiplication_lookup_11.
    APPEND '72' TO mt_multiplication_lookup_11.
    APPEND '79' TO mt_multiplication_lookup_11.
    APPEND '48' TO mt_multiplication_lookup_11.
    APPEND '43' TO mt_multiplication_lookup_11.
    APPEND '5E' TO mt_multiplication_lookup_11.
    APPEND '55' TO mt_multiplication_lookup_11.
    APPEND '01' TO mt_multiplication_lookup_11.
    APPEND '0A' TO mt_multiplication_lookup_11.
    APPEND '17' TO mt_multiplication_lookup_11.
    APPEND '1C' TO mt_multiplication_lookup_11.
    APPEND '2D' TO mt_multiplication_lookup_11.
    APPEND '26' TO mt_multiplication_lookup_11.
    APPEND '3B' TO mt_multiplication_lookup_11.
    APPEND '30' TO mt_multiplication_lookup_11.
    APPEND '59' TO mt_multiplication_lookup_11.
    APPEND '52' TO mt_multiplication_lookup_11.
    APPEND '4F' TO mt_multiplication_lookup_11.
    APPEND '44' TO mt_multiplication_lookup_11.
    APPEND '75' TO mt_multiplication_lookup_11.
    APPEND '7E' TO mt_multiplication_lookup_11.
    APPEND '63' TO mt_multiplication_lookup_11.
    APPEND '68' TO mt_multiplication_lookup_11.
    APPEND 'B1' TO mt_multiplication_lookup_11.
    APPEND 'BA' TO mt_multiplication_lookup_11.
    APPEND 'A7' TO mt_multiplication_lookup_11.
    APPEND 'AC' TO mt_multiplication_lookup_11.
    APPEND '9D' TO mt_multiplication_lookup_11.
    APPEND '96' TO mt_multiplication_lookup_11.
    APPEND '8B' TO mt_multiplication_lookup_11.
    APPEND '80' TO mt_multiplication_lookup_11.
    APPEND 'E9' TO mt_multiplication_lookup_11.
    APPEND 'E2' TO mt_multiplication_lookup_11.
    APPEND 'FF' TO mt_multiplication_lookup_11.
    APPEND 'F4' TO mt_multiplication_lookup_11.
    APPEND 'C5' TO mt_multiplication_lookup_11.
    APPEND 'CE' TO mt_multiplication_lookup_11.
    APPEND 'D3' TO mt_multiplication_lookup_11.
    APPEND 'D8' TO mt_multiplication_lookup_11.
    APPEND '7A' TO mt_multiplication_lookup_11.
    APPEND '71' TO mt_multiplication_lookup_11.
    APPEND '6C' TO mt_multiplication_lookup_11.
    APPEND '67' TO mt_multiplication_lookup_11.
    APPEND '56' TO mt_multiplication_lookup_11.
    APPEND '5D' TO mt_multiplication_lookup_11.
    APPEND '40' TO mt_multiplication_lookup_11.
    APPEND '4B' TO mt_multiplication_lookup_11.
    APPEND '22' TO mt_multiplication_lookup_11.
    APPEND '29' TO mt_multiplication_lookup_11.
    APPEND '34' TO mt_multiplication_lookup_11.
    APPEND '3F' TO mt_multiplication_lookup_11.
    APPEND '0E' TO mt_multiplication_lookup_11.
    APPEND '05' TO mt_multiplication_lookup_11.
    APPEND '18' TO mt_multiplication_lookup_11.
    APPEND '13' TO mt_multiplication_lookup_11.
    APPEND 'CA' TO mt_multiplication_lookup_11.
    APPEND 'C1' TO mt_multiplication_lookup_11.
    APPEND 'DC' TO mt_multiplication_lookup_11.
    APPEND 'D7' TO mt_multiplication_lookup_11.
    APPEND 'E6' TO mt_multiplication_lookup_11.
    APPEND 'ED' TO mt_multiplication_lookup_11.
    APPEND 'F0' TO mt_multiplication_lookup_11.
    APPEND 'FB' TO mt_multiplication_lookup_11.
    APPEND '92' TO mt_multiplication_lookup_11.
    APPEND '99' TO mt_multiplication_lookup_11.
    APPEND '84' TO mt_multiplication_lookup_11.
    APPEND '8F' TO mt_multiplication_lookup_11.
    APPEND 'BE' TO mt_multiplication_lookup_11.
    APPEND 'B5' TO mt_multiplication_lookup_11.
    APPEND 'A8' TO mt_multiplication_lookup_11.
    APPEND 'A3' TO mt_multiplication_lookup_11.

    "Build Multiplication Table for 13
    APPEND '00' TO mt_multiplication_lookup_13.
    APPEND '0D' TO mt_multiplication_lookup_13.
    APPEND '1A' TO mt_multiplication_lookup_13.
    APPEND '17' TO mt_multiplication_lookup_13.
    APPEND '34' TO mt_multiplication_lookup_13.
    APPEND '39' TO mt_multiplication_lookup_13.
    APPEND '2E' TO mt_multiplication_lookup_13.
    APPEND '23' TO mt_multiplication_lookup_13.
    APPEND '68' TO mt_multiplication_lookup_13.
    APPEND '65' TO mt_multiplication_lookup_13.
    APPEND '72' TO mt_multiplication_lookup_13.
    APPEND '7F' TO mt_multiplication_lookup_13.
    APPEND '5C' TO mt_multiplication_lookup_13.
    APPEND '51' TO mt_multiplication_lookup_13.
    APPEND '46' TO mt_multiplication_lookup_13.
    APPEND '4B' TO mt_multiplication_lookup_13.
    APPEND 'D0' TO mt_multiplication_lookup_13.
    APPEND 'DD' TO mt_multiplication_lookup_13.
    APPEND 'CA' TO mt_multiplication_lookup_13.
    APPEND 'C7' TO mt_multiplication_lookup_13.
    APPEND 'E4' TO mt_multiplication_lookup_13.
    APPEND 'E9' TO mt_multiplication_lookup_13.
    APPEND 'FE' TO mt_multiplication_lookup_13.
    APPEND 'F3' TO mt_multiplication_lookup_13.
    APPEND 'B8' TO mt_multiplication_lookup_13.
    APPEND 'B5' TO mt_multiplication_lookup_13.
    APPEND 'A2' TO mt_multiplication_lookup_13.
    APPEND 'AF' TO mt_multiplication_lookup_13.
    APPEND '8C' TO mt_multiplication_lookup_13.
    APPEND '81' TO mt_multiplication_lookup_13.
    APPEND '96' TO mt_multiplication_lookup_13.
    APPEND '9B' TO mt_multiplication_lookup_13.
    APPEND 'BB' TO mt_multiplication_lookup_13.
    APPEND 'B6' TO mt_multiplication_lookup_13.
    APPEND 'A1' TO mt_multiplication_lookup_13.
    APPEND 'AC' TO mt_multiplication_lookup_13.
    APPEND '8F' TO mt_multiplication_lookup_13.
    APPEND '82' TO mt_multiplication_lookup_13.
    APPEND '95' TO mt_multiplication_lookup_13.
    APPEND '98' TO mt_multiplication_lookup_13.
    APPEND 'D3' TO mt_multiplication_lookup_13.
    APPEND 'DE' TO mt_multiplication_lookup_13.
    APPEND 'C9' TO mt_multiplication_lookup_13.
    APPEND 'C4' TO mt_multiplication_lookup_13.
    APPEND 'E7' TO mt_multiplication_lookup_13.
    APPEND 'EA' TO mt_multiplication_lookup_13.
    APPEND 'FD' TO mt_multiplication_lookup_13.
    APPEND 'F0' TO mt_multiplication_lookup_13.
    APPEND '6B' TO mt_multiplication_lookup_13.
    APPEND '66' TO mt_multiplication_lookup_13.
    APPEND '71' TO mt_multiplication_lookup_13.
    APPEND '7C' TO mt_multiplication_lookup_13.
    APPEND '5F' TO mt_multiplication_lookup_13.
    APPEND '52' TO mt_multiplication_lookup_13.
    APPEND '45' TO mt_multiplication_lookup_13.
    APPEND '48' TO mt_multiplication_lookup_13.
    APPEND '03' TO mt_multiplication_lookup_13.
    APPEND '0E' TO mt_multiplication_lookup_13.
    APPEND '19' TO mt_multiplication_lookup_13.
    APPEND '14' TO mt_multiplication_lookup_13.
    APPEND '37' TO mt_multiplication_lookup_13.
    APPEND '3A' TO mt_multiplication_lookup_13.
    APPEND '2D' TO mt_multiplication_lookup_13.
    APPEND '20' TO mt_multiplication_lookup_13.
    APPEND '6D' TO mt_multiplication_lookup_13.
    APPEND '60' TO mt_multiplication_lookup_13.
    APPEND '77' TO mt_multiplication_lookup_13.
    APPEND '7A' TO mt_multiplication_lookup_13.
    APPEND '59' TO mt_multiplication_lookup_13.
    APPEND '54' TO mt_multiplication_lookup_13.
    APPEND '43' TO mt_multiplication_lookup_13.
    APPEND '4E' TO mt_multiplication_lookup_13.
    APPEND '05' TO mt_multiplication_lookup_13.
    APPEND '08' TO mt_multiplication_lookup_13.
    APPEND '1F' TO mt_multiplication_lookup_13.
    APPEND '12' TO mt_multiplication_lookup_13.
    APPEND '31' TO mt_multiplication_lookup_13.
    APPEND '3C' TO mt_multiplication_lookup_13.
    APPEND '2B' TO mt_multiplication_lookup_13.
    APPEND '26' TO mt_multiplication_lookup_13.
    APPEND 'BD' TO mt_multiplication_lookup_13.
    APPEND 'B0' TO mt_multiplication_lookup_13.
    APPEND 'A7' TO mt_multiplication_lookup_13.
    APPEND 'AA' TO mt_multiplication_lookup_13.
    APPEND '89' TO mt_multiplication_lookup_13.
    APPEND '84' TO mt_multiplication_lookup_13.
    APPEND '93' TO mt_multiplication_lookup_13.
    APPEND '9E' TO mt_multiplication_lookup_13.
    APPEND 'D5' TO mt_multiplication_lookup_13.
    APPEND 'D8' TO mt_multiplication_lookup_13.
    APPEND 'CF' TO mt_multiplication_lookup_13.
    APPEND 'C2' TO mt_multiplication_lookup_13.
    APPEND 'E1' TO mt_multiplication_lookup_13.
    APPEND 'EC' TO mt_multiplication_lookup_13.
    APPEND 'FB' TO mt_multiplication_lookup_13.
    APPEND 'F6' TO mt_multiplication_lookup_13.
    APPEND 'D6' TO mt_multiplication_lookup_13.
    APPEND 'DB' TO mt_multiplication_lookup_13.
    APPEND 'CC' TO mt_multiplication_lookup_13.
    APPEND 'C1' TO mt_multiplication_lookup_13.
    APPEND 'E2' TO mt_multiplication_lookup_13.
    APPEND 'EF' TO mt_multiplication_lookup_13.
    APPEND 'F8' TO mt_multiplication_lookup_13.
    APPEND 'F5' TO mt_multiplication_lookup_13.
    APPEND 'BE' TO mt_multiplication_lookup_13.
    APPEND 'B3' TO mt_multiplication_lookup_13.
    APPEND 'A4' TO mt_multiplication_lookup_13.
    APPEND 'A9' TO mt_multiplication_lookup_13.
    APPEND '8A' TO mt_multiplication_lookup_13.
    APPEND '87' TO mt_multiplication_lookup_13.
    APPEND '90' TO mt_multiplication_lookup_13.
    APPEND '9D' TO mt_multiplication_lookup_13.
    APPEND '06' TO mt_multiplication_lookup_13.
    APPEND '0B' TO mt_multiplication_lookup_13.
    APPEND '1C' TO mt_multiplication_lookup_13.
    APPEND '11' TO mt_multiplication_lookup_13.
    APPEND '32' TO mt_multiplication_lookup_13.
    APPEND '3F' TO mt_multiplication_lookup_13.
    APPEND '28' TO mt_multiplication_lookup_13.
    APPEND '25' TO mt_multiplication_lookup_13.
    APPEND '6E' TO mt_multiplication_lookup_13.
    APPEND '63' TO mt_multiplication_lookup_13.
    APPEND '74' TO mt_multiplication_lookup_13.
    APPEND '79' TO mt_multiplication_lookup_13.
    APPEND '5A' TO mt_multiplication_lookup_13.
    APPEND '57' TO mt_multiplication_lookup_13.
    APPEND '40' TO mt_multiplication_lookup_13.
    APPEND '4D' TO mt_multiplication_lookup_13.
    APPEND 'DA' TO mt_multiplication_lookup_13.
    APPEND 'D7' TO mt_multiplication_lookup_13.
    APPEND 'C0' TO mt_multiplication_lookup_13.
    APPEND 'CD' TO mt_multiplication_lookup_13.
    APPEND 'EE' TO mt_multiplication_lookup_13.
    APPEND 'E3' TO mt_multiplication_lookup_13.
    APPEND 'F4' TO mt_multiplication_lookup_13.
    APPEND 'F9' TO mt_multiplication_lookup_13.
    APPEND 'B2' TO mt_multiplication_lookup_13.
    APPEND 'BF' TO mt_multiplication_lookup_13.
    APPEND 'A8' TO mt_multiplication_lookup_13.
    APPEND 'A5' TO mt_multiplication_lookup_13.
    APPEND '86' TO mt_multiplication_lookup_13.
    APPEND '8B' TO mt_multiplication_lookup_13.
    APPEND '9C' TO mt_multiplication_lookup_13.
    APPEND '91' TO mt_multiplication_lookup_13.
    APPEND '0A' TO mt_multiplication_lookup_13.
    APPEND '07' TO mt_multiplication_lookup_13.
    APPEND '10' TO mt_multiplication_lookup_13.
    APPEND '1D' TO mt_multiplication_lookup_13.
    APPEND '3E' TO mt_multiplication_lookup_13.
    APPEND '33' TO mt_multiplication_lookup_13.
    APPEND '24' TO mt_multiplication_lookup_13.
    APPEND '29' TO mt_multiplication_lookup_13.
    APPEND '62' TO mt_multiplication_lookup_13.
    APPEND '6F' TO mt_multiplication_lookup_13.
    APPEND '78' TO mt_multiplication_lookup_13.
    APPEND '75' TO mt_multiplication_lookup_13.
    APPEND '56' TO mt_multiplication_lookup_13.
    APPEND '5B' TO mt_multiplication_lookup_13.
    APPEND '4C' TO mt_multiplication_lookup_13.
    APPEND '41' TO mt_multiplication_lookup_13.
    APPEND '61' TO mt_multiplication_lookup_13.
    APPEND '6C' TO mt_multiplication_lookup_13.
    APPEND '7B' TO mt_multiplication_lookup_13.
    APPEND '76' TO mt_multiplication_lookup_13.
    APPEND '55' TO mt_multiplication_lookup_13.
    APPEND '58' TO mt_multiplication_lookup_13.
    APPEND '4F' TO mt_multiplication_lookup_13.
    APPEND '42' TO mt_multiplication_lookup_13.
    APPEND '09' TO mt_multiplication_lookup_13.
    APPEND '04' TO mt_multiplication_lookup_13.
    APPEND '13' TO mt_multiplication_lookup_13.
    APPEND '1E' TO mt_multiplication_lookup_13.
    APPEND '3D' TO mt_multiplication_lookup_13.
    APPEND '30' TO mt_multiplication_lookup_13.
    APPEND '27' TO mt_multiplication_lookup_13.
    APPEND '2A' TO mt_multiplication_lookup_13.
    APPEND 'B1' TO mt_multiplication_lookup_13.
    APPEND 'BC' TO mt_multiplication_lookup_13.
    APPEND 'AB' TO mt_multiplication_lookup_13.
    APPEND 'A6' TO mt_multiplication_lookup_13.
    APPEND '85' TO mt_multiplication_lookup_13.
    APPEND '88' TO mt_multiplication_lookup_13.
    APPEND '9F' TO mt_multiplication_lookup_13.
    APPEND '92' TO mt_multiplication_lookup_13.
    APPEND 'D9' TO mt_multiplication_lookup_13.
    APPEND 'D4' TO mt_multiplication_lookup_13.
    APPEND 'C3' TO mt_multiplication_lookup_13.
    APPEND 'CE' TO mt_multiplication_lookup_13.
    APPEND 'ED' TO mt_multiplication_lookup_13.
    APPEND 'E0' TO mt_multiplication_lookup_13.
    APPEND 'F7' TO mt_multiplication_lookup_13.
    APPEND 'FA' TO mt_multiplication_lookup_13.
    APPEND 'B7' TO mt_multiplication_lookup_13.
    APPEND 'BA' TO mt_multiplication_lookup_13.
    APPEND 'AD' TO mt_multiplication_lookup_13.
    APPEND 'A0' TO mt_multiplication_lookup_13.
    APPEND '83' TO mt_multiplication_lookup_13.
    APPEND '8E' TO mt_multiplication_lookup_13.
    APPEND '99' TO mt_multiplication_lookup_13.
    APPEND '94' TO mt_multiplication_lookup_13.
    APPEND 'DF' TO mt_multiplication_lookup_13.
    APPEND 'D2' TO mt_multiplication_lookup_13.
    APPEND 'C5' TO mt_multiplication_lookup_13.
    APPEND 'C8' TO mt_multiplication_lookup_13.
    APPEND 'EB' TO mt_multiplication_lookup_13.
    APPEND 'E6' TO mt_multiplication_lookup_13.
    APPEND 'F1' TO mt_multiplication_lookup_13.
    APPEND 'FC' TO mt_multiplication_lookup_13.
    APPEND '67' TO mt_multiplication_lookup_13.
    APPEND '6A' TO mt_multiplication_lookup_13.
    APPEND '7D' TO mt_multiplication_lookup_13.
    APPEND '70' TO mt_multiplication_lookup_13.
    APPEND '53' TO mt_multiplication_lookup_13.
    APPEND '5E' TO mt_multiplication_lookup_13.
    APPEND '49' TO mt_multiplication_lookup_13.
    APPEND '44' TO mt_multiplication_lookup_13.
    APPEND '0F' TO mt_multiplication_lookup_13.
    APPEND '02' TO mt_multiplication_lookup_13.
    APPEND '15' TO mt_multiplication_lookup_13.
    APPEND '18' TO mt_multiplication_lookup_13.
    APPEND '3B' TO mt_multiplication_lookup_13.
    APPEND '36' TO mt_multiplication_lookup_13.
    APPEND '21' TO mt_multiplication_lookup_13.
    APPEND '2C' TO mt_multiplication_lookup_13.
    APPEND '0C' TO mt_multiplication_lookup_13.
    APPEND '01' TO mt_multiplication_lookup_13.
    APPEND '16' TO mt_multiplication_lookup_13.
    APPEND '1B' TO mt_multiplication_lookup_13.
    APPEND '38' TO mt_multiplication_lookup_13.
    APPEND '35' TO mt_multiplication_lookup_13.
    APPEND '22' TO mt_multiplication_lookup_13.
    APPEND '2F' TO mt_multiplication_lookup_13.
    APPEND '64' TO mt_multiplication_lookup_13.
    APPEND '69' TO mt_multiplication_lookup_13.
    APPEND '7E' TO mt_multiplication_lookup_13.
    APPEND '73' TO mt_multiplication_lookup_13.
    APPEND '50' TO mt_multiplication_lookup_13.
    APPEND '5D' TO mt_multiplication_lookup_13.
    APPEND '4A' TO mt_multiplication_lookup_13.
    APPEND '47' TO mt_multiplication_lookup_13.
    APPEND 'DC' TO mt_multiplication_lookup_13.
    APPEND 'D1' TO mt_multiplication_lookup_13.
    APPEND 'C6' TO mt_multiplication_lookup_13.
    APPEND 'CB' TO mt_multiplication_lookup_13.
    APPEND 'E8' TO mt_multiplication_lookup_13.
    APPEND 'E5' TO mt_multiplication_lookup_13.
    APPEND 'F2' TO mt_multiplication_lookup_13.
    APPEND 'FF' TO mt_multiplication_lookup_13.
    APPEND 'B4' TO mt_multiplication_lookup_13.
    APPEND 'B9' TO mt_multiplication_lookup_13.
    APPEND 'AE' TO mt_multiplication_lookup_13.
    APPEND 'A3' TO mt_multiplication_lookup_13.
    APPEND '80' TO mt_multiplication_lookup_13.
    APPEND '8D' TO mt_multiplication_lookup_13.
    APPEND '9A' TO mt_multiplication_lookup_13.
    APPEND '97' TO mt_multiplication_lookup_13.

    "Build Multiplication Table for 14
    APPEND '00' TO mt_multiplication_lookup_14.
    APPEND '0E' TO mt_multiplication_lookup_14.
    APPEND '1C' TO mt_multiplication_lookup_14.
    APPEND '12' TO mt_multiplication_lookup_14.
    APPEND '38' TO mt_multiplication_lookup_14.
    APPEND '36' TO mt_multiplication_lookup_14.
    APPEND '24' TO mt_multiplication_lookup_14.
    APPEND '2A' TO mt_multiplication_lookup_14.
    APPEND '70' TO mt_multiplication_lookup_14.
    APPEND '7E' TO mt_multiplication_lookup_14.
    APPEND '6C' TO mt_multiplication_lookup_14.
    APPEND '62' TO mt_multiplication_lookup_14.
    APPEND '48' TO mt_multiplication_lookup_14.
    APPEND '46' TO mt_multiplication_lookup_14.
    APPEND '54' TO mt_multiplication_lookup_14.
    APPEND '5A' TO mt_multiplication_lookup_14.
    APPEND 'E0' TO mt_multiplication_lookup_14.
    APPEND 'EE' TO mt_multiplication_lookup_14.
    APPEND 'FC' TO mt_multiplication_lookup_14.
    APPEND 'F2' TO mt_multiplication_lookup_14.
    APPEND 'D8' TO mt_multiplication_lookup_14.
    APPEND 'D6' TO mt_multiplication_lookup_14.
    APPEND 'C4' TO mt_multiplication_lookup_14.
    APPEND 'CA' TO mt_multiplication_lookup_14.
    APPEND '90' TO mt_multiplication_lookup_14.
    APPEND '9E' TO mt_multiplication_lookup_14.
    APPEND '8C' TO mt_multiplication_lookup_14.
    APPEND '82' TO mt_multiplication_lookup_14.
    APPEND 'A8' TO mt_multiplication_lookup_14.
    APPEND 'A6' TO mt_multiplication_lookup_14.
    APPEND 'B4' TO mt_multiplication_lookup_14.
    APPEND 'BA' TO mt_multiplication_lookup_14.
    APPEND 'DB' TO mt_multiplication_lookup_14.
    APPEND 'D5' TO mt_multiplication_lookup_14.
    APPEND 'C7' TO mt_multiplication_lookup_14.
    APPEND 'C9' TO mt_multiplication_lookup_14.
    APPEND 'E3' TO mt_multiplication_lookup_14.
    APPEND 'ED' TO mt_multiplication_lookup_14.
    APPEND 'FF' TO mt_multiplication_lookup_14.
    APPEND 'F1' TO mt_multiplication_lookup_14.
    APPEND 'AB' TO mt_multiplication_lookup_14.
    APPEND 'A5' TO mt_multiplication_lookup_14.
    APPEND 'B7' TO mt_multiplication_lookup_14.
    APPEND 'B9' TO mt_multiplication_lookup_14.
    APPEND '93' TO mt_multiplication_lookup_14.
    APPEND '9D' TO mt_multiplication_lookup_14.
    APPEND '8F' TO mt_multiplication_lookup_14.
    APPEND '81' TO mt_multiplication_lookup_14.
    APPEND '3B' TO mt_multiplication_lookup_14.
    APPEND '35' TO mt_multiplication_lookup_14.
    APPEND '27' TO mt_multiplication_lookup_14.
    APPEND '29' TO mt_multiplication_lookup_14.
    APPEND '03' TO mt_multiplication_lookup_14.
    APPEND '0D' TO mt_multiplication_lookup_14.
    APPEND '1F' TO mt_multiplication_lookup_14.
    APPEND '11' TO mt_multiplication_lookup_14.
    APPEND '4B' TO mt_multiplication_lookup_14.
    APPEND '45' TO mt_multiplication_lookup_14.
    APPEND '57' TO mt_multiplication_lookup_14.
    APPEND '59' TO mt_multiplication_lookup_14.
    APPEND '73' TO mt_multiplication_lookup_14.
    APPEND '7D' TO mt_multiplication_lookup_14.
    APPEND '6F' TO mt_multiplication_lookup_14.
    APPEND '61' TO mt_multiplication_lookup_14.
    APPEND 'AD' TO mt_multiplication_lookup_14.
    APPEND 'A3' TO mt_multiplication_lookup_14.
    APPEND 'B1' TO mt_multiplication_lookup_14.
    APPEND 'BF' TO mt_multiplication_lookup_14.
    APPEND '95' TO mt_multiplication_lookup_14.
    APPEND '9B' TO mt_multiplication_lookup_14.
    APPEND '89' TO mt_multiplication_lookup_14.
    APPEND '87' TO mt_multiplication_lookup_14.
    APPEND 'DD' TO mt_multiplication_lookup_14.
    APPEND 'D3' TO mt_multiplication_lookup_14.
    APPEND 'C1' TO mt_multiplication_lookup_14.
    APPEND 'CF' TO mt_multiplication_lookup_14.
    APPEND 'E5' TO mt_multiplication_lookup_14.
    APPEND 'EB' TO mt_multiplication_lookup_14.
    APPEND 'F9' TO mt_multiplication_lookup_14.
    APPEND 'F7' TO mt_multiplication_lookup_14.
    APPEND '4D' TO mt_multiplication_lookup_14.
    APPEND '43' TO mt_multiplication_lookup_14.
    APPEND '51' TO mt_multiplication_lookup_14.
    APPEND '5F' TO mt_multiplication_lookup_14.
    APPEND '75' TO mt_multiplication_lookup_14.
    APPEND '7B' TO mt_multiplication_lookup_14.
    APPEND '69' TO mt_multiplication_lookup_14.
    APPEND '67' TO mt_multiplication_lookup_14.
    APPEND '3D' TO mt_multiplication_lookup_14.
    APPEND '33' TO mt_multiplication_lookup_14.
    APPEND '21' TO mt_multiplication_lookup_14.
    APPEND '2F' TO mt_multiplication_lookup_14.
    APPEND '05' TO mt_multiplication_lookup_14.
    APPEND '0B' TO mt_multiplication_lookup_14.
    APPEND '19' TO mt_multiplication_lookup_14.
    APPEND '17' TO mt_multiplication_lookup_14.
    APPEND '76' TO mt_multiplication_lookup_14.
    APPEND '78' TO mt_multiplication_lookup_14.
    APPEND '6A' TO mt_multiplication_lookup_14.
    APPEND '64' TO mt_multiplication_lookup_14.
    APPEND '4E' TO mt_multiplication_lookup_14.
    APPEND '40' TO mt_multiplication_lookup_14.
    APPEND '52' TO mt_multiplication_lookup_14.
    APPEND '5C' TO mt_multiplication_lookup_14.
    APPEND '06' TO mt_multiplication_lookup_14.
    APPEND '08' TO mt_multiplication_lookup_14.
    APPEND '1A' TO mt_multiplication_lookup_14.
    APPEND '14' TO mt_multiplication_lookup_14.
    APPEND '3E' TO mt_multiplication_lookup_14.
    APPEND '30' TO mt_multiplication_lookup_14.
    APPEND '22' TO mt_multiplication_lookup_14.
    APPEND '2C' TO mt_multiplication_lookup_14.
    APPEND '96' TO mt_multiplication_lookup_14.
    APPEND '98' TO mt_multiplication_lookup_14.
    APPEND '8A' TO mt_multiplication_lookup_14.
    APPEND '84' TO mt_multiplication_lookup_14.
    APPEND 'AE' TO mt_multiplication_lookup_14.
    APPEND 'A0' TO mt_multiplication_lookup_14.
    APPEND 'B2' TO mt_multiplication_lookup_14.
    APPEND 'BC' TO mt_multiplication_lookup_14.
    APPEND 'E6' TO mt_multiplication_lookup_14.
    APPEND 'E8' TO mt_multiplication_lookup_14.
    APPEND 'FA' TO mt_multiplication_lookup_14.
    APPEND 'F4' TO mt_multiplication_lookup_14.
    APPEND 'DE' TO mt_multiplication_lookup_14.
    APPEND 'D0' TO mt_multiplication_lookup_14.
    APPEND 'C2' TO mt_multiplication_lookup_14.
    APPEND 'CC' TO mt_multiplication_lookup_14.
    APPEND '41' TO mt_multiplication_lookup_14.
    APPEND '4F' TO mt_multiplication_lookup_14.
    APPEND '5D' TO mt_multiplication_lookup_14.
    APPEND '53' TO mt_multiplication_lookup_14.
    APPEND '79' TO mt_multiplication_lookup_14.
    APPEND '77' TO mt_multiplication_lookup_14.
    APPEND '65' TO mt_multiplication_lookup_14.
    APPEND '6B' TO mt_multiplication_lookup_14.
    APPEND '31' TO mt_multiplication_lookup_14.
    APPEND '3F' TO mt_multiplication_lookup_14.
    APPEND '2D' TO mt_multiplication_lookup_14.
    APPEND '23' TO mt_multiplication_lookup_14.
    APPEND '09' TO mt_multiplication_lookup_14.
    APPEND '07' TO mt_multiplication_lookup_14.
    APPEND '15' TO mt_multiplication_lookup_14.
    APPEND '1B' TO mt_multiplication_lookup_14.
    APPEND 'A1' TO mt_multiplication_lookup_14.
    APPEND 'AF' TO mt_multiplication_lookup_14.
    APPEND 'BD' TO mt_multiplication_lookup_14.
    APPEND 'B3' TO mt_multiplication_lookup_14.
    APPEND '99' TO mt_multiplication_lookup_14.
    APPEND '97' TO mt_multiplication_lookup_14.
    APPEND '85' TO mt_multiplication_lookup_14.
    APPEND '8B' TO mt_multiplication_lookup_14.
    APPEND 'D1' TO mt_multiplication_lookup_14.
    APPEND 'DF' TO mt_multiplication_lookup_14.
    APPEND 'CD' TO mt_multiplication_lookup_14.
    APPEND 'C3' TO mt_multiplication_lookup_14.
    APPEND 'E9' TO mt_multiplication_lookup_14.
    APPEND 'E7' TO mt_multiplication_lookup_14.
    APPEND 'F5' TO mt_multiplication_lookup_14.
    APPEND 'FB' TO mt_multiplication_lookup_14.
    APPEND '9A' TO mt_multiplication_lookup_14.
    APPEND '94' TO mt_multiplication_lookup_14.
    APPEND '86' TO mt_multiplication_lookup_14.
    APPEND '88' TO mt_multiplication_lookup_14.
    APPEND 'A2' TO mt_multiplication_lookup_14.
    APPEND 'AC' TO mt_multiplication_lookup_14.
    APPEND 'BE' TO mt_multiplication_lookup_14.
    APPEND 'B0' TO mt_multiplication_lookup_14.
    APPEND 'EA' TO mt_multiplication_lookup_14.
    APPEND 'E4' TO mt_multiplication_lookup_14.
    APPEND 'F6' TO mt_multiplication_lookup_14.
    APPEND 'F8' TO mt_multiplication_lookup_14.
    APPEND 'D2' TO mt_multiplication_lookup_14.
    APPEND 'DC' TO mt_multiplication_lookup_14.
    APPEND 'CE' TO mt_multiplication_lookup_14.
    APPEND 'C0' TO mt_multiplication_lookup_14.
    APPEND '7A' TO mt_multiplication_lookup_14.
    APPEND '74' TO mt_multiplication_lookup_14.
    APPEND '66' TO mt_multiplication_lookup_14.
    APPEND '68' TO mt_multiplication_lookup_14.
    APPEND '42' TO mt_multiplication_lookup_14.
    APPEND '4C' TO mt_multiplication_lookup_14.
    APPEND '5E' TO mt_multiplication_lookup_14.
    APPEND '50' TO mt_multiplication_lookup_14.
    APPEND '0A' TO mt_multiplication_lookup_14.
    APPEND '04' TO mt_multiplication_lookup_14.
    APPEND '16' TO mt_multiplication_lookup_14.
    APPEND '18' TO mt_multiplication_lookup_14.
    APPEND '32' TO mt_multiplication_lookup_14.
    APPEND '3C' TO mt_multiplication_lookup_14.
    APPEND '2E' TO mt_multiplication_lookup_14.
    APPEND '20' TO mt_multiplication_lookup_14.
    APPEND 'EC' TO mt_multiplication_lookup_14.
    APPEND 'E2' TO mt_multiplication_lookup_14.
    APPEND 'F0' TO mt_multiplication_lookup_14.
    APPEND 'FE' TO mt_multiplication_lookup_14.
    APPEND 'D4' TO mt_multiplication_lookup_14.
    APPEND 'DA' TO mt_multiplication_lookup_14.
    APPEND 'C8' TO mt_multiplication_lookup_14.
    APPEND 'C6' TO mt_multiplication_lookup_14.
    APPEND '9C' TO mt_multiplication_lookup_14.
    APPEND '92' TO mt_multiplication_lookup_14.
    APPEND '80' TO mt_multiplication_lookup_14.
    APPEND '8E' TO mt_multiplication_lookup_14.
    APPEND 'A4' TO mt_multiplication_lookup_14.
    APPEND 'AA' TO mt_multiplication_lookup_14.
    APPEND 'B8' TO mt_multiplication_lookup_14.
    APPEND 'B6' TO mt_multiplication_lookup_14.
    APPEND '0C' TO mt_multiplication_lookup_14.
    APPEND '02' TO mt_multiplication_lookup_14.
    APPEND '10' TO mt_multiplication_lookup_14.
    APPEND '1E' TO mt_multiplication_lookup_14.
    APPEND '34' TO mt_multiplication_lookup_14.
    APPEND '3A' TO mt_multiplication_lookup_14.
    APPEND '28' TO mt_multiplication_lookup_14.
    APPEND '26' TO mt_multiplication_lookup_14.
    APPEND '7C' TO mt_multiplication_lookup_14.
    APPEND '72' TO mt_multiplication_lookup_14.
    APPEND '60' TO mt_multiplication_lookup_14.
    APPEND '6E' TO mt_multiplication_lookup_14.
    APPEND '44' TO mt_multiplication_lookup_14.
    APPEND '4A' TO mt_multiplication_lookup_14.
    APPEND '58' TO mt_multiplication_lookup_14.
    APPEND '56' TO mt_multiplication_lookup_14.
    APPEND '37' TO mt_multiplication_lookup_14.
    APPEND '39' TO mt_multiplication_lookup_14.
    APPEND '2B' TO mt_multiplication_lookup_14.
    APPEND '25' TO mt_multiplication_lookup_14.
    APPEND '0F' TO mt_multiplication_lookup_14.
    APPEND '01' TO mt_multiplication_lookup_14.
    APPEND '13' TO mt_multiplication_lookup_14.
    APPEND '1D' TO mt_multiplication_lookup_14.
    APPEND '47' TO mt_multiplication_lookup_14.
    APPEND '49' TO mt_multiplication_lookup_14.
    APPEND '5B' TO mt_multiplication_lookup_14.
    APPEND '55' TO mt_multiplication_lookup_14.
    APPEND '7F' TO mt_multiplication_lookup_14.
    APPEND '71' TO mt_multiplication_lookup_14.
    APPEND '63' TO mt_multiplication_lookup_14.
    APPEND '6D' TO mt_multiplication_lookup_14.
    APPEND 'D7' TO mt_multiplication_lookup_14.
    APPEND 'D9' TO mt_multiplication_lookup_14.
    APPEND 'CB' TO mt_multiplication_lookup_14.
    APPEND 'C5' TO mt_multiplication_lookup_14.
    APPEND 'EF' TO mt_multiplication_lookup_14.
    APPEND 'E1' TO mt_multiplication_lookup_14.
    APPEND 'F3' TO mt_multiplication_lookup_14.
    APPEND 'FD' TO mt_multiplication_lookup_14.
    APPEND 'A7' TO mt_multiplication_lookup_14.
    APPEND 'A9' TO mt_multiplication_lookup_14.
    APPEND 'BB' TO mt_multiplication_lookup_14.
    APPEND 'B5' TO mt_multiplication_lookup_14.
    APPEND '9F' TO mt_multiplication_lookup_14.
    APPEND '91' TO mt_multiplication_lookup_14.
    APPEND '83' TO mt_multiplication_lookup_14.
    APPEND '8D' TO mt_multiplication_lookup_14.

  ENDMETHOD.                    "_build_multiplication


  METHOD _build_rcon.
    APPEND '8D' TO mt_rcon.
    APPEND '01' TO mt_rcon.
    APPEND '02' TO mt_rcon.
    APPEND '04' TO mt_rcon.
    APPEND '08' TO mt_rcon.
    APPEND '10' TO mt_rcon.
    APPEND '20' TO mt_rcon.
    APPEND '40' TO mt_rcon.
    APPEND '80' TO mt_rcon.
    APPEND '1B' TO mt_rcon.
    APPEND '36' TO mt_rcon.
    APPEND '6C' TO mt_rcon.
    APPEND 'D8' TO mt_rcon.
    APPEND 'AB' TO mt_rcon.
    APPEND '4D' TO mt_rcon.
    APPEND '9A' TO mt_rcon.
    APPEND '2F' TO mt_rcon.
    APPEND '5E' TO mt_rcon.
    APPEND 'BC' TO mt_rcon.
    APPEND '63' TO mt_rcon.
    APPEND 'C6' TO mt_rcon.
    APPEND '97' TO mt_rcon.
    APPEND '35' TO mt_rcon.
    APPEND '6A' TO mt_rcon.
    APPEND 'D4' TO mt_rcon.
    APPEND 'B3' TO mt_rcon.
    APPEND '7D' TO mt_rcon.
    APPEND 'FA' TO mt_rcon.
    APPEND 'EF' TO mt_rcon.
    APPEND 'C5' TO mt_rcon.
    APPEND '91' TO mt_rcon.
    APPEND '39' TO mt_rcon.
    APPEND '72' TO mt_rcon.
    APPEND 'E4' TO mt_rcon.
    APPEND 'D3' TO mt_rcon.
    APPEND 'BD' TO mt_rcon.
    APPEND '61' TO mt_rcon.
    APPEND 'C2' TO mt_rcon.
    APPEND '9F' TO mt_rcon.
    APPEND '25' TO mt_rcon.
    APPEND '4A' TO mt_rcon.
    APPEND '94' TO mt_rcon.
    APPEND '33' TO mt_rcon.
    APPEND '66' TO mt_rcon.
    APPEND 'CC' TO mt_rcon.
    APPEND '83' TO mt_rcon.
    APPEND '1D' TO mt_rcon.
    APPEND '3A' TO mt_rcon.
    APPEND '74' TO mt_rcon.
    APPEND 'E8' TO mt_rcon.
    APPEND 'CB' TO mt_rcon.
    APPEND '8D' TO mt_rcon.
    APPEND '01' TO mt_rcon.
    APPEND '02' TO mt_rcon.
    APPEND '04' TO mt_rcon.
    APPEND '08' TO mt_rcon.
    APPEND '10' TO mt_rcon.
    APPEND '20' TO mt_rcon.
    APPEND '40' TO mt_rcon.
    APPEND '80' TO mt_rcon.
    APPEND '1B' TO mt_rcon.
    APPEND '36' TO mt_rcon.
    APPEND '6C' TO mt_rcon.
    APPEND 'D8' TO mt_rcon.
    APPEND 'AB' TO mt_rcon.
    APPEND '4D' TO mt_rcon.
    APPEND '9A' TO mt_rcon.
    APPEND '2F' TO mt_rcon.
    APPEND '5E' TO mt_rcon.
    APPEND 'BC' TO mt_rcon.
    APPEND '63' TO mt_rcon.
    APPEND 'C6' TO mt_rcon.
    APPEND '97' TO mt_rcon.
    APPEND '35' TO mt_rcon.
    APPEND '6A' TO mt_rcon.
    APPEND 'D4' TO mt_rcon.
    APPEND 'B3' TO mt_rcon.
    APPEND '7D' TO mt_rcon.
    APPEND 'FA' TO mt_rcon.
    APPEND 'EF' TO mt_rcon.
    APPEND 'C5' TO mt_rcon.
    APPEND '91' TO mt_rcon.
    APPEND '39' TO mt_rcon.
    APPEND '72' TO mt_rcon.
    APPEND 'E4' TO mt_rcon.
    APPEND 'D3' TO mt_rcon.
    APPEND 'BD' TO mt_rcon.
    APPEND '61' TO mt_rcon.
    APPEND 'C2' TO mt_rcon.
    APPEND '9F' TO mt_rcon.
    APPEND '25' TO mt_rcon.
    APPEND '4A' TO mt_rcon.
    APPEND '94' TO mt_rcon.
    APPEND '33' TO mt_rcon.
    APPEND '66' TO mt_rcon.
    APPEND 'CC' TO mt_rcon.
    APPEND '83' TO mt_rcon.
    APPEND '1D' TO mt_rcon.
    APPEND '3A' TO mt_rcon.
    APPEND '74' TO mt_rcon.
    APPEND 'E8' TO mt_rcon.
    APPEND 'CB' TO mt_rcon.
    APPEND '8D' TO mt_rcon.
    APPEND '01' TO mt_rcon.
    APPEND '02' TO mt_rcon.
    APPEND '04' TO mt_rcon.
    APPEND '08' TO mt_rcon.
    APPEND '10' TO mt_rcon.
    APPEND '20' TO mt_rcon.
    APPEND '40' TO mt_rcon.
    APPEND '80' TO mt_rcon.
    APPEND '1B' TO mt_rcon.
    APPEND '36' TO mt_rcon.
    APPEND '6C' TO mt_rcon.
    APPEND 'D8' TO mt_rcon.
    APPEND 'AB' TO mt_rcon.
    APPEND '4D' TO mt_rcon.
    APPEND '9A' TO mt_rcon.
    APPEND '2F' TO mt_rcon.
    APPEND '5E' TO mt_rcon.
    APPEND 'BC' TO mt_rcon.
    APPEND '63' TO mt_rcon.
    APPEND 'C6' TO mt_rcon.
    APPEND '97' TO mt_rcon.
    APPEND '35' TO mt_rcon.
    APPEND '6A' TO mt_rcon.
    APPEND 'D4' TO mt_rcon.
    APPEND 'B3' TO mt_rcon.
    APPEND '7D' TO mt_rcon.
    APPEND 'FA' TO mt_rcon.
    APPEND 'EF' TO mt_rcon.
    APPEND 'C5' TO mt_rcon.
    APPEND '91' TO mt_rcon.
    APPEND '39' TO mt_rcon.
    APPEND '72' TO mt_rcon.
    APPEND 'E4' TO mt_rcon.
    APPEND 'D3' TO mt_rcon.
    APPEND 'BD' TO mt_rcon.
    APPEND '61' TO mt_rcon.
    APPEND 'C2' TO mt_rcon.
    APPEND '9F' TO mt_rcon.
    APPEND '25' TO mt_rcon.
    APPEND '4A' TO mt_rcon.
    APPEND '94' TO mt_rcon.
    APPEND '33' TO mt_rcon.
    APPEND '66' TO mt_rcon.
    APPEND 'CC' TO mt_rcon.
    APPEND '83' TO mt_rcon.
    APPEND '1D' TO mt_rcon.
    APPEND '3A' TO mt_rcon.
    APPEND '74' TO mt_rcon.
    APPEND 'E8' TO mt_rcon.
    APPEND 'CB' TO mt_rcon.
    APPEND '8D' TO mt_rcon.
    APPEND '01' TO mt_rcon.
    APPEND '02' TO mt_rcon.
    APPEND '04' TO mt_rcon.
    APPEND '08' TO mt_rcon.
    APPEND '10' TO mt_rcon.
    APPEND '20' TO mt_rcon.
    APPEND '40' TO mt_rcon.
    APPEND '80' TO mt_rcon.
    APPEND '1B' TO mt_rcon.
    APPEND '36' TO mt_rcon.
    APPEND '6C' TO mt_rcon.
    APPEND 'D8' TO mt_rcon.
    APPEND 'AB' TO mt_rcon.
    APPEND '4D' TO mt_rcon.
    APPEND '9A' TO mt_rcon.
    APPEND '2F' TO mt_rcon.
    APPEND '5E' TO mt_rcon.
    APPEND 'BC' TO mt_rcon.
    APPEND '63' TO mt_rcon.
    APPEND 'C6' TO mt_rcon.
    APPEND '97' TO mt_rcon.
    APPEND '35' TO mt_rcon.
    APPEND '6A' TO mt_rcon.
    APPEND 'D4' TO mt_rcon.
    APPEND 'B3' TO mt_rcon.
    APPEND '7D' TO mt_rcon.
    APPEND 'FA' TO mt_rcon.
    APPEND 'EF' TO mt_rcon.
    APPEND 'C5' TO mt_rcon.
    APPEND '91' TO mt_rcon.
    APPEND '39' TO mt_rcon.
    APPEND '72' TO mt_rcon.
    APPEND 'E4' TO mt_rcon.
    APPEND 'D3' TO mt_rcon.
    APPEND 'BD' TO mt_rcon.
    APPEND '61' TO mt_rcon.
    APPEND 'C2' TO mt_rcon.
    APPEND '9F' TO mt_rcon.
    APPEND '25' TO mt_rcon.
    APPEND '4A' TO mt_rcon.
    APPEND '94' TO mt_rcon.
    APPEND '33' TO mt_rcon.
    APPEND '66' TO mt_rcon.
    APPEND 'CC' TO mt_rcon.
    APPEND '83' TO mt_rcon.
    APPEND '1D' TO mt_rcon.
    APPEND '3A' TO mt_rcon.
    APPEND '74' TO mt_rcon.
    APPEND 'E8' TO mt_rcon.
    APPEND 'CB' TO mt_rcon.
    APPEND '8D' TO mt_rcon.
    APPEND '01' TO mt_rcon.
    APPEND '02' TO mt_rcon.
    APPEND '04' TO mt_rcon.
    APPEND '08' TO mt_rcon.
    APPEND '10' TO mt_rcon.
    APPEND '20' TO mt_rcon.
    APPEND '40' TO mt_rcon.
    APPEND '80' TO mt_rcon.
    APPEND '1B' TO mt_rcon.
    APPEND '36' TO mt_rcon.
    APPEND '6C' TO mt_rcon.
    APPEND 'D8' TO mt_rcon.
    APPEND 'AB' TO mt_rcon.
    APPEND '4D' TO mt_rcon.
    APPEND '9A' TO mt_rcon.
    APPEND '2F' TO mt_rcon.
    APPEND '5E' TO mt_rcon.
    APPEND 'BC' TO mt_rcon.
    APPEND '63' TO mt_rcon.
    APPEND 'C6' TO mt_rcon.
    APPEND '97' TO mt_rcon.
    APPEND '35' TO mt_rcon.
    APPEND '6A' TO mt_rcon.
    APPEND 'D4' TO mt_rcon.
    APPEND 'B3' TO mt_rcon.
    APPEND '7D' TO mt_rcon.
    APPEND 'FA' TO mt_rcon.
    APPEND 'EF' TO mt_rcon.
    APPEND 'C5' TO mt_rcon.
    APPEND '91' TO mt_rcon.
    APPEND '39' TO mt_rcon.
    APPEND '72' TO mt_rcon.
    APPEND 'E4' TO mt_rcon.
    APPEND 'D3' TO mt_rcon.
    APPEND 'BD' TO mt_rcon.
    APPEND '61' TO mt_rcon.
    APPEND 'C2' TO mt_rcon.
    APPEND '9F' TO mt_rcon.
    APPEND '25' TO mt_rcon.
    APPEND '4A' TO mt_rcon.
    APPEND '94' TO mt_rcon.
    APPEND '33' TO mt_rcon.
    APPEND '66' TO mt_rcon.
    APPEND 'CC' TO mt_rcon.
    APPEND '83' TO mt_rcon.
    APPEND '1D' TO mt_rcon.
    APPEND '3A' TO mt_rcon.
    APPEND '74' TO mt_rcon.
    APPEND 'E8' TO mt_rcon.
    APPEND 'CB' TO mt_rcon.
    APPEND '8D' TO mt_rcon.
  ENDMETHOD.                    "_build_rcon


  METHOD _build_row_shift.
    "Block length 4 word
    APPEND  1 TO mt_row_shift_4.
    APPEND  6 TO mt_row_shift_4.
    APPEND 11 TO mt_row_shift_4.
    APPEND 16 TO mt_row_shift_4.
    APPEND  5 TO mt_row_shift_4.
    APPEND 10 TO mt_row_shift_4.
    APPEND 15 TO mt_row_shift_4.
    APPEND  4 TO mt_row_shift_4.
    APPEND  9 TO mt_row_shift_4.
    APPEND 14 TO mt_row_shift_4.
    APPEND  3 TO mt_row_shift_4.
    APPEND  8 TO mt_row_shift_4.
    APPEND 13 TO mt_row_shift_4.
    APPEND  2 TO mt_row_shift_4.
    APPEND  7 TO mt_row_shift_4.
    APPEND 12 TO mt_row_shift_4.

    "Block length 5 word
    APPEND  1 TO mt_row_shift_5.
    APPEND  6 TO mt_row_shift_5.
    APPEND 11 TO mt_row_shift_5.
    APPEND 16 TO mt_row_shift_5.
    APPEND  5 TO mt_row_shift_5.
    APPEND 10 TO mt_row_shift_5.
    APPEND 15 TO mt_row_shift_5.
    APPEND 20 TO mt_row_shift_5.
    APPEND  9 TO mt_row_shift_5.
    APPEND 14 TO mt_row_shift_5.
    APPEND 19 TO mt_row_shift_5.
    APPEND  4 TO mt_row_shift_5.
    APPEND 13 TO mt_row_shift_5.
    APPEND 18 TO mt_row_shift_5.
    APPEND  3 TO mt_row_shift_5.
    APPEND  8 TO mt_row_shift_5.
    APPEND 17 TO mt_row_shift_5.
    APPEND  2 TO mt_row_shift_5.
    APPEND  7 TO mt_row_shift_5.
    APPEND 12 TO mt_row_shift_5.

    "Block length 6 word
    APPEND  1 TO mt_row_shift_6.
    APPEND  6 TO mt_row_shift_6.
    APPEND 11 TO mt_row_shift_6.
    APPEND 16 TO mt_row_shift_6.
    APPEND  5 TO mt_row_shift_6.
    APPEND 10 TO mt_row_shift_6.
    APPEND 15 TO mt_row_shift_6.
    APPEND 20 TO mt_row_shift_6.
    APPEND  9 TO mt_row_shift_6.
    APPEND 14 TO mt_row_shift_6.
    APPEND 19 TO mt_row_shift_6.
    APPEND 24 TO mt_row_shift_6.
    APPEND 13 TO mt_row_shift_6.
    APPEND 18 TO mt_row_shift_6.
    APPEND 23 TO mt_row_shift_6.
    APPEND  4 TO mt_row_shift_6.
    APPEND 17 TO mt_row_shift_6.
    APPEND 22 TO mt_row_shift_6.
    APPEND  3 TO mt_row_shift_6.
    APPEND  8 TO mt_row_shift_6.
    APPEND 21 TO mt_row_shift_6.
    APPEND  2 TO mt_row_shift_6.
    APPEND  7 TO mt_row_shift_6.
    APPEND 12 TO mt_row_shift_6.

    "Block length 7 word
    APPEND  1 TO mt_row_shift_7.
    APPEND  6 TO mt_row_shift_7.
    APPEND 11 TO mt_row_shift_7.
    APPEND 20 TO mt_row_shift_7.
    APPEND  5 TO mt_row_shift_7.
    APPEND 10 TO mt_row_shift_7.
    APPEND 15 TO mt_row_shift_7.
    APPEND 24 TO mt_row_shift_7.
    APPEND  9 TO mt_row_shift_7.
    APPEND 14 TO mt_row_shift_7.
    APPEND 19 TO mt_row_shift_7.
    APPEND 28 TO mt_row_shift_7.
    APPEND 13 TO mt_row_shift_7.
    APPEND 18 TO mt_row_shift_7.
    APPEND 23 TO mt_row_shift_7.
    APPEND  4 TO mt_row_shift_7.
    APPEND 17 TO mt_row_shift_7.
    APPEND 22 TO mt_row_shift_7.
    APPEND 27 TO mt_row_shift_7.
    APPEND  8 TO mt_row_shift_7.
    APPEND 21 TO mt_row_shift_7.
    APPEND 26 TO mt_row_shift_7.
    APPEND  3 TO mt_row_shift_7.
    APPEND 12 TO mt_row_shift_7.
    APPEND 25 TO mt_row_shift_7.
    APPEND  2 TO mt_row_shift_7.
    APPEND  7 TO mt_row_shift_7.
    APPEND 16 TO mt_row_shift_7.

    "Block length 8 word
    APPEND  1 TO mt_row_shift_8.
    APPEND  6 TO mt_row_shift_8.
    APPEND 15 TO mt_row_shift_8.
    APPEND 20 TO mt_row_shift_8.
    APPEND  5 TO mt_row_shift_8.
    APPEND 10 TO mt_row_shift_8.
    APPEND 19 TO mt_row_shift_8.
    APPEND 24 TO mt_row_shift_8.
    APPEND  9 TO mt_row_shift_8.
    APPEND 14 TO mt_row_shift_8.
    APPEND 23 TO mt_row_shift_8.
    APPEND 28 TO mt_row_shift_8.
    APPEND 13 TO mt_row_shift_8.
    APPEND 18 TO mt_row_shift_8.
    APPEND 27 TO mt_row_shift_8.
    APPEND 32 TO mt_row_shift_8.
    APPEND 17 TO mt_row_shift_8.
    APPEND 22 TO mt_row_shift_8.
    APPEND 31 TO mt_row_shift_8.
    APPEND  4 TO mt_row_shift_8.
    APPEND 21 TO mt_row_shift_8.
    APPEND 26 TO mt_row_shift_8.
    APPEND  3 TO mt_row_shift_8.
    APPEND  8 TO mt_row_shift_8.
    APPEND 25 TO mt_row_shift_8.
    APPEND 30 TO mt_row_shift_8.
    APPEND  7 TO mt_row_shift_8.
    APPEND 12 TO mt_row_shift_8.
    APPEND 29 TO mt_row_shift_8.
    APPEND  2 TO mt_row_shift_8.
    APPEND 11 TO mt_row_shift_8.
    APPEND 16 TO mt_row_shift_8.

  ENDMETHOD.                    "_build_row_shift


  METHOD _build_row_shift_inv.
    "Block length 4 word
    APPEND  1 TO mt_row_shift_4_inv.
    APPEND 14 TO mt_row_shift_4_inv.
    APPEND 11 TO mt_row_shift_4_inv.
    APPEND  8 TO mt_row_shift_4_inv.
    APPEND  5 TO mt_row_shift_4_inv.
    APPEND  2 TO mt_row_shift_4_inv.
    APPEND 15 TO mt_row_shift_4_inv.
    APPEND 12 TO mt_row_shift_4_inv.
    APPEND  9 TO mt_row_shift_4_inv.
    APPEND  6 TO mt_row_shift_4_inv.
    APPEND  3 TO mt_row_shift_4_inv.
    APPEND 16 TO mt_row_shift_4_inv.
    APPEND 13 TO mt_row_shift_4_inv.
    APPEND 10 TO mt_row_shift_4_inv.
    APPEND  7 TO mt_row_shift_4_inv.
    APPEND  4 TO mt_row_shift_4_inv.

    "Block length 5 word
    APPEND  1 TO mt_row_shift_5_inv.
    APPEND 18 TO mt_row_shift_5_inv.
    APPEND 15 TO mt_row_shift_5_inv.
    APPEND 12 TO mt_row_shift_5_inv.
    APPEND  5 TO mt_row_shift_5_inv.
    APPEND  2 TO mt_row_shift_5_inv.
    APPEND 19 TO mt_row_shift_5_inv.
    APPEND 16 TO mt_row_shift_5_inv.
    APPEND  9 TO mt_row_shift_5_inv.
    APPEND  6 TO mt_row_shift_5_inv.
    APPEND  3 TO mt_row_shift_5_inv.
    APPEND 20 TO mt_row_shift_5_inv.
    APPEND 13 TO mt_row_shift_5_inv.
    APPEND 10 TO mt_row_shift_5_inv.
    APPEND  7 TO mt_row_shift_5_inv.
    APPEND  4 TO mt_row_shift_5_inv.
    APPEND 17 TO mt_row_shift_5_inv.
    APPEND 14 TO mt_row_shift_5_inv.
    APPEND 11 TO mt_row_shift_5_inv.
    APPEND  8 TO mt_row_shift_5_inv.

    "Block length 6 word
    APPEND  1 TO mt_row_shift_6_inv.
    APPEND 22 TO mt_row_shift_6_inv.
    APPEND 19 TO mt_row_shift_6_inv.
    APPEND 16 TO mt_row_shift_6_inv.
    APPEND  5 TO mt_row_shift_6_inv.
    APPEND  2 TO mt_row_shift_6_inv.
    APPEND 23 TO mt_row_shift_6_inv.
    APPEND 20 TO mt_row_shift_6_inv.
    APPEND  9 TO mt_row_shift_6_inv.
    APPEND  6 TO mt_row_shift_6_inv.
    APPEND  3 TO mt_row_shift_6_inv.
    APPEND 24 TO mt_row_shift_6_inv.
    APPEND 13 TO mt_row_shift_6_inv.
    APPEND 10 TO mt_row_shift_6_inv.
    APPEND  7 TO mt_row_shift_6_inv.
    APPEND  4 TO mt_row_shift_6_inv.
    APPEND 17 TO mt_row_shift_6_inv.
    APPEND 14 TO mt_row_shift_6_inv.
    APPEND 11 TO mt_row_shift_6_inv.
    APPEND  8 TO mt_row_shift_6_inv.
    APPEND 21 TO mt_row_shift_6_inv.
    APPEND 18 TO mt_row_shift_6_inv.
    APPEND 15 TO mt_row_shift_6_inv.
    APPEND 12 TO mt_row_shift_6_inv.

    "Block length 7 word
    APPEND  1 TO mt_row_shift_7_inv.
    APPEND 26 TO mt_row_shift_7_inv.
    APPEND 23 TO mt_row_shift_7_inv.
    APPEND 16 TO mt_row_shift_7_inv.
    APPEND  5 TO mt_row_shift_7_inv.
    APPEND  2 TO mt_row_shift_7_inv.
    APPEND 27 TO mt_row_shift_7_inv.
    APPEND 20 TO mt_row_shift_7_inv.
    APPEND  9 TO mt_row_shift_7_inv.
    APPEND  6 TO mt_row_shift_7_inv.
    APPEND  3 TO mt_row_shift_7_inv.
    APPEND 24 TO mt_row_shift_7_inv.
    APPEND 13 TO mt_row_shift_7_inv.
    APPEND 10 TO mt_row_shift_7_inv.
    APPEND  7 TO mt_row_shift_7_inv.
    APPEND 28 TO mt_row_shift_7_inv.
    APPEND 17 TO mt_row_shift_7_inv.
    APPEND 14 TO mt_row_shift_7_inv.
    APPEND 11 TO mt_row_shift_7_inv.
    APPEND  4 TO mt_row_shift_7_inv.
    APPEND 21 TO mt_row_shift_7_inv.
    APPEND 18 TO mt_row_shift_7_inv.
    APPEND 15 TO mt_row_shift_7_inv.
    APPEND  8 TO mt_row_shift_7_inv.
    APPEND 25 TO mt_row_shift_7_inv.
    APPEND 22 TO mt_row_shift_7_inv.
    APPEND 19 TO mt_row_shift_7_inv.
    APPEND 12 TO mt_row_shift_7_inv.

    "Block length 8 word
    APPEND  1 TO mt_row_shift_8_inv.
    APPEND 30 TO mt_row_shift_8_inv.
    APPEND 23 TO mt_row_shift_8_inv.
    APPEND 20 TO mt_row_shift_8_inv.
    APPEND  5 TO mt_row_shift_8_inv.
    APPEND  2 TO mt_row_shift_8_inv.
    APPEND 27 TO mt_row_shift_8_inv.
    APPEND 24 TO mt_row_shift_8_inv.
    APPEND  9 TO mt_row_shift_8_inv.
    APPEND  6 TO mt_row_shift_8_inv.
    APPEND 31 TO mt_row_shift_8_inv.
    APPEND 28 TO mt_row_shift_8_inv.
    APPEND 13 TO mt_row_shift_8_inv.
    APPEND 10 TO mt_row_shift_8_inv.
    APPEND  3 TO mt_row_shift_8_inv.
    APPEND 32 TO mt_row_shift_8_inv.
    APPEND 17 TO mt_row_shift_8_inv.
    APPEND 14 TO mt_row_shift_8_inv.
    APPEND  7 TO mt_row_shift_8_inv.
    APPEND  4 TO mt_row_shift_8_inv.
    APPEND 21 TO mt_row_shift_8_inv.
    APPEND 18 TO mt_row_shift_8_inv.
    APPEND 11 TO mt_row_shift_8_inv.
    APPEND  8 TO mt_row_shift_8_inv.
    APPEND 25 TO mt_row_shift_8_inv.
    APPEND 22 TO mt_row_shift_8_inv.
    APPEND 15 TO mt_row_shift_8_inv.
    APPEND 12 TO mt_row_shift_8_inv.
    APPEND 29 TO mt_row_shift_8_inv.
    APPEND 26 TO mt_row_shift_8_inv.
    APPEND 19 TO mt_row_shift_8_inv.
    APPEND 16 TO mt_row_shift_8_inv.

  ENDMETHOD.                    "_build_row_shift_inv


  METHOD _build_sbox.
    APPEND '63' TO mt_sbox.
    APPEND '7C' TO mt_sbox.
    APPEND '77' TO mt_sbox.
    APPEND '7B' TO mt_sbox.
    APPEND 'F2' TO mt_sbox.
    APPEND '6B' TO mt_sbox.
    APPEND '6F' TO mt_sbox.
    APPEND 'C5' TO mt_sbox.
    APPEND '30' TO mt_sbox.
    APPEND '01' TO mt_sbox.
    APPEND '67' TO mt_sbox.
    APPEND '2B' TO mt_sbox.
    APPEND 'FE' TO mt_sbox.
    APPEND 'D7' TO mt_sbox.
    APPEND 'AB' TO mt_sbox.
    APPEND '76' TO mt_sbox.
    APPEND 'CA' TO mt_sbox.
    APPEND '82' TO mt_sbox.
    APPEND 'C9' TO mt_sbox.
    APPEND '7D' TO mt_sbox.
    APPEND 'FA' TO mt_sbox.
    APPEND '59' TO mt_sbox.
    APPEND '47' TO mt_sbox.
    APPEND 'F0' TO mt_sbox.
    APPEND 'AD' TO mt_sbox.
    APPEND 'D4' TO mt_sbox.
    APPEND 'A2' TO mt_sbox.
    APPEND 'AF' TO mt_sbox.
    APPEND '9C' TO mt_sbox.
    APPEND 'A4' TO mt_sbox.
    APPEND '72' TO mt_sbox.
    APPEND 'C0' TO mt_sbox.
    APPEND 'B7' TO mt_sbox.
    APPEND 'FD' TO mt_sbox.
    APPEND '93' TO mt_sbox.
    APPEND '26' TO mt_sbox.
    APPEND '36' TO mt_sbox.
    APPEND '3F' TO mt_sbox.
    APPEND 'F7' TO mt_sbox.
    APPEND 'CC' TO mt_sbox.
    APPEND '34' TO mt_sbox.
    APPEND 'A5' TO mt_sbox.
    APPEND 'E5' TO mt_sbox.
    APPEND 'F1' TO mt_sbox.
    APPEND '71' TO mt_sbox.
    APPEND 'D8' TO mt_sbox.
    APPEND '31' TO mt_sbox.
    APPEND '15' TO mt_sbox.
    APPEND '04' TO mt_sbox.
    APPEND 'C7' TO mt_sbox.
    APPEND '23' TO mt_sbox.
    APPEND 'C3' TO mt_sbox.
    APPEND '18' TO mt_sbox.
    APPEND '96' TO mt_sbox.
    APPEND '05' TO mt_sbox.
    APPEND '9A' TO mt_sbox.
    APPEND '07' TO mt_sbox.
    APPEND '12' TO mt_sbox.
    APPEND '80' TO mt_sbox.
    APPEND 'E2' TO mt_sbox.
    APPEND 'EB' TO mt_sbox.
    APPEND '27' TO mt_sbox.
    APPEND 'B2' TO mt_sbox.
    APPEND '75' TO mt_sbox.
    APPEND '09' TO mt_sbox.
    APPEND '83' TO mt_sbox.
    APPEND '2C' TO mt_sbox.
    APPEND '1A' TO mt_sbox.
    APPEND '1B' TO mt_sbox.
    APPEND '6E' TO mt_sbox.
    APPEND '5A' TO mt_sbox.
    APPEND 'A0' TO mt_sbox.
    APPEND '52' TO mt_sbox.
    APPEND '3B' TO mt_sbox.
    APPEND 'D6' TO mt_sbox.
    APPEND 'B3' TO mt_sbox.
    APPEND '29' TO mt_sbox.
    APPEND 'E3' TO mt_sbox.
    APPEND '2F' TO mt_sbox.
    APPEND '84' TO mt_sbox.
    APPEND '53' TO mt_sbox.
    APPEND 'D1' TO mt_sbox.
    APPEND '00' TO mt_sbox.
    APPEND 'ED' TO mt_sbox.
    APPEND '20' TO mt_sbox.
    APPEND 'FC' TO mt_sbox.
    APPEND 'B1' TO mt_sbox.
    APPEND '5B' TO mt_sbox.
    APPEND '6A' TO mt_sbox.
    APPEND 'CB' TO mt_sbox.
    APPEND 'BE' TO mt_sbox.
    APPEND '39' TO mt_sbox.
    APPEND '4A' TO mt_sbox.
    APPEND '4C' TO mt_sbox.
    APPEND '58' TO mt_sbox.
    APPEND 'CF' TO mt_sbox.
    APPEND 'D0' TO mt_sbox.
    APPEND 'EF' TO mt_sbox.
    APPEND 'AA' TO mt_sbox.
    APPEND 'FB' TO mt_sbox.
    APPEND '43' TO mt_sbox.
    APPEND '4D' TO mt_sbox.
    APPEND '33' TO mt_sbox.
    APPEND '85' TO mt_sbox.
    APPEND '45' TO mt_sbox.
    APPEND 'F9' TO mt_sbox.
    APPEND '02' TO mt_sbox.
    APPEND '7F' TO mt_sbox.
    APPEND '50' TO mt_sbox.
    APPEND '3C' TO mt_sbox.
    APPEND '9F' TO mt_sbox.
    APPEND 'A8' TO mt_sbox.
    APPEND '51' TO mt_sbox.
    APPEND 'A3' TO mt_sbox.
    APPEND '40' TO mt_sbox.
    APPEND '8F' TO mt_sbox.
    APPEND '92' TO mt_sbox.
    APPEND '9D' TO mt_sbox.
    APPEND '38' TO mt_sbox.
    APPEND 'F5' TO mt_sbox.
    APPEND 'BC' TO mt_sbox.
    APPEND 'B6' TO mt_sbox.
    APPEND 'DA' TO mt_sbox.
    APPEND '21' TO mt_sbox.
    APPEND '10' TO mt_sbox.
    APPEND 'FF' TO mt_sbox.
    APPEND 'F3' TO mt_sbox.
    APPEND 'D2' TO mt_sbox.
    APPEND 'CD' TO mt_sbox.
    APPEND '0C' TO mt_sbox.
    APPEND '13' TO mt_sbox.
    APPEND 'EC' TO mt_sbox.
    APPEND '5F' TO mt_sbox.
    APPEND '97' TO mt_sbox.
    APPEND '44' TO mt_sbox.
    APPEND '17' TO mt_sbox.
    APPEND 'C4' TO mt_sbox.
    APPEND 'A7' TO mt_sbox.
    APPEND '7E' TO mt_sbox.
    APPEND '3D' TO mt_sbox.
    APPEND '64' TO mt_sbox.
    APPEND '5D' TO mt_sbox.
    APPEND '19' TO mt_sbox.
    APPEND '73' TO mt_sbox.
    APPEND '60' TO mt_sbox.
    APPEND '81' TO mt_sbox.
    APPEND '4F' TO mt_sbox.
    APPEND 'DC' TO mt_sbox.
    APPEND '22' TO mt_sbox.
    APPEND '2A' TO mt_sbox.
    APPEND '90' TO mt_sbox.
    APPEND '88' TO mt_sbox.
    APPEND '46' TO mt_sbox.
    APPEND 'EE' TO mt_sbox.
    APPEND 'B8' TO mt_sbox.
    APPEND '14' TO mt_sbox.
    APPEND 'DE' TO mt_sbox.
    APPEND '5E' TO mt_sbox.
    APPEND '0B' TO mt_sbox.
    APPEND 'DB' TO mt_sbox.
    APPEND 'E0' TO mt_sbox.
    APPEND '32' TO mt_sbox.
    APPEND '3A' TO mt_sbox.
    APPEND '0A' TO mt_sbox.
    APPEND '49' TO mt_sbox.
    APPEND '06' TO mt_sbox.
    APPEND '24' TO mt_sbox.
    APPEND '5C' TO mt_sbox.
    APPEND 'C2' TO mt_sbox.
    APPEND 'D3' TO mt_sbox.
    APPEND 'AC' TO mt_sbox.
    APPEND '62' TO mt_sbox.
    APPEND '91' TO mt_sbox.
    APPEND '95' TO mt_sbox.
    APPEND 'E4' TO mt_sbox.
    APPEND '79' TO mt_sbox.
    APPEND 'E7' TO mt_sbox.
    APPEND 'C8' TO mt_sbox.
    APPEND '37' TO mt_sbox.
    APPEND '6D' TO mt_sbox.
    APPEND '8D' TO mt_sbox.
    APPEND 'D5' TO mt_sbox.
    APPEND '4E' TO mt_sbox.
    APPEND 'A9' TO mt_sbox.
    APPEND '6C' TO mt_sbox.
    APPEND '56' TO mt_sbox.
    APPEND 'F4' TO mt_sbox.
    APPEND 'EA' TO mt_sbox.
    APPEND '65' TO mt_sbox.
    APPEND '7A' TO mt_sbox.
    APPEND 'AE' TO mt_sbox.
    APPEND '08' TO mt_sbox.
    APPEND 'BA' TO mt_sbox.
    APPEND '78' TO mt_sbox.
    APPEND '25' TO mt_sbox.
    APPEND '2E' TO mt_sbox.
    APPEND '1C' TO mt_sbox.
    APPEND 'A6' TO mt_sbox.
    APPEND 'B4' TO mt_sbox.
    APPEND 'C6' TO mt_sbox.
    APPEND 'E8' TO mt_sbox.
    APPEND 'DD' TO mt_sbox.
    APPEND '74' TO mt_sbox.
    APPEND '1F' TO mt_sbox.
    APPEND '4B' TO mt_sbox.
    APPEND 'BD' TO mt_sbox.
    APPEND '8B' TO mt_sbox.
    APPEND '8A' TO mt_sbox.
    APPEND '70' TO mt_sbox.
    APPEND '3E' TO mt_sbox.
    APPEND 'B5' TO mt_sbox.
    APPEND '66' TO mt_sbox.
    APPEND '48' TO mt_sbox.
    APPEND '03' TO mt_sbox.
    APPEND 'F6' TO mt_sbox.
    APPEND '0E' TO mt_sbox.
    APPEND '61' TO mt_sbox.
    APPEND '35' TO mt_sbox.
    APPEND '57' TO mt_sbox.
    APPEND 'B9' TO mt_sbox.
    APPEND '86' TO mt_sbox.
    APPEND 'C1' TO mt_sbox.
    APPEND '1D' TO mt_sbox.
    APPEND '9E' TO mt_sbox.
    APPEND 'E1' TO mt_sbox.
    APPEND 'F8' TO mt_sbox.
    APPEND '98' TO mt_sbox.
    APPEND '11' TO mt_sbox.
    APPEND '69' TO mt_sbox.
    APPEND 'D9' TO mt_sbox.
    APPEND '8E' TO mt_sbox.
    APPEND '94' TO mt_sbox.
    APPEND '9B' TO mt_sbox.
    APPEND '1E' TO mt_sbox.
    APPEND '87' TO mt_sbox.
    APPEND 'E9' TO mt_sbox.
    APPEND 'CE' TO mt_sbox.
    APPEND '55' TO mt_sbox.
    APPEND '28' TO mt_sbox.
    APPEND 'DF' TO mt_sbox.
    APPEND '8C' TO mt_sbox.
    APPEND 'A1' TO mt_sbox.
    APPEND '89' TO mt_sbox.
    APPEND '0D' TO mt_sbox.
    APPEND 'BF' TO mt_sbox.
    APPEND 'E6' TO mt_sbox.
    APPEND '42' TO mt_sbox.
    APPEND '68' TO mt_sbox.
    APPEND '41' TO mt_sbox.
    APPEND '99' TO mt_sbox.
    APPEND '2D' TO mt_sbox.
    APPEND '0F' TO mt_sbox.
    APPEND 'B0' TO mt_sbox.
    APPEND '54' TO mt_sbox.
    APPEND 'BB' TO mt_sbox.
    APPEND '16' TO mt_sbox.
  ENDMETHOD.                    "_build_sbox


  METHOD _build_sbox_inv.
    APPEND '52' TO mt_sbox_inv.
    APPEND '09' TO mt_sbox_inv.
    APPEND '6A' TO mt_sbox_inv.
    APPEND 'D5' TO mt_sbox_inv.
    APPEND '30' TO mt_sbox_inv.
    APPEND '36' TO mt_sbox_inv.
    APPEND 'A5' TO mt_sbox_inv.
    APPEND '38' TO mt_sbox_inv.
    APPEND 'BF' TO mt_sbox_inv.
    APPEND '40' TO mt_sbox_inv.
    APPEND 'A3' TO mt_sbox_inv.
    APPEND '9E' TO mt_sbox_inv.
    APPEND '81' TO mt_sbox_inv.
    APPEND 'F3' TO mt_sbox_inv.
    APPEND 'D7' TO mt_sbox_inv.
    APPEND 'FB' TO mt_sbox_inv.
    APPEND '7C' TO mt_sbox_inv.
    APPEND 'E3' TO mt_sbox_inv.
    APPEND '39' TO mt_sbox_inv.
    APPEND '82' TO mt_sbox_inv.
    APPEND '9B' TO mt_sbox_inv.
    APPEND '2F' TO mt_sbox_inv.
    APPEND 'FF' TO mt_sbox_inv.
    APPEND '87' TO mt_sbox_inv.
    APPEND '34' TO mt_sbox_inv.
    APPEND '8E' TO mt_sbox_inv.
    APPEND '43' TO mt_sbox_inv.
    APPEND '44' TO mt_sbox_inv.
    APPEND 'C4' TO mt_sbox_inv.
    APPEND 'DE' TO mt_sbox_inv.
    APPEND 'E9' TO mt_sbox_inv.
    APPEND 'CB' TO mt_sbox_inv.
    APPEND '54' TO mt_sbox_inv.
    APPEND '7B' TO mt_sbox_inv.
    APPEND '94' TO mt_sbox_inv.
    APPEND '32' TO mt_sbox_inv.
    APPEND 'A6' TO mt_sbox_inv.
    APPEND 'C2' TO mt_sbox_inv.
    APPEND '23' TO mt_sbox_inv.
    APPEND '3D' TO mt_sbox_inv.
    APPEND 'EE' TO mt_sbox_inv.
    APPEND '4C' TO mt_sbox_inv.
    APPEND '95' TO mt_sbox_inv.
    APPEND '0B' TO mt_sbox_inv.
    APPEND '42' TO mt_sbox_inv.
    APPEND 'FA' TO mt_sbox_inv.
    APPEND 'C3' TO mt_sbox_inv.
    APPEND '4E' TO mt_sbox_inv.
    APPEND '08' TO mt_sbox_inv.
    APPEND '2E' TO mt_sbox_inv.
    APPEND 'A1' TO mt_sbox_inv.
    APPEND '66' TO mt_sbox_inv.
    APPEND '28' TO mt_sbox_inv.
    APPEND 'D9' TO mt_sbox_inv.
    APPEND '24' TO mt_sbox_inv.
    APPEND 'B2' TO mt_sbox_inv.
    APPEND '76' TO mt_sbox_inv.
    APPEND '5B' TO mt_sbox_inv.
    APPEND 'A2' TO mt_sbox_inv.
    APPEND '49' TO mt_sbox_inv.
    APPEND '6D' TO mt_sbox_inv.
    APPEND '8B' TO mt_sbox_inv.
    APPEND 'D1' TO mt_sbox_inv.
    APPEND '25' TO mt_sbox_inv.
    APPEND '72' TO mt_sbox_inv.
    APPEND 'F8' TO mt_sbox_inv.
    APPEND 'F6' TO mt_sbox_inv.
    APPEND '64' TO mt_sbox_inv.
    APPEND '86' TO mt_sbox_inv.
    APPEND '68' TO mt_sbox_inv.
    APPEND '98' TO mt_sbox_inv.
    APPEND '16' TO mt_sbox_inv.
    APPEND 'D4' TO mt_sbox_inv.
    APPEND 'A4' TO mt_sbox_inv.
    APPEND '5C' TO mt_sbox_inv.
    APPEND 'CC' TO mt_sbox_inv.
    APPEND '5D' TO mt_sbox_inv.
    APPEND '65' TO mt_sbox_inv.
    APPEND 'B6' TO mt_sbox_inv.
    APPEND '92' TO mt_sbox_inv.
    APPEND '6C' TO mt_sbox_inv.
    APPEND '70' TO mt_sbox_inv.
    APPEND '48' TO mt_sbox_inv.
    APPEND '50' TO mt_sbox_inv.
    APPEND 'FD' TO mt_sbox_inv.
    APPEND 'ED' TO mt_sbox_inv.
    APPEND 'B9' TO mt_sbox_inv.
    APPEND 'DA' TO mt_sbox_inv.
    APPEND '5E' TO mt_sbox_inv.
    APPEND '15' TO mt_sbox_inv.
    APPEND '46' TO mt_sbox_inv.
    APPEND '57' TO mt_sbox_inv.
    APPEND 'A7' TO mt_sbox_inv.
    APPEND '8D' TO mt_sbox_inv.
    APPEND '9D' TO mt_sbox_inv.
    APPEND '84' TO mt_sbox_inv.
    APPEND '90' TO mt_sbox_inv.
    APPEND 'D8' TO mt_sbox_inv.
    APPEND 'AB' TO mt_sbox_inv.
    APPEND '00' TO mt_sbox_inv.
    APPEND '8C' TO mt_sbox_inv.
    APPEND 'BC' TO mt_sbox_inv.
    APPEND 'D3' TO mt_sbox_inv.
    APPEND '0A' TO mt_sbox_inv.
    APPEND 'F7' TO mt_sbox_inv.
    APPEND 'E4' TO mt_sbox_inv.
    APPEND '58' TO mt_sbox_inv.
    APPEND '05' TO mt_sbox_inv.
    APPEND 'B8' TO mt_sbox_inv.
    APPEND 'B3' TO mt_sbox_inv.
    APPEND '45' TO mt_sbox_inv.
    APPEND '06' TO mt_sbox_inv.
    APPEND 'D0' TO mt_sbox_inv.
    APPEND '2C' TO mt_sbox_inv.
    APPEND '1E' TO mt_sbox_inv.
    APPEND '8F' TO mt_sbox_inv.
    APPEND 'CA' TO mt_sbox_inv.
    APPEND '3F' TO mt_sbox_inv.
    APPEND '0F' TO mt_sbox_inv.
    APPEND '02' TO mt_sbox_inv.
    APPEND 'C1' TO mt_sbox_inv.
    APPEND 'AF' TO mt_sbox_inv.
    APPEND 'BD' TO mt_sbox_inv.
    APPEND '03' TO mt_sbox_inv.
    APPEND '01' TO mt_sbox_inv.
    APPEND '13' TO mt_sbox_inv.
    APPEND '8A' TO mt_sbox_inv.
    APPEND '6B' TO mt_sbox_inv.
    APPEND '3A' TO mt_sbox_inv.
    APPEND '91' TO mt_sbox_inv.
    APPEND '11' TO mt_sbox_inv.
    APPEND '41' TO mt_sbox_inv.
    APPEND '4F' TO mt_sbox_inv.
    APPEND '67' TO mt_sbox_inv.
    APPEND 'DC' TO mt_sbox_inv.
    APPEND 'EA' TO mt_sbox_inv.
    APPEND '97' TO mt_sbox_inv.
    APPEND 'F2' TO mt_sbox_inv.
    APPEND 'CF' TO mt_sbox_inv.
    APPEND 'CE' TO mt_sbox_inv.
    APPEND 'F0' TO mt_sbox_inv.
    APPEND 'B4' TO mt_sbox_inv.
    APPEND 'E6' TO mt_sbox_inv.
    APPEND '73' TO mt_sbox_inv.
    APPEND '96' TO mt_sbox_inv.
    APPEND 'AC' TO mt_sbox_inv.
    APPEND '74' TO mt_sbox_inv.
    APPEND '22' TO mt_sbox_inv.
    APPEND 'E7' TO mt_sbox_inv.
    APPEND 'AD' TO mt_sbox_inv.
    APPEND '35' TO mt_sbox_inv.
    APPEND '85' TO mt_sbox_inv.
    APPEND 'E2' TO mt_sbox_inv.
    APPEND 'F9' TO mt_sbox_inv.
    APPEND '37' TO mt_sbox_inv.
    APPEND 'E8' TO mt_sbox_inv.
    APPEND '1C' TO mt_sbox_inv.
    APPEND '75' TO mt_sbox_inv.
    APPEND 'DF' TO mt_sbox_inv.
    APPEND '6E' TO mt_sbox_inv.
    APPEND '47' TO mt_sbox_inv.
    APPEND 'F1' TO mt_sbox_inv.
    APPEND '1A' TO mt_sbox_inv.
    APPEND '71' TO mt_sbox_inv.
    APPEND '1D' TO mt_sbox_inv.
    APPEND '29' TO mt_sbox_inv.
    APPEND 'C5' TO mt_sbox_inv.
    APPEND '89' TO mt_sbox_inv.
    APPEND '6F' TO mt_sbox_inv.
    APPEND 'B7' TO mt_sbox_inv.
    APPEND '62' TO mt_sbox_inv.
    APPEND '0E' TO mt_sbox_inv.
    APPEND 'AA' TO mt_sbox_inv.
    APPEND '18' TO mt_sbox_inv.
    APPEND 'BE' TO mt_sbox_inv.
    APPEND '1B' TO mt_sbox_inv.
    APPEND 'FC' TO mt_sbox_inv.
    APPEND '56' TO mt_sbox_inv.
    APPEND '3E' TO mt_sbox_inv.
    APPEND '4B' TO mt_sbox_inv.
    APPEND 'C6' TO mt_sbox_inv.
    APPEND 'D2' TO mt_sbox_inv.
    APPEND '79' TO mt_sbox_inv.
    APPEND '20' TO mt_sbox_inv.
    APPEND '9A' TO mt_sbox_inv.
    APPEND 'DB' TO mt_sbox_inv.
    APPEND 'C0' TO mt_sbox_inv.
    APPEND 'FE' TO mt_sbox_inv.
    APPEND '78' TO mt_sbox_inv.
    APPEND 'CD' TO mt_sbox_inv.
    APPEND '5A' TO mt_sbox_inv.
    APPEND 'F4' TO mt_sbox_inv.
    APPEND '1F' TO mt_sbox_inv.
    APPEND 'DD' TO mt_sbox_inv.
    APPEND 'A8' TO mt_sbox_inv.
    APPEND '33' TO mt_sbox_inv.
    APPEND '88' TO mt_sbox_inv.
    APPEND '07' TO mt_sbox_inv.
    APPEND 'C7' TO mt_sbox_inv.
    APPEND '31' TO mt_sbox_inv.
    APPEND 'B1' TO mt_sbox_inv.
    APPEND '12' TO mt_sbox_inv.
    APPEND '10' TO mt_sbox_inv.
    APPEND '59' TO mt_sbox_inv.
    APPEND '27' TO mt_sbox_inv.
    APPEND '80' TO mt_sbox_inv.
    APPEND 'EC' TO mt_sbox_inv.
    APPEND '5F' TO mt_sbox_inv.
    APPEND '60' TO mt_sbox_inv.
    APPEND '51' TO mt_sbox_inv.
    APPEND '7F' TO mt_sbox_inv.
    APPEND 'A9' TO mt_sbox_inv.
    APPEND '19' TO mt_sbox_inv.
    APPEND 'B5' TO mt_sbox_inv.
    APPEND '4A' TO mt_sbox_inv.
    APPEND '0D' TO mt_sbox_inv.
    APPEND '2D' TO mt_sbox_inv.
    APPEND 'E5' TO mt_sbox_inv.
    APPEND '7A' TO mt_sbox_inv.
    APPEND '9F' TO mt_sbox_inv.
    APPEND '93' TO mt_sbox_inv.
    APPEND 'C9' TO mt_sbox_inv.
    APPEND '9C' TO mt_sbox_inv.
    APPEND 'EF' TO mt_sbox_inv.
    APPEND 'A0' TO mt_sbox_inv.
    APPEND 'E0' TO mt_sbox_inv.
    APPEND '3B' TO mt_sbox_inv.
    APPEND '4D' TO mt_sbox_inv.
    APPEND 'AE' TO mt_sbox_inv.
    APPEND '2A' TO mt_sbox_inv.
    APPEND 'F5' TO mt_sbox_inv.
    APPEND 'B0' TO mt_sbox_inv.
    APPEND 'C8' TO mt_sbox_inv.
    APPEND 'EB' TO mt_sbox_inv.
    APPEND 'BB' TO mt_sbox_inv.
    APPEND '3C' TO mt_sbox_inv.
    APPEND '83' TO mt_sbox_inv.
    APPEND '53' TO mt_sbox_inv.
    APPEND '99' TO mt_sbox_inv.
    APPEND '61' TO mt_sbox_inv.
    APPEND '17' TO mt_sbox_inv.
    APPEND '2B' TO mt_sbox_inv.
    APPEND '04' TO mt_sbox_inv.
    APPEND '7E' TO mt_sbox_inv.
    APPEND 'BA' TO mt_sbox_inv.
    APPEND '77' TO mt_sbox_inv.
    APPEND 'D6' TO mt_sbox_inv.
    APPEND '26' TO mt_sbox_inv.
    APPEND 'E1' TO mt_sbox_inv.
    APPEND '69' TO mt_sbox_inv.
    APPEND '14' TO mt_sbox_inv.
    APPEND '63' TO mt_sbox_inv.
    APPEND '55' TO mt_sbox_inv.
    APPEND '21' TO mt_sbox_inv.
    APPEND '0C' TO mt_sbox_inv.
    APPEND '7D' TO mt_sbox_inv.
  ENDMETHOD.                    "_build_sbox_inv


  METHOD _get_multiplication_11.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_11 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_GET_MULTIPLICATION_11


  METHOD _get_multiplication_13.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_13 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_GET_MULTIPLICATION_13


  METHOD _get_multiplication_14.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_14 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_get_multiplication_14


  METHOD _get_multiplication_2.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_2 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_get_multiplication_2


  METHOD _get_multiplication_3.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_3 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_GET_MULTIPLICATION_3


  METHOD _get_multiplication_9.
    DATA: lookup_index    TYPE int1.
    lookup_index = i_x.
    READ TABLE mt_multiplication_lookup_9 INDEX lookup_index + 1 INTO r_x.
  ENDMETHOD.                    "_GET_MULTIPLICATION_9


  METHOD _rcon.
    DATA: temp    TYPE x.

    CLEAR e_array.

    READ TABLE mt_rcon INDEX i_number + 1 INTO temp.
    APPEND temp TO e_array.

    APPEND '00' TO e_array.
    APPEND '00' TO e_array.
    APPEND '00' TO e_array.
  ENDMETHOD.                    "rcon


  METHOD _sbox.
    READ TABLE mt_sbox INDEX c_x + 1 INTO c_x.
  ENDMETHOD.                    "sbox


  METHOD _sbox_inv.
    READ TABLE mt_sbox_inv INDEX c_x + 1 INTO c_x.
  ENDMETHOD.                    "sbox_inv
ENDCLASS.