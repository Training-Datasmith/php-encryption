#!/usr/bin/env python3
"""One-shot rename pass for repo-owned identifiers (run from repo root)."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Longest-first token replacements (identifiers / doc refs).
REPLACEMENTS = [
    ("WrongKeyOrModifiedCiphertextException", "Wrong_Key_Or_Modified_Ciphertext_Exception"),
    ("EnvironmentIsBrokenException", "Environment_Is_Broken_Exception"),
    ("saveBytesToChecksummedAsciiSafeString", "save_bytes_to_checksummed_ascii_safe_string"),
    ("loadBytesFromChecksummedAsciiSafeString", "load_bytes_from_checksummed_ascii_safe_string"),
    ("createRandomPasswordProtectedKey", "create_random_password_protected_key"),
    ("KeyProtectedByPassword", "Key_Protected_By_Password"),
    ("BackwardsCompatibilityTest", "Backwards_Compatibility_Test"),
    ("allNonZeroByteValuesProvider", "all_non_zero_byte_values_provider"),
    ("counterTestVectorProvider", "counter_test_vector_provider"),
    ("garbageCiphertextProvider", "garbage_ciphertext_provider"),
    ("testEncryptDecryptWithPassword", "test_encrypt_decrypt_with_password"),
    ("testDecryptLegacyWithWrongMethodStraightUpHex", "test_decrypt_legacy_with_wrong_method_straight_up_hex"),
    ("testDecryptLegacyWithWrongMethodStraightUpBinary", "test_decrypt_legacy_with_wrong_method_straight_up_binary"),
    ("testOurSubstrTrailingEmptyStringBugWeird", "test_our_substr_trailing_empty_string_bug_weird"),
    ("testOurSubstrTrailingEmptyStringBugNormal", "test_our_substr_trailing_empty_string_bug_normal"),
    ("testIncrementCounterTestVector", "test_increment_counter_test_vector"),
    ("testIncrementCausingOverflowInFirstByte", "test_increment_causing_overflow_in_first_byte"),
    ("testEncryptWithPasswordTypeError", "test_encrypt_with_password_type_error"),
    ("testDecryptWithPasswordTypeError", "test_decrypt_with_password_type_error"),
    ("testKeyProtectedByPasswordCorrect", "test_key_protected_by_password_correct"),
    ("testKeyProtectedByPasswordWrong", "test_key_protected_by_password_wrong"),
    ("testEncryptWithCryptoDecryptWithFile", "test_encrypt_with_crypto_decrypt_with_file"),
    ("testEncryptWithFileDecryptWithCrypto", "test_encrypt_with_file_decrypt_with_crypto"),
    ("testBadSourcePathEncryptWithPassword", "test_bad_source_path_encrypt_with_password"),
    ("testBadDestinationPathEncryptWithPassword", "test_bad_destination_path_encrypt_with_password"),
    ("testBadSourcePathDecryptWithPassword", "test_bad_source_path_decrypt_with_password"),
    ("testBadDestinationPathDecryptWithPassword", "test_bad_destination_path_decrypt_with_password"),
    ("testNonResourceInputDecrypt", "test_non_resource_input_decrypt"),
    ("testNonResourceOutputDecrypt", "test_non_resource_output_decrypt"),
    ("testNonResourceInputEncrypt", "test_non_resource_input_encrypt"),
    ("testNonResourceOutputEncrypt", "test_non_resource_output_encrypt"),
    ("testNonFileResourceDecrypt", "test_non_file_resource_decrypt"),
    ("testDecryptTruncatedCiphertext", "test_decrypt_truncated_ciphertext"),
    ("testDecryptLegacyCiphertextWrongKey", "test_decrypt_legacy_ciphertext_wrong_key"),
    ("testLegacyDecryptTooShort", "test_legacy_decrypt_too_short"),
    ("testPasswordActuallyChanges", "test_password_actually_changes"),
    ("testEncodeDecodeEquivalencyTwoBytes", "test_encode_decode_equivalency_two_bytes"),
    ("testIncrementWithShortIvLength", "test_increment_with_short_iv_length"),
    ("testIncrementWithLongIvLength", "test_increment_with_long_iv_length"),
    ("testIncrementByNegativeValue", "test_increment_by_negative_value"),
    ("testIncrementByNonInteger", "test_increment_by_non_integer"),
    ("testCompatibilityWithOpenSSL", "test_compatibility_with_open_ssl"),
    ("testFuzzIncrementCounter", "test_fuzz_increment_counter"),
    ("testIncorrectHeader", "test_incorrect_header"),
    ("testCreateNewRandomKey", "test_create_new_random_key"),
    ("testSaveAndLoadKey", "test_save_and_load_key"),
    ("testFileCreateRandomKey", "test_file_create_random_key"),
    ("testBadSourcePathEncrypt", "test_bad_source_path_encrypt"),
    ("testBadDestinationPathEncrypt", "test_bad_destination_path_encrypt"),
    ("testBadSourcePathDecrypt", "test_bad_source_path_decrypt"),
    ("testBadDestinationPathDecrypt", "test_bad_destination_path_decrypt"),
    ("testDecryptBadMagicNumber", "test_decrypt_bad_magic_number"),
    ("testDecryptEmptyFile", "test_decrypt_empty_file"),
    ("testIncrementByZero", "test_increment_by_zero"),
    ("testOurSubstrOutOfBorders", "test_our_substr_out_of_borders"),
    ("testOurSubstrNegativeLength", "test_our_substr_negative_length"),
    ("testOurSubstrNegativeStart", "test_our_substr_negative_start"),
    ("testOurSubstrLengthIsMax", "test_our_substr_length_is_max"),
    ("testSecureRandomZeroLength", "test_secure_random_zero_length"),
    ("testSecureRandomNegativeLength", "test_secure_random_negative_length"),
    ("testSecureRandomPositiveLength", "test_secure_random_positive_length"),
    ("testEncryptTypeErrorA", "test_encrypt_type_error_a"),
    ("testEncryptTypeErrorB", "test_encrypt_type_error_b"),
    ("testEncryptTypeErrorC", "test_encrypt_type_error_c"),
    ("testDecryptTypeErrorA", "test_decrypt_type_error_a"),
    ("testDecryptTypeErrorB", "test_decrypt_type_error_b"),
    ("testDecryptTypeErrorC", "test_decrypt_type_error_c"),
    ("testEncryptWithPasswordTypeErrorA", "test_encrypt_with_password_type_error_a"),
    ("testEncryptWithPasswordTypeErrorB", "test_encrypt_with_password_type_error_b"),
    ("testEncryptWithPasswordTypeErrorC", "test_encrypt_with_password_type_error_c"),
    ("testDecryptWithPasswordTypeErrorA", "test_decrypt_with_password_type_error_a"),
    ("testDecryptWithPasswordTypeErrorB", "test_decrypt_with_password_type_error_b"),
    ("testDecryptWithPasswordTypeErrorC", "test_decrypt_with_password_type_error_c"),
    ("testLegacyDecryptTypeErrorA", "test_legacy_decrypt_type_error_a"),
    ("testLegacyDecryptTypeErrorB", "test_legacy_decrypt_type_error_b"),
    ("testDecryptRawAsHex", "test_decrypt_raw_as_hex"),
    ("testDecryptHexAsRaw", "test_decrypt_hex_as_raw"),
    ("testIncorrectChecksum", "test_incorrect_checksum"),
    ("testBadHexEncoding", "test_bad_hex_encoding"),
    ("testPaddedHexEncoding", "test_padded_hex_encoding"),
    ("testEncodeDecodeEquivalency", "test_encode_decode_equivalency"),
    ("testDecryptGarbage", "test_decrypt_garbage"),
    ("testDecryptLegacyCiphertext", "test_decrypt_legacy_ciphertext"),
    ("testChangePassword", "test_change_password"),
    ("testMalformedLoad", "test_malformed_load"),
    ("testRuntimeTest", "test_runtime_test"),
    ("testEmptyString", "test_empty_string"),
    ("testResourceToResourceWithPassword", "test_resource_to_resource_with_password"),
    ("testFileToFile", "test_file_to_file"),
    ("testFileToFileWithPassword", "test_file_to_file_with_password"),
    ("testResourceToResource", "test_resource_to_resource"),
    ("testExtraData", "test_extra_data"),
    ("fileToFileProvider", "file_to_file_provider"),
    ("CiphertextIntegrityTest", "Ciphertext_Integrity_Test"),
    ("removePHPUnitErrorHandler", "remove_php_unit_error_handler"),
    ("restorePHPUnitErrorHandler", "restore_php_unit_error_handler"),
    ("ensureConstantExists", "ensure_constant_exists"),
    ("ensureFunctionExists", "ensure_function_exists"),
    ("encryptWithPassword", "encrypt_with_password"),
    ("decryptWithPassword", "decrypt_with_password"),
    ("createNewRandomKey", "create_new_random_key"),
    ("loadFromAsciiSafeString", "load_from_ascii_safe_string"),
    ("saveToAsciiSafeString", "save_to_ascii_safe_string"),
    ("getAuthenticationKey", "get_authentication_key"),
    ("getEncryptionKey", "get_encryption_key"),
    ("trimTrailingWhitespace", "trim_trailing_whitespace"),
    ("incrementCounter", "increment_counter"),
    ("getLastErrorMessage", "get_last_error_message"),
    ("encryptFileWithPassword", "encrypt_file_with_password"),
    ("decryptFileWithPassword", "decrypt_file_with_password"),
    ("encryptResourceWithPassword", "encrypt_resource_with_password"),
    ("decryptResourceWithPassword", "decrypt_resource_with_password"),
    ("encryptFileInternal", "encrypt_file_internal"),
    ("decryptFileInternal", "decrypt_file_internal"),
    ("encryptResourceInternal", "encrypt_resource_internal"),
    ("decryptResourceInternal", "decrypt_resource_internal"),
    ("createRandomPasswordProtectedKey", "create_random_password_protected_key"),
    ("unlockKey", "unlock_key"),
    ("changePassword", "change_password"),
    ("HKDFTestVector", "hkdf_test_vector"),
    ("HMACTestVector", "hmac_test_vector"),
    ("AESTestVector", "aes_test_vector"),
    ("testEncryptDecrypt", "test_encrypt_decrypt"),
    ("legacyDecrypt", "legacy_decrypt"),
    ("encryptInternal", "encrypt_internal"),
    ("decryptInternal", "decrypt_internal"),
    ("plainEncrypt", "plain_encrypt"),
    ("plainDecrypt", "plain_decrypt"),
    ("verifyHMAC", "verify_hmac"),
    ("ensureTrue", "ensure_true"),
    ("hashEquals", "hash_equals"),
    ("ourStrlen", "our_strlen"),
    ("ourSubstr", "our_substr"),
    ("secureRandom", "secure_random"),
    ("binToHex", "bin_to_hex"),
    ("hexToBin", "hex_to_bin"),
    ("getRawBytes", "get_raw_bytes"),
    ("createFromKey", "create_from_key"),
    ("createFromPassword", "create_from_password"),
    ("deriveKeys", "derive_keys"),
    ("runtimeTest", "runtime_test"),
    ("encryptFile", "encrypt_file"),
    ("decryptFile", "decrypt_file"),
    ("encryptResource", "encrypt_resource"),
    ("decryptResource", "decrypt_resource"),
    ("readBytes", "read_bytes"),
    ("writeBytes", "write_bytes"),
    ("BadFormatException", "Bad_Format_Exception"),
    ("CryptoException", "Crypto_Exception"),
    ("IOException", "Io_Exception"),
    ("DerivedKeys", "Derived_Keys"),
    ("KeyOrPassword", "Key_Or_Password"),
    ("RuntimeTests", "Runtime_Tests"),
    ("RuntimeTestTest", "Runtime_Test_Test"),
    ("LegacyDecryptTest", "Legacy_Decrypt_Test"),
    ("CtrModeTest", "Ctr_Mode_Test"),
    ("EncodingTest", "Encoding_Test"),
    ("PasswordTest", "Password_Test"),
    ("CryptoTest", "Crypto_Test"),
    ("CoreTest", "Core_Test"),
    ("FileTest", "File_Test"),
    ("KeyTest", "Key_Test"),
    ("keyHelper", "key_helper"),
]

CLASS_FILE_RENAMES = [
    ("docs/classes/KeyProtectedByPassword.md", "docs/classes/Key_Protected_By_Password.md"),
    ("tests/Security/CiphertextIntegrityTest.php", "tests/Security/Ciphertext_Integrity_Test.php"),
    ("src/Exception/IO_Exception.php", "src/Exception/Io_Exception.php"),
]

SCAN_DIRS = ("src", "test", "tests", "docs", "examples", "bin", "ARCHITECTURE.md", "README.md")

def should_scan(path: str) -> bool:
    rel = os.path.relpath(path, ROOT)
    if rel in ("ARCHITECTURE.md", "README.md"):
        return True
    for d in ("src", "test", "tests", "docs", "examples", "bin"):
        if rel.startswith(d + os.sep) or rel == d:
            return True
    return False

def main() -> None:
    for old, new in CLASS_FILE_RENAMES:
        o = os.path.join(ROOT, old)
        n = os.path.join(ROOT, new)
        if os.path.isfile(o):
            os.makedirs(os.path.dirname(n), exist_ok=True)
            if os.path.exists(n):
                os.remove(n)
            os.rename(o, n)

    for dirpath, _, files in os.walk(ROOT):
        for fn in files:
            path = os.path.join(dirpath, fn)
            if not should_scan(path):
                continue
            if not fn.endswith((".php", ".md")):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            orig = text
            for old, new in REPLACEMENTS:
                text = text.replace(old, new)
            # Parameter / variable hints in docs
            text = re.sub(r"\$srcName\b", "$src_name", text)
            text = re.sub(r"\$inputFilename\b", "$input_filename", text)
            text = re.sub(r"\$outputFilename\b", "$output_filename", text)
            text = re.sub(r"\$inputHandle\b", "$input_handle", text)
            text = re.sub(r"\$outputHandle\b", "$output_handle", text)
            text = re.sub(r"\$keyAscii\b", "$key_ascii", text)
            text = text.replace("Sensitive_Parameter", "SensitiveParameter")
            if text != orig:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)

if __name__ == "__main__":
    main()
