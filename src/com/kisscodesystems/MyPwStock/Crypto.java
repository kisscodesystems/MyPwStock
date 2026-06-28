package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.FileStore.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides encryption and decryption of password file contents, scanning and locating keys within
 * decrypted content, and secure generation of strong passwords.
 */
final class Crypto {
  /**
   * Generates a cryptographically secure random password whose length and characters are drawn from
   * the printable ASCII range, retrying until the result passes good-password validation.
   *
   * @return a newly generated valid good password as a char array
   */
  static final char[] getGeneratedGoodPassword() {
    char[] thePassword = new char[0];
    char[] charsToUse = new char[126 - 33 + 1];
    for (int i = 33; i <= 126; i++) {
      charsToUse[i - 33] = (char) i;
    }
    SecureRandom secureRandom = new SecureRandom();
    int lengthOfPassword = 0;
    while (true) {
      lengthOfPassword =
          secureRandom.nextInt(
                  APP_MAX_LENGTH_OF_GENERATED_PASSWORDS
                      - APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS
                      + 1)
              + APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS;
      clearCharArray(thePassword);
      thePassword = null;
      thePassword = new char[lengthOfPassword];
      for (int i = 0; i < lengthOfPassword; i++) {
        thePassword[i] = charsToUse[secureRandom.nextInt(charsToUse.length)];
      }
      if (isValidGoodPassword(thePassword, false)) {
        break;
      }
    }
    lengthOfPassword = 0;

    clearCharArray(charsToUse);
    charsToUse = null;

    secureRandom = null;
    return thePassword;
  }

  /**
   * Locates the character position immediately after the given key within the decrypted content of
   * the specified password file, scanning newline-delimited key markers.
   *
   * @param passwordType the password file type selecting which decrypted content to scan
   * @param key the key name to search for
   * @return the position just after the matched key, or -1 if the key is invalid or not found
   */
  static final int getKeyPos(String passwordType, String key) {
    int keyPos = -1;
    if (isValidKeyOrFileName(key, false)) {
      boolean inKey = false;
      boolean found = true;
      String tempKey = NEW_LINE_CHAR + key + NEW_LINE_CHAR;
      char[] fileContentOrig = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        fileContentOrig = fileContent1Orig;
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        fileContentOrig = fileContent2Orig;
      }

      if (fileContentOrig == null) {
        throw systemexit("Error - fileContentOrig is null, getKeyPos");
      }
      for (int i = getHeaderLength(fileContentOrig) + 1; i < fileContentOrig.length; i++) {
        if (fileContentOrig[i] == NEW_LINE_CHAR) {
          inKey = !inKey;
          if (inKey) {
            found = true;
            for (int j = 0; j < tempKey.length(); j++) {
              if (i + j >= fileContentOrig.length || fileContentOrig[i + j] != tempKey.charAt(j)) {
                found = false;
                break;
              }
            }
            if (found) {
              keyPos = i + 1;
              break;
            }
          }
        } else if (fileContentOrig[i] == NUL_CHAR) {
          break;
        }
      }

      fileContentOrig = null;
      inKey = false;
      found = false;
      tempKey = null;
    }
    return keyPos;
  }

  /**
   * Computes the number of keys stored in the decrypted content of the specified password file,
   * derived from the count of newline characters.
   *
   * @param passwordType the password file type whose key count is requested
   * @return the number of keys in the content, or 0 for unrecognized password types
   */
  static final int getNumOfKeysInContent(String passwordType) {
    int keysCount = 0;
    if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
      keysCount = (getNumOfNewLinesInContent(passwordType) - 2) / 2;
    }

    return keysCount;
  }

  /**
   * Counts the newline characters in the decrypted content of the specified file type, stopping at
   * the first space character that marks the end of meaningful content.
   *
   * @param passwordType the file type (file1, file2, or admin) whose content is scanned
   * @return the number of newline characters found before the trailing padding
   */
  static final int getNumOfNewLinesInContent(String passwordType) {
    int newLineCount = 0;
    char[] fileContentOrig = null;
    if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
      fileContentOrig = fileContent1Orig;
    } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
      fileContentOrig = fileContent2Orig;
    } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
      fileContentOrig = fileContentAdminOrig;
    }

    if (fileContentOrig == null) {
      throw systemexit("Error - fileContent is null, getNumOfNewLinesInContent");
    }
    for (int i = 0; i < fileContentOrig.length; i++) {
      if (fileContentOrig[i] == NEW_LINE_CHAR) {
        newLineCount++;
      } else if (fileContentOrig[i] == NUL_CHAR) {
        break;
      }
    }

    fileContentOrig = null;
    return newLineCount;
  }

  /**
   * Shifts the trailing portion of the decrypted file content starting at a given position by a
   * signed offset, padding the vacated region with space characters to insert or remove space.
   *
   * @param passwordType the file type whose content buffer is modified
   * @param startPos the index at which the shifted region begins
   * @param diff the signed number of positions to move the region (positive shifts right, negative
   *     shifts left)
   */
  static final void shiftFileContent(String passwordType, int startPos, int diff) {
    if (diff != 0) {
      int lastNonSpaceCharIndexOrig = 0;
      int movedPartCount = 0;
      char[] fileContentOrig = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        fileContentOrig = fileContent1Orig;
        lastNonSpaceCharIndexOrig = getFirstPadCharIndexBefore(fileContentOrig);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        fileContentOrig = fileContent2Orig;
        lastNonSpaceCharIndexOrig = getFirstPadCharIndexBefore(fileContentOrig);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        fileContentOrig = fileContentAdminOrig;
        lastNonSpaceCharIndexOrig = getFirstNewLineAndSpaceCharIndex(fileContentOrig);
      }

      if (fileContentOrig == null) {
        throw systemexit("Error - fileContentOrig is null, shiftFileContent");
      }
      // The vacated region is filled with the file's padding sentinel: NUL for password files
      // (so note values may contain spaces) and a space for the admin file.
      char padChar = PASSWORD_TYPE_ADMIN.equals(passwordType) ? SPACE_CHAR : NUL_CHAR;
      movedPartCount = lastNonSpaceCharIndexOrig - startPos + 1;
      if (movedPartCount < 0) {
        throw systemexit("Error - movedPartCount is negative, shiftFileContent");
      }
      char[] movedPart = new char[movedPartCount];
      clearCharArray(movedPart);
      for (int i = startPos; i <= lastNonSpaceCharIndexOrig; i++) {
        movedPart[i - startPos] = fileContentOrig[i];
      }
      if (!(startPos + diff >= 0)) {
        throw systemexit("Error - Write before content, shiftFileContent");
      }
      if (!(startPos + diff + (movedPart.length - 1) < fileContentOrig.length)) {
        throw systemexit("Error - Writing after content, shiftFileContent");
      }
      for (int i = 0; i < movedPart.length; i++) {
        fileContentOrig[startPos + diff + i] = movedPart[i];
      }
      if (diff < 0) {
        for (int i = startPos + diff + movedPartCount; i <= lastNonSpaceCharIndexOrig; i++) {
          fileContentOrig[i] = padChar;
        }
      } else if (diff > 0) {
        for (int i = startPos; i < startPos + Math.min(movedPartCount, diff); i++) {
          fileContentOrig[i] = padChar;
        }
      }

      clearCharArray(movedPart);
      movedPart = null;

      fileContentOrig = null;
      lastNonSpaceCharIndexOrig = 0;
      movedPartCount = 0;
    }
  }

  /**
   * Reads the salt, IV, and encrypted data for the given file, derives the key via PBE, decrypts
   * the content into the corresponding in-memory buffer, and verifies its header.
   *
   * @param fileName the name of the file to read and decrypt
   * @param passwordType the file type (file1, file2, or admin) being loaded
   * @return true if the file was successfully decrypted and its header validated, false otherwise
   */
  static final boolean getFileContent(String fileName, String passwordType) {
    boolean success = false;
    if (isValidKeyOrFileName(fileName, false)) {
      if (((PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType))
              && isExistingPasswordFile(fileName, false))
          || (PASSWORD_TYPE_ADMIN.equals(passwordType)
              && isExistingAdminFile(APP_ADMIN_FILE_NAME, false))) {
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          clearCharArray(fileContent1Orig);
          // A fresh char[] is NUL-filled by default, which is exactly the password-file padding
          // sentinel, so the buffer is left NUL-padded (no space-fill).
          fileContent1Orig = new char[APP_FILE_CONTENT_MAX_LENGTH];
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          clearCharArray(fileContent2Orig);
          fileContent2Orig = new char[APP_FILE_CONTENT_MAX_LENGTH];
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          clearCharArray(fileContentAdminOrig);
          fileContentAdminOrig = new char[APP_FILE_CONTENT_MAX_LENGTH];
          clearCharArray(fileContentAdminOrig);
        }
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          sl1 = readFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX);
          if (sl1 == null) {
            throw systemexit("Error - sl1 is null, getFileContent");
          } else if (sl1.length == 0) {
            throw systemexit("Error - sl1 is empty, getFileContent");
          }
          iv1 = readFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX);
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          sl2 = readFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX);
          if (sl2 == null) {
            throw systemexit("Error - sl2 is null, getFileContent");
          } else if (sl2.length == 0) {
            throw systemexit("Error - sl2 is empty, getFileContent");
          }
          iv2 = readFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          slAdmin = readFileBytes(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX);
          if (slAdmin == null) {
            throw systemexit("Error - slAdmin is null, getFileContent");
          } else if (slAdmin.length == 0) {
            throw systemexit("Error - slAdmin is empty, getFileContent");
          }
          ivAdmin = readFileBytes(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX);
        }
        SecretKeyFactory skf = null;
        try {
          skf = SecretKeyFactory.getInstance(APP_SECRET_KEY_FACTORY_INSTANCE);
        } catch (NoSuchAlgorithmException e) {
          throw systemexit("Exception - NoSuchAlgorithmException0, getFileContent");
        }
        if (skf == null) {
          throw systemexit("Error - skf is null, getFileContent");
        }
        PBEKeySpec pbeks = null;
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          pbeks =
              new PBEKeySpec(
                  passwordForFile1, sl1, APP_PBE_KEY_SPEC_ITERATIONS, APP_PBE_KEY_SPEC_KEY_LENGTH);
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          pbeks =
              new PBEKeySpec(
                  passwordForFile2, sl2, APP_PBE_KEY_SPEC_ITERATIONS, APP_PBE_KEY_SPEC_KEY_LENGTH);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          pbeks =
              new PBEKeySpec(
                  passwordForAdmin,
                  slAdmin,
                  APP_PBE_KEY_SPEC_ITERATIONS,
                  APP_PBE_KEY_SPEC_KEY_LENGTH);
        }
        if (pbeks == null) {
          throw systemexit("Error - pbeks is null, getFileContent");
        }
        SecretKey sk = null;
        try {
          sk = skf.generateSecret(pbeks);
        } catch (InvalidKeySpecException e) {
          throw systemexit("Exception - InvalidKeySpecException, getFileContent");
        }
        if (sk == null) {
          throw systemexit("Error - sk is null, getFileContent");
        }
        SecretKeySpec sks = new SecretKeySpec(sk.getEncoded(), APP_SECRET_KEY_SPEC_ALGORYTHM);
        Cipher cipher = null;
        try {
          cipher = Cipher.getInstance(APP_CIPHER_INSTANCE);
        } catch (NoSuchAlgorithmException e) {
          throw systemexit("Exception - NoSuchAlgorithmException1, getFileContent");
        } catch (NoSuchPaddingException e) {
          throw systemexit("Exception - NoSuchPaddingException, getFileContent");
        }
        if (cipher == null) {
          throw systemexit("Error - cipher is null, getFileContent");
        }
        GCMParameterSpec gps = null;
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          gps = new GCMParameterSpec(APP_GCM_TAG_LENGTH_BITS, iv1);
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          gps = new GCMParameterSpec(APP_GCM_TAG_LENGTH_BITS, iv2);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          gps = new GCMParameterSpec(APP_GCM_TAG_LENGTH_BITS, ivAdmin);
        }
        if (gps == null) {
          throw systemexit("Error - gps is null, getFileContent");
        }
        try {
          cipher.init(Cipher.DECRYPT_MODE, sks, gps);
        } catch (InvalidAlgorithmParameterException e) {
          throw systemexit("Exception - InvalidAlgorithmParameterException, getFileContent");
        } catch (InvalidKeyException e) {
          throw systemexit("Exception - InvalidKeyException, getFileContent");
        }
        byte[] decryptedBytes = null;
        byte[] bytes = null;
        if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
          bytes = readFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          bytes = readFileBytes(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX);
        }
        try {
          decryptedBytes = cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException e) {
          throw systemexit("Exception - IllegalBlockSizeException, getFileContent");
        } catch (BadPaddingException e) {
          // AES-GCM throws AEADBadTagException (a BadPaddingException) when the key is wrong or the
          // data has been tampered with: that is how an incorrect password is detected. The message
          // is suppressed while silently trying cached passwords from other files.
          if (!quietFilePasswordTrial) {
            outprintln(MESSAGE_INCORRECT_FILE_PASSWORD + fileName);
          }
        }
        gps = null;
        cipher = null;
        sks = null;
        sk = null;
        pbeks = null;
        skf = null;
        boolean headerFound = false;
        if (decryptedBytes != null) {
          char[] tempChar = toCharsASCII(decryptedBytes);
          if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
            for (int i = 0; i < Math.min(tempChar.length, APP_FILE_CONTENT_MAX_LENGTH); i++) {
              fileContent1Orig[i] = tempChar[i];
            }
            headerFound = isContentDecrypted(PASSWORD_TYPE_FILE1);
          } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
            for (int i = 0; i < Math.min(tempChar.length, APP_FILE_CONTENT_MAX_LENGTH); i++) {
              fileContent2Orig[i] = tempChar[i];
            }
            headerFound = isContentDecrypted(PASSWORD_TYPE_FILE2);
          } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
            for (int i = 0; i < Math.min(tempChar.length, APP_FILE_CONTENT_MAX_LENGTH); i++) {
              fileContentAdminOrig[i] = tempChar[i];
            }
            headerFound = isContentDecrypted(PASSWORD_TYPE_ADMIN);
          }
          clearCharArray(tempChar);
          tempChar = null;
          clearByteArray(decryptedBytes);
          decryptedBytes = null;
        } else {
          headerFound = false;
        }
        clearByteArray(bytes);
        bytes = null;
        if (headerFound) {
          if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
            if (fileContent1Orig == null) {
              throw systemexit("Error - fileContent1Orig is null, getFileContent");
            }
            allowNotesFile1 = fileContent1Orig[getHeaderLength(fileContent1Orig)];

          } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
            if (fileContent2Orig == null) {
              throw systemexit("Error - fileContent2Orig is null, getFileContent");
            }
            allowNotesFile2 = fileContent2Orig[getHeaderLength(fileContent2Orig)];
          }
          success = true;

        } else {
          // Suppressed while silently trying cached passwords from other files (a wrong password
          // fails to decrypt and lands here).
          if (!quietFilePasswordTrial) {
            outprintln(MESSAGE_FILE_CONTENT_HAS_NOT_BEEN_FOUND + fileName);
          }
        }
        headerFound = false;

      } else {
        if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
          outprintln(MESSAGE_MISSING_PW_OR_SL_OR_IV_FILE + fileName);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          outprintln(MESSAGE_MISSING_AN_OR_SL_OR_IV_FILE + fileName);
        }
      }
      if (!success) {
        if (toCachePasswords) {
          if (PASSWORD_TYPE_FILE1.equals(passwordType)
              || PASSWORD_TYPE_FILE2.equals(passwordType)) {
            purgeCachedFilePassword(fileName);
          } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
            purgeCachedAdminPassword();
          }
        }
      }
    }
    return success;
  }

  /**
   * Checks that the in-memory content buffer for the given file type has the expected structure
   * after decryption: a random header line, and (for password files) a valid stored-password-type
   * flag right after it. Authenticity and "correct key" are already guaranteed by the authenticated
   * cipher (AES-GCM); this is a structural sanity check on the decrypted layout.
   *
   * @param passwordType the file type whose content buffer is validated
   * @return true if the content has the expected structure, false otherwise
   */
  static final boolean isContentDecrypted(String passwordType) {
    boolean valid = false;
    if (!(fileContent1Orig != null && fileContent2Orig != null && fileContentAdminOrig != null)) {
      throw systemexit(
          "Error - One of these is null:"
              + " fileContent1Orig|fileContent2Orig|fileContentAdminOrig, isContentDecrypted");
    }
    char[] content = null;
    if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
      content = fileContent1Orig;
    } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
      content = fileContent2Orig;
    } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
      content = fileContentAdminOrig;
    }
    if (content != null && content.length == APP_FILE_CONTENT_MAX_LENGTH) {
      int headerLen = -1;
      for (int i = 0; i < Math.min(content.length, APP_HEADER_MAX_LETTERS + 1); i++) {
        if (content[i] == NEW_LINE_CHAR) {
          headerLen = i + 1;
          break;
        }
      }
      if (headerLen >= APP_HEADER_MIN_LETTERS + 1) {
        if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          valid = true;
        } else if (headerLen + 1 < content.length
            && (content[headerLen] == ALLOW_NOTES_YES
                || content[headerLen] == ALLOW_NOTES_NO
                || content[headerLen] == ALLOW_NOTES_RICH)
            && content[headerLen + 1] == NEW_LINE_CHAR) {
          valid = true;
        }
      }
    }

    if (!valid) {
      outprintln(MESSAGE_CONTENT_IS_NOT_DECRYPTED + passwordType);
    }
    return valid;
  }

  /**
   * Generates a header line for new file content: a random number (between the configured minimum
   * and maximum) of random lowercase letters, terminated by a newline. The header carries no fixed
   * plaintext.
   *
   * @return the generated header characters including the trailing newline
   */
  static final char[] generateRandomHeader() {
    SecureRandom secureRandom = new SecureRandom();
    int letters =
        secureRandom.nextInt(APP_HEADER_MAX_LETTERS - APP_HEADER_MIN_LETTERS + 1)
            + APP_HEADER_MIN_LETTERS;
    char[] header = new char[letters + 1];
    for (int i = 0; i < letters; i++) {
      header[i] = (char) ('a' + secureRandom.nextInt(26));
    }
    header[letters] = NEW_LINE_CHAR;
    secureRandom = null;
    return header;
  }

  /**
   * Encrypts the trimmed in-memory content for the given file type using a freshly generated salt
   * and IV, writes the new salt, IV, and data files, then atomically replaces the old files.
   *
   * @param fileName the name of the file to save
   * @param passwordType the file type (file1, file2, or admin) being saved
   * @return true if the file was successfully encrypted and the new files installed, false
   *     otherwise
   */
  static final boolean saveFile(String fileName, String passwordType) {
    boolean success = false;
    if (isValidKeyOrFileName(fileName, false)) {
      SecureRandom secureRandom = new SecureRandom();
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        sl1 = new byte[APP_SALT_LENGTH];
        secureRandom.nextBytes(sl1);
        writeFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX, sl1);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        sl2 = new byte[APP_SALT_LENGTH];
        secureRandom.nextBytes(sl2);
        writeFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX, sl2);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        slAdmin = new byte[APP_SALT_LENGTH];
        secureRandom.nextBytes(slAdmin);
        writeFileBytes(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX, slAdmin);
      }

      secureRandom = null;
      SecretKeyFactory skf = null;
      try {
        skf = SecretKeyFactory.getInstance(APP_SECRET_KEY_FACTORY_INSTANCE);
      } catch (NoSuchAlgorithmException e) {
        throw systemexit("Exception - NoSuchAlgorithmException0, saveFile");
      }
      if (skf == null) {
        throw systemexit("Error - skf is null, saveFile");
      }
      PBEKeySpec pbeks = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        pbeks =
            new PBEKeySpec(
                passwordForFile1, sl1, APP_PBE_KEY_SPEC_ITERATIONS, APP_PBE_KEY_SPEC_KEY_LENGTH);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        pbeks =
            new PBEKeySpec(
                passwordForFile2, sl2, APP_PBE_KEY_SPEC_ITERATIONS, APP_PBE_KEY_SPEC_KEY_LENGTH);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        pbeks =
            new PBEKeySpec(
                passwordForAdmin,
                slAdmin,
                APP_PBE_KEY_SPEC_ITERATIONS,
                APP_PBE_KEY_SPEC_KEY_LENGTH);
      }
      if (pbeks == null) {
        throw systemexit("Error - pbeks is null, saveFile");
      }
      SecretKey sk = null;
      try {
        sk = skf.generateSecret(pbeks);
      } catch (InvalidKeySpecException e) {
        throw systemexit("Exception - InvalidKeyException, saveFile");
      }
      if (sk == null) {
        throw systemexit("Error - sk is null, saveFile");
      }
      SecretKeySpec sks = new SecretKeySpec(sk.getEncoded(), APP_SECRET_KEY_SPEC_ALGORYTHM);
      Cipher cipher = null;
      try {
        cipher = Cipher.getInstance(APP_CIPHER_INSTANCE);
      } catch (NoSuchAlgorithmException e) {
        throw systemexit("Exception - NoSuchAlgorithmException1, saveFile");
      } catch (NoSuchPaddingException e) {
        throw systemexit("Exception - NoSuchPaddingException, saveFile");
      }
      if (cipher == null) {
        throw systemexit("Error - cipher is null, saveFile");
      }
      // AES-GCM needs a unique nonce per (key) use; a fresh random salt above already derives a
      // fresh key for every save, and a fresh random IV is generated here as well, so the nonce is
      // never reused with the same key.
      byte[] iv = new byte[APP_GCM_IV_LENGTH];
      new SecureRandom().nextBytes(iv);
      try {
        cipher.init(Cipher.ENCRYPT_MODE, sks, new GCMParameterSpec(APP_GCM_TAG_LENGTH_BITS, iv));
      } catch (InvalidAlgorithmParameterException e) {
        throw systemexit("Exception - InvalidAlgorithmParameterException, saveFile");
      } catch (InvalidKeyException e) {
        throw systemexit("Exception - InvalidKeyException, saveFile");
      }
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        iv1 = iv;
        writeFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX, iv1);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        iv2 = iv;
        writeFileBytes(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX, iv2);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        ivAdmin = iv;
        writeFileBytes(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX, ivAdmin);
      }

      iv = null;
      byte[] encryptedBytes = null;
      byte[] bytes = null;
      int endIndex = 0;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        endIndex = getFirstPadCharIndexBefore(fileContent1Orig);
        clearCharArray(fileContent1Trim);
        fileContent1Trim = new char[endIndex + 1];
        clearCharArray(fileContent1Trim);
        for (int i = 0; i < fileContent1Trim.length; i++) {
          fileContent1Trim[i] = fileContent1Orig[i];
        }
        bytes = toBytesASCII(fileContent1Trim);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        endIndex = getFirstPadCharIndexBefore(fileContent2Orig);
        clearCharArray(fileContent2Trim);
        fileContent2Trim = new char[endIndex + 1];
        clearCharArray(fileContent2Trim);
        for (int i = 0; i < fileContent2Trim.length; i++) {
          fileContent2Trim[i] = fileContent2Orig[i];
        }
        bytes = toBytesASCII(fileContent2Trim);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        endIndex = getFirstNewLineAndSpaceCharIndex(fileContentAdminOrig);
        clearCharArray(fileContentAdminTrim);
        fileContentAdminTrim = new char[endIndex + 1];
        clearCharArray(fileContentAdminTrim);
        for (int i = 0; i < fileContentAdminTrim.length; i++) {
          fileContentAdminTrim[i] = fileContentAdminOrig[i];
        }
        bytes = toBytesASCII(fileContentAdminTrim);
      }
      try {
        encryptedBytes = cipher.doFinal(bytes);
      } catch (IllegalBlockSizeException e) {
        throw systemexit("Exception - IllegalBlockSizeException, saveFile");
      } catch (BadPaddingException e) {
        throw systemexit("Exception - BadPaddingException, saveFile");
      }
      if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
        writeFileBytes(
            APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX + APP_NW_POSTFIX, encryptedBytes);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        writeFileBytes(
            APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX + APP_NW_POSTFIX, encryptedBytes);
      }
      clearByteArray(encryptedBytes);
      encryptedBytes = null;
      clearByteArray(bytes);
      bytes = null;

      cipher = null;
      sks = null;
      sk = null;
      pbeks = null;
      skf = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        clearCharArray(fileContent1Orig);
        clearCharArray(fileContent1Trim);
        clearByteArray(sl1);
        clearByteArray(iv1);
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        clearCharArray(fileContent2Orig);
        clearCharArray(fileContent2Trim);
        clearByteArray(sl2);
        clearByteArray(iv2);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        clearCharArray(fileContentAdminOrig);
        clearCharArray(fileContentAdminTrim);
        clearByteArray(slAdmin);
        clearByteArray(ivAdmin);
      }
      File fileNew = null;
      File slFileNew = null;
      File ivFileNew = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
        fileNew = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX + APP_NW_POSTFIX);
        slFileNew = new File(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX);
        ivFileNew = new File(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        fileNew = new File(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX + APP_NW_POSTFIX);
        slFileNew = new File(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX);
        ivFileNew = new File(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX);
      }
      if (!(fileNew != null && slFileNew != null && ivFileNew != null)) {
        throw systemexit("Error - One of these is null: fileNew|slFileNew|ivFileNew, saveFile");
      }
      if (fileNew.exists() && slFileNew.exists() && ivFileNew.exists()) {
        if (removeOldFilesAndRenameNewFiles(fileName, passwordType)) {
          success = true;
          outprintln(MESSAGE_FILE_HAS_BEEN_SAVED + fileName);
        }
      } else {
        if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
          outprintln(MESSAGE_MISSING_NEW_PW_OR_SL_OR_IV_FILE);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          outprintln(MESSAGE_MISSING_NEW_AN_OR_SL_OR_IV_FILE);
        }
        if (fileNew.exists()) {
          if (!fileNew.delete()) {
            outprintln(MESSAGE_ERROR_DELETING_NEW_PW_FILE);
          }
        }
        if (slFileNew.exists()) {
          if (!slFileNew.delete()) {
            outprintln(MESSAGE_ERROR_DELETING_NEW_SL_FILE);
          }
        }
        if (ivFileNew.exists()) {
          if (!ivFileNew.delete()) {
            outprintln(MESSAGE_ERROR_DELETING_NEW_IV_FILE);
          }
        }
      }

      fileNew = null;
      slFileNew = null;
      ivFileNew = null;
    }
    return success;
  }

  /**
   * Deletes the existing data, salt, and IV files for the given file and renames the newly written
   * temporary files into their place.
   *
   * @param fileName the name of the file whose old files are replaced
   * @param passwordType the file type (file1, file2, or admin) being replaced
   * @return true if the old files were removed and the new files renamed successfully, false
   *     otherwise
   */
  static final boolean removeOldFilesAndRenameNewFiles(String fileName, String passwordType) {
    boolean success = false;
    if (isValidKeyOrFileName(fileName, true)) {
      File file = null;
      File slFile = null;
      File ivFile = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
        file = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX);
        slFile = new File(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX);
        ivFile = new File(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX);
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        file = new File(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX);
        slFile = new File(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX);
        ivFile = new File(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX);
      }
      if (!(file != null && slFile != null && ivFile != null)) {
        throw systemexit(
            "Error - One of these is null: file|slFile|ivFile, removeOldFilesAndRenameNewFiles");
      }
      if ((file.exists() && !file.delete())
          || (slFile.exists() && !slFile.delete())
          || (ivFile.exists() && !ivFile.delete())) {
        outprintln(MESSAGE_ERROR_DELETING_OLD_FILES_OR_RENAME_NEW_FILES + fileName);
      } else {
        File fileOld = null;
        File fileNew = null;
        File fileOldSl = null;
        File fileNewSl = null;
        File fileOldIv = null;
        File fileNewIv = null;
        if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
          fileOld = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX + APP_NW_POSTFIX);
          fileNew = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX);
          fileOldSl = new File(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX);
          fileNewSl = new File(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX);
          fileOldIv = new File(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX);
          fileNewIv = new File(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          fileOld = new File(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX + APP_NW_POSTFIX);
          fileNew = new File(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX);
          fileOldSl = new File(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX);
          fileNewSl = new File(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX);
          fileOldIv = new File(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX);
          fileNewIv = new File(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX);
        }
        if (!(fileOld != null
            && fileNew != null
            && fileOldSl != null
            && fileNewSl != null
            && fileOldIv != null
            && fileNewIv != null)) {
          throw systemexit(
              "Error - One of these is null:"
                  + " fileOld|fileNew|fileOldSl|fileNewSl|fileOldIv|fileNewIv,"
                  + " removeOldFilesAndRenameNewFiles");
        }
        if (!fileOld.renameTo(fileNew)
            || !fileOldSl.renameTo(fileNewSl)
            || !fileOldIv.renameTo(fileNewIv)) {
          outprintln(MESSAGE_ERROR_DELETING_OLD_FILES_OR_RENAME_NEW_FILES + fileName);
        } else {
          success = true;
        }

        fileOld = null;
        fileNew = null;
        fileOldSl = null;
        fileNewSl = null;
        fileOldIv = null;
        fileNewIv = null;
      }

      file = null;
      slFile = null;
      ivFile = null;
    }
    return success;
  }
}
