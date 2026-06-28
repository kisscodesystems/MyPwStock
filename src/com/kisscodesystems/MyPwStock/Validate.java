package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.AppCommands.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Messages.*;

import java.io.File;

/**
 * Input validation helpers for MyPwStock: good-password, note, key/file-name,
 * backup-description and file-path checks, ASCII predicates, and file/folder existence checks.
 */
final class Validate {
  /**
   * Validates a backup description: it must be non-null, ASCII, and shorter than the configured
   * maximum backup description length.
   *
   * @param description the backup description to validate
   * @return true if the description is a valid backup description, false otherwise
   */
  static final boolean isValidBackupDescription(String description) {
    boolean valid = false;
    if (description != null) {
      if (isASCII(description)) {
        if (description.length() < APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION) {
          valid = true;
        }
      }
    }
    return valid;
  }

  /**
   * Validates a strong password: it must contain only non-space ASCII characters, fall within the
   * allowed length range, and meet the configured minimum counts of upper-case letters, lower-case
   * letters, digits and special characters.
   *
   * @param password the password characters to validate
   * @param messageIfNot if true, prints a message when the password is not valid
   * @return true if the password meets all good-password requirements, false otherwise
   */
  static final boolean isValidGoodPassword(char[] password, boolean messageIfNot) {
    boolean valid = false;
    if (isASCIIandNONSPACE(password)) {
      if (password.length <= APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES) {
        if (password.length >= APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS) {
          int countUCLetters = 0;
          int countLCLetters = 0;
          int countDigits = 0;
          int countSpecChars = 0;
          for (int i = 0; i < password.length; i++) {
            if (password[i] >= 33 && password[i] <= 47) {
              countSpecChars++;
            } else if (password[i] >= 48 && password[i] <= 57) {
              countDigits++;
            } else if (password[i] >= 58 && password[i] <= 64) {
              countSpecChars++;
            } else if (password[i] >= 65 && password[i] <= 90) {
              countUCLetters++;
            } else if (password[i] >= 91 && password[i] <= 96) {
              countSpecChars++;
            } else if (password[i] >= 97 && password[i] <= 122) {
              countLCLetters++;
            } else if (password[i] >= 123 && password[i] <= 126) {
              countSpecChars++;
            }
          }
          if (countUCLetters >= APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS
              && countLCLetters >= APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS
              && countDigits >= APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS
              && countSpecChars >= APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS) {
            valid = true;
          }
          countUCLetters = 0;
          countLCLetters = 0;
          countDigits = 0;
          countSpecChars = 0;
        }
      }
    }
    if (!valid && messageIfNot) {
      outprintln(MESSAGE_GOOD_PASSWORD_IS_NOT_VALID);
    }
    return valid;
  }

  /**
   * Validates a note: it must contain only non-space ASCII characters and have a length
   * within the allowed maximum and the configured minimum note length.
   *
   * @param password the note characters to validate
   * @param messageIfNot if true, prints a message when the note is not valid
   * @return true if the note is valid, false otherwise
   */
  static final boolean isValidNote(char[] password, boolean messageIfNot) {
    boolean valid = false;
    if (isASCIIandNONSPACE(password)) {
      if (password.length <= APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES) {
        if (password.length >= APP_MIN_LENGTH_OF_NOTE) {
          valid = true;
        }
      }
    }
    if (!valid && messageIfNot) {
      outprintln(MESSAGE_NOTE_IS_NOT_VALID);
    }
    return valid;
  }

  /**
   * Validates a rich note (the key value in a 'r'-mode file): it must contain only printable ASCII
   * characters (32-126), so spaces are allowed but line breaks and other control characters are
   * not, and have a length between the configured minimum and the rich-note maximum.
   *
   * @param note the rich-note characters to validate
   * @param messageIfNot if true, prints a message when the note is not valid
   * @return true if the rich note is valid, false otherwise
   */
  static final boolean isValidRichNote(char[] note, boolean messageIfNot) {
    boolean valid = false;
    if (isASCII(note)) {
      if (note.length <= APP_MAX_LENGTH_OF_NOTE) {
        if (note.length >= APP_MIN_LENGTH_OF_NOTE) {
          valid = true;
        }
      }
    }
    if (!valid && messageIfNot) {
      outprintln(MESSAGE_NOTE_IS_NOT_VALID);
    }
    return valid;
  }

  /**
   * Validates a key or file name: it must contain only non-space ASCII characters and have a length
   * within the allowed maximum and the configured minimum key/file-name length.
   *
   * @param name the key or file name to validate
   * @param messageIfNot if true, prints a message when the name is not valid
   * @return true if the name is a valid key or file name, false otherwise
   */
  static final boolean isValidKeyOrFileName(String name, boolean messageIfNot) {
    boolean valid = false;
    if (isASCIIandNONSPACE(name)) {
      if (name.length() <= APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES) {
        if (name.length() >= APP_MIN_LENGTH_OF_KEYS_AND_FILE_NAMES) {
          valid = true;
        }
      }
    }
    if (!valid && messageIfNot) {
      outprintln(MESSAGE_NAME_IS_NOT_VALID);
    }
    return valid;
  }

  /**
   * Validates a file path: it must be ASCII, start with one of the password, admin or backup
   * directories, and end with one of the recognized application file postfixes or the backup
   * description file name.
   *
   * @param filePath the file path to validate
   * @return true if the file path is an allowed application file path, false otherwise
   */
  static final boolean isValidFilePath(String filePath) {
    boolean valid = false;
    if (isASCII(filePath)) {
      if ((filePath.startsWith(APP_PASSWORD_DIR + SEP)
              || filePath.startsWith(APP_ADMIN_DIR + SEP)
              || filePath.startsWith(APP_BACKUP_DIR + SEP))
          && (filePath.endsWith(APP_PD_POSTFIX)
              || filePath.endsWith(APP_AN_POSTFIX)
              || filePath.endsWith(APP_SL_POSTFIX)
              || filePath.endsWith(APP_IV_POSTFIX)
              || filePath.endsWith(APP_NW_POSTFIX)
              || filePath.endsWith(APP_BACKUP_DESCRIPTION_FILE_NAME))) {
        valid = true;
      }
    }
    return valid;
  }

  /**
   * Checks that the command-line arguments array is non-null and every element contains only
   * non-space ASCII characters; prints the usage message for wrong parameters if not.
   *
   * @param args the command-line arguments to validate
   * @return true if the arguments array is valid, false otherwise
   */
  static final boolean isGoodArgsObject(String[] args) {
    boolean isGood = true;
    if (args != null) {
      for (int i = 0; i < args.length; i++) {
        if (!isASCIIandNONSPACE(args[i])) {
          isGood = false;
          break;
        }
      }
    } else {
      isGood = false;
    }
    if (!isGood) {
      usageWrongParameters();
    }
    return isGood;
  }

  /**
   * Checks that all parts (data, IV and salt files) of a backed-up password file exist within the
   * given backup directory.
   *
   * @param backupName the name of the backup folder
   * @param fileName the base name of the password file
   * @param messageIfNot if true, prints a message for each missing file
   * @return true if all backed-up password file parts exist, false otherwise
   */
  static final boolean isExistingBackedUpPasswordFile(
      String backupName, String fileName, boolean messageIfNot) {
    return (isExistingFile(
            APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_PD_POSTFIX, messageIfNot)
        && isExistingFile(
            APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_IV_POSTFIX, messageIfNot)
        && isExistingFile(
            APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_SL_POSTFIX, messageIfNot));
  }

  /**
   * Checks that all parts (data, IV and salt files) of a password file exist in the password
   * directory.
   *
   * @param fileName the base name of the password file
   * @param messageIfNot if true, prints a message for each missing file
   * @return true if all password file parts exist, false otherwise
   */
  static final boolean isExistingPasswordFile(String fileName, boolean messageIfNot) {
    return (isExistingFile(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX, messageIfNot)
        && isExistingFile(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX, messageIfNot)
        && isExistingFile(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX, messageIfNot));
  }

  /**
   * Checks that all parts (admin-data, IV and salt files) of an admin file exist in the admin
   * directory.
   *
   * @param fileName the base name of the admin file
   * @param messageIfNot if true, prints a message for each missing file
   * @return true if all admin file parts exist, false otherwise
   */
  static final boolean isExistingAdminFile(String fileName, boolean messageIfNot) {
    return (isExistingFile(APP_ADMIN_DIR + SEP + fileName + APP_AN_POSTFIX, messageIfNot)
        && isExistingFile(APP_ADMIN_DIR + SEP + fileName + APP_IV_POSTFIX, messageIfNot)
        && isExistingFile(APP_ADMIN_DIR + SEP + fileName + APP_SL_POSTFIX, messageIfNot));
  }

  /**
   * Checks whether the given path exists and is a regular file.
   *
   * @param filePath the path to check
   * @param messageIfNot if true, prints a message when the path is missing or not a regular file
   * @return true if the path exists and is a file, false otherwise
   */
  static final boolean isExistingFile(String filePath, boolean messageIfNot) {
    boolean success = false;
    File file = new File(filePath);
    if (file.exists()) {
      if (file.isFile()) {
        success = true;
      } else {
        if (messageIfNot) {
          outprintln(MESSAGE_FILE_IS_NOT_FILE + filePath);
        }
      }
    } else {
      if (messageIfNot) {
        outprintln(MESSAGE_FILE_DOES_NOT_EXIST + filePath);
      }
    }

    file = null;
    return success;
  }

  /**
   * Checks whether the given path exists and is a directory.
   *
   * @param filePath the path to check
   * @param messageIfNot if true, prints a message when the path is missing or not a directory
   * @return true if the path exists and is a directory, false otherwise
   */
  static final boolean isExistingFolder(String filePath, boolean messageIfNot) {
    boolean success = false;
    File folder = new File(filePath);
    if (folder.exists()) {
      if (folder.isDirectory()) {
        success = true;
      } else {
        if (messageIfNot) {
          outprintln(MESSAGE_FOLDER_IS_FILE + filePath);
        }
      }
    } else {
      if (messageIfNot) {
        outprintln(MESSAGE_FOLDER_DOES_NOT_EXIST + filePath);
      }
    }

    folder = null;
    return success;
  }

  /**
   * Checks whether a single character is a printable ASCII character or a newline.
   *
   * @param c the character to check
   * @return true if the character is printable ASCII or a newline, false otherwise
   */
  static final boolean isASCIIorNEWLINE(char c) {
    return ((c >= 32 && c <= 126) || c == 10);
  }

  /**
   * Checks whether every character in the array is a printable ASCII character or a newline; a null
   * array is considered invalid.
   *
   * @param cs the character array to check
   * @return true if all characters are printable ASCII or newlines, false otherwise
   */
  static final boolean isASCIIorNEWLINE(char[] cs) {
    boolean success = true;
    if (cs != null) {
      for (int i = 0; i < cs.length; i++) {
        if (!((cs[i] >= 32 && cs[i] <= 126) || cs[i] == 10)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }

  /**
   * Checks whether every character in the string is a printable ASCII character or a newline; a
   * null string is considered invalid.
   *
   * @param s the string to check
   * @return true if all characters are printable ASCII or newlines, false otherwise
   */
  static final boolean isASCIIorNEWLINE(String s) {
    boolean success = true;
    if (s != null) {
      for (int i = 0; i < s.length(); i++) {
        if (!((s.charAt(i) >= 32 && s.charAt(i) <= 126) || s.charAt(i) == 10)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }

  /**
   * Checks whether every character in the array is a printable ASCII character (32-126); a null
   * array is considered invalid.
   *
   * @param cs the character array to check
   * @return true if all characters are printable ASCII, false otherwise
   */
  static final boolean isASCII(char[] cs) {
    boolean success = true;
    if (cs != null) {
      for (int i = 0; i < cs.length; i++) {
        if (!(cs[i] >= 32 && cs[i] <= 126)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }

  /**
   * Checks whether every character in the string is a printable ASCII character (32-126); a null
   * string is considered invalid.
   *
   * @param s the string to check
   * @return true if all characters are printable ASCII, false otherwise
   */
  static final boolean isASCII(String s) {
    boolean success = true;
    if (s != null) {
      for (int i = 0; i < s.length(); i++) {
        if (!(s.charAt(i) >= 32 && s.charAt(i) <= 126)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }

  /**
   * Checks whether every character in the array is a printable, non-space ASCII character (33-126);
   * a null array is considered invalid.
   *
   * @param cs the character array to check
   * @return true if all characters are non-space printable ASCII, false otherwise
   */
  static final boolean isASCIIandNONSPACE(char[] cs) {
    boolean success = true;
    if (cs != null) {
      for (int i = 0; i < cs.length; i++) {
        if (!(cs[i] >= 33 && cs[i] <= 126)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }

  /**
   * Checks whether every character in the string is a printable, non-space ASCII character
   * (33-126); a null string is considered invalid.
   *
   * @param s the string to check
   * @return true if all characters are non-space printable ASCII, false otherwise
   */
  static final boolean isASCIIandNONSPACE(String s) {
    boolean success = true;
    if (s != null) {
      for (int i = 0; i < s.length(); i++) {
        if (!(s.charAt(i) >= 33 && s.charAt(i) <= 126)) {
          success = false;
          break;
        }
      }
    } else {
      success = false;
    }
    return success;
  }
}
