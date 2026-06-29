package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/**
 * Reads passwords and keys from the console with optional verification, and caches or purges file
 * and admin passwords held in state.
 */
final class Auth {
  /**
   * Resolves a password of the given type either from the in-memory cache or by prompting the user
   * on the console, validating (and optionally verifying) it, storing it in the appropriate state
   * field, and re-caching it when password caching is enabled.
   *
   * @param passwordType the type of password to read (file1, file2, key, or admin)
   * @param beVerified whether the user must re-enter the password for confirmation
   * @param fileName the file name associated with the password, used for caching
   */
  static final void readPassword(String passwordType, boolean beVerified, String fileName) {
    boolean haveToReadFromConsole = true;
    char[] cachedPassword = new char[0];
    if (fileName == null) {
      throw systemexit("Error - fileName is null, readPassword");
    }
    if (!(isValidKeyOrFileName(fileName, false) || PASSWORD_TYPE_KEY.equals(passwordType))) {
      throw systemexit(
          "Error - invalid filename and the password type is not passwordTypeKey,"
              + " readPassword");
    }
    if (toCachePasswords) {
      if (beVerified || PASSWORD_TYPE_KEY.equals(passwordType)) {
        haveToReadFromConsole = true;
      } else {
        if (PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType)) {
          cachedPassword = getCachedFilePassword(fileName);
          if (cachedPassword.length == 0) {
            // No password is cached for this file, but the user may reuse the same password across
            // files: try the passwords cached for other files and, if one opens this file, use it
            // so the user is not asked again.
            cachedPassword = tryCachedFilePasswordOfOtherFile(fileName, passwordType);
          }
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          cachedPassword = getCachedAdminPassword();
        }
        if (cachedPassword.length == 0) {
          haveToReadFromConsole = true;
        } else {
          haveToReadFromConsole = false;
        }
      }
    } else {
      haveToReadFromConsole = true;
    }
    if (!haveToReadFromConsole) {
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        clearCharArray(passwordForFile1);
        passwordForFile1 = cachedPassword;
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        clearCharArray(passwordForFile2);
        passwordForFile2 = cachedPassword;
      } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
        clearCharArray(passwordForAdmin);
        passwordForAdmin = cachedPassword;
      }
    } else {
      char isNoteAllowed = SPACE_CHAR;
      if (PASSWORD_TYPE_KEY.equals(passwordType)) {
        isNoteAllowed = allowNotesFile1;
      } else {
        // The file (FILE1/FILE2) and admin unlock passwords must always be strong good
        // passwords; only the stored key values (PASSWORD_TYPE_KEY) may be notes.
        isNoteAllowed = ALLOW_NOTES_NO;
      }
      boolean isValidPassword = false;
      boolean isVerifiedPassword = false;
      int attempts = 0;
      while (attempts < FILE_PASSWORD_MAX_ATTEMPTS & (!isValidPassword || !isVerifiedPassword)) {
        attempts ++;
        isValidPassword = false;
        isVerifiedPassword = true;
        clearCharArray(passwordFromInputOriginal);
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          passwordFromInputOriginal = readpassword(MESSAGE_ENTER_PASSWORD_FOR_FILE);
          clearCharArray(passwordForFile1);
          passwordForFile1 = new char[passwordFromInputOriginal.length];
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          passwordFromInputOriginal = readpassword(MESSAGE_ENTER_PASSWORD_FOR_FILE);
          clearCharArray(passwordForFile2);
          passwordForFile2 = new char[passwordFromInputOriginal.length];
        } else if (PASSWORD_TYPE_KEY.equals(passwordType)) {
          if (isNoteAllowed == ALLOW_NOTES_RICH) {
            // Rich notes are entered in plain view (they may be long messages with spaces). Any
            // non-ASCII input is best-effort folded to ASCII, and input longer than the allowed
            // note length is truncated rather than rejected; the user is told when either happens.
            String noteRead = readlineForNote(MESSAGE_ENTER_NOTE);
            String noteFolded = foldToAscii(noteRead);
            if (!noteFolded.equals(noteRead)) {
              outprintln(MESSAGE_NOTE_CONVERTED_TO_ASCII);
            }
            if (noteFolded.length() > APP_MAX_LENGTH_OF_NOTE) {
              noteFolded = noteFolded.substring(0, APP_MAX_LENGTH_OF_NOTE);
              outprintln(MESSAGE_NOTE_TRUNCATED);
            }
            passwordFromInputOriginal = noteFolded.toCharArray();
            noteRead = null;
            noteFolded = null;
          } else {
            passwordFromInputOriginal = readpassword(MESSAGE_ENTER_PASSWORD_FOR_KEY);
          }
          clearCharArray(passwordForKey);
          passwordForKey = new char[passwordFromInputOriginal.length];
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          passwordFromInputOriginal = readpassword(MESSAGE_ENTER_PASSWORD_FOR_ADMIN);
          clearCharArray(passwordForAdmin);
          passwordForAdmin = new char[passwordFromInputOriginal.length];
        }
        if (isNoteAllowed == ALLOW_NOTES_NO) {
          isValidPassword = isValidGoodPassword(passwordFromInputOriginal, beVerified);
        } else if (isNoteAllowed == ALLOW_NOTES_RICH) {
          isValidPassword = isValidRichNote(passwordFromInputOriginal, true);
        } else {
          isValidPassword = isValidNote(passwordFromInputOriginal, true);
        }
        if (isValidPassword) {
          for (int i = 0; i < passwordFromInputOriginal.length; i++) {
            if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
              passwordForFile1[i] = passwordFromInputOriginal[i];
            } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
              passwordForFile2[i] = passwordFromInputOriginal[i];
            } else if (PASSWORD_TYPE_KEY.equals(passwordType)) {
              passwordForKey[i] = passwordFromInputOriginal[i];
            } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
              passwordForAdmin[i] = passwordFromInputOriginal[i];
            }
          }
          if (beVerified && isNoteAllowed != ALLOW_NOTES_RICH) {
            clearCharArray(passwordFromInputVerified);
            passwordFromInputVerified = readpassword(MESSAGE_ENTER_PASSWORD_VERIFY);
            if (passwordFromInputVerified.length != passwordFromInputOriginal.length) {
              isVerifiedPassword = false;
            } else {
              for (int i = 0; i < passwordFromInputVerified.length; i++) {
                if (passwordFromInputVerified[i] != passwordFromInputOriginal[i]) {
                  isVerifiedPassword = false;
                  break;
                }
              }
            }
            clearCharArray(passwordFromInputVerified);
            if (!isVerifiedPassword) {
              outprintln(MESSAGE_PASSWORD_VERIFICATION_ERROR);
            }
          }
        }
        clearCharArray(passwordFromInputOriginal);
      }
      if (toCachePasswords) {
        if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
          purgeCachedFilePassword(fileName);
          cacheFilePassword(fileName, passwordForFile1);
        } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
          purgeCachedFilePassword(fileName);
          cacheFilePassword(fileName, passwordForFile2);
        } else if (PASSWORD_TYPE_ADMIN.equals(passwordType)) {
          purgeCachedAdminPassword();
          cacheAdminPassword(passwordForAdmin);
        }
      }
      isValidPassword = false;
      isVerifiedPassword = false;
      isNoteAllowed = SPACE_CHAR;
    }

    haveToReadFromConsole = false;
    cachedPassword = null;
  }

  /**
   * Repeatedly prompts the user for a key until a valid key or file name is entered, then stores it
   * in the key1 state field.
   */
  static final void readKeyFile1() {
    boolean isValid = false;
    String key = "";
    while (!isValid) {
      key = readline(MESSAGE_ENTER_KEY, APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES);
      isValid = isValidKeyOrFileName(key, true);
    }
    key1 = key;
    isValid = false;
    key = null;
  }

  /**
   * Repeatedly prompts the user until a single-character yes/no answer is entered, then stores the
   * resulting storage mode in the allowNotesFile1 state field. A "yes" creates a rich-note file
   * (flag 'r', spaces and long notes allowed); a "no" creates a full-passwords-only file.
   */
  static final void readAllowNotesFile1() {
    allowNotesFile1 = SPACE_CHAR;
    String allow = "";
    while (!(allowNotesFile1 == ALLOW_NOTES_RICH
        || allowNotesFile1 == ALLOW_NOTES_NO)) {
      allow =
          readline(
              MESSAGE_ALLOW_NOTES, APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES);
      if (allow == null) {
        throw systemexit("Error - allow is null, readAllowNotesFile1");
      }
      if (allow.length() == 1) {
        if (allow.charAt(0) == ALLOW_NOTES_YES) {
          allowNotesFile1 = ALLOW_NOTES_RICH;
        } else if (allow.charAt(0) == ALLOW_NOTES_NO) {
          allowNotesFile1 = ALLOW_NOTES_NO;
        }
      }
    }
    allow = null;
  }

  /**
   * Prompts the user with the given question and returns whether the answer was "yes", printing the
   * not-yes message otherwise. Both messages must be ASCII or newline.
   *
   * @param questionMessage the prompt shown to the user
   * @param notYesMessage the message printed when the answer is not "yes"
   * @return true if the user answered "yes", false otherwise
   */
  static final boolean readYesElseAnything(String questionMessage, String notYesMessage) {
    boolean success = false;
    if (isASCIIorNEWLINE(questionMessage)) {
      if (isASCIIorNEWLINE(notYesMessage)) {
        if (YES.equals(
            readline(questionMessage, APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES))) {
          success = true;
        } else {
          outprintln(notYesMessage);
        }
      }
    }
    return success;
  }

  /**
   * Repeatedly prompts the user until a valid backup description is entered.
   *
   * @return the validated backup description
   */
  static final String readBackupDescription() {
    boolean isValid = false;
    String description = "";
    while (!isValid) {
      description =
          readline(MESSAGE_ENTER_BACKUP_DESCRIPTION, APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION);
      isValid = isValidBackupDescription(description);
    }
    isValid = false;
    return description;
  }

  /** Purges both the cached admin password and all cached file passwords. */
  static final void purgeCachedPasswords() {
    purgeCachedAdminPassword();
    purgeCachedFilePasswords();
  }

  /** Securely wipes and resets every cached file password to an empty array. */
  static final void purgeCachedFilePasswords() {
    if (cachedFilePasswords == null) {
      throw systemexit("Error - cachedFilePasswords is null, purgeCachedFilePasswords");
    }
    for (HashMap.Entry<String, char[]> cachedFilePassword : cachedFilePasswords.entrySet()) {
      if (cachedFilePassword == null) {
        throw systemexit("Error - cachedFilePassword is null, purgeCachedFilePasswords");
      }
      if (cachedFilePassword.getKey() == null) {
        throw systemexit("Error - cachedFilePasswordKey is null, purgeCachedFilePasswords");
      }
      if (cachedFilePassword.getValue() == null) {
        throw systemexit("Error - cachedFilePasswordValue is null, purgeCachedFilePasswords");
      }
      clearCharArray(cachedFilePassword.getValue());
      cachedFilePasswords.put(cachedFilePassword.getKey(), new char[0]);
    }
  }

  /**
   * Securely wipes and resets the cached password for the given file name, if present.
   *
   * @param fileName the file name whose cached password should be purged
   */
  static final void purgeCachedFilePassword(String fileName) {
    if (isValidKeyOrFileName(fileName, false)) {
      if (cachedFilePasswords == null) {
        throw systemexit("Error - cachedFilePasswords is null, purgeCachedFilePassword");
      }
      for (HashMap.Entry<String, char[]> cachedFilePassword : cachedFilePasswords.entrySet()) {
        if (cachedFilePassword == null) {
          throw systemexit("Error - cachedFilePassword is null, purgeCachedFilePassword");
        }
        if (cachedFilePassword.getKey() == null) {
          throw systemexit("Error - cachedFilePasswordKey is null, purgeCachedFilePassword");
        }
        if (cachedFilePassword.getValue() == null) {
          throw systemexit("Error - cachedFilePasswordValue is null, purgeCachedFilePassword");
        }
        if (cachedFilePassword.getKey().equals(fileName)) {
          clearCharArray(cachedFilePassword.getValue());
          cachedFilePasswords.put(cachedFilePassword.getKey(), new char[0]);
          break;
        }
      }
    }
  }

  /** Securely wipes the cached admin password and resets it to an empty array. */
  static final void purgeCachedAdminPassword() {
    clearCharArray(cachedAdminPassword);
    cachedAdminPassword = new char[0];
  }

  /**
   * Returns a copy of the cached password for the given file name, refreshing the cache timestamp;
   * purges the entry and returns an empty array if it is invalid or absent.
   *
   * @param fileName the file name whose cached password is requested
   * @return a copy of the cached password, or an empty array if none is available
   */
  static final char[] getCachedFilePassword(String fileName) {
    char[] thePassword = new char[0];
    if (isValidKeyOrFileName(fileName, false)) {
      if (cachedFilePasswords == null) {
        throw systemexit("Error - cachedFilePasswords is null, getCachedFilePassword");
      }
      for (HashMap.Entry<String, char[]> cachedFilePassword : cachedFilePasswords.entrySet()) {
        if (cachedFilePassword == null) {
          throw systemexit("Error - cachedFilePassword is null, getCachedFilePassword");
        }
        if (cachedFilePassword.getKey() == null) {
          throw systemexit("Error - cachedFilePasswordKey is null, getCachedFilePassword");
        }
        if (cachedFilePassword.getValue() == null) {
          throw systemexit("Error - cachedFilePasswordValue is null, getCachedFilePassword");
        }
        if (cachedFilePassword.getKey().equals(fileName)) {
          char[] tempPassword = cachedFilePassword.getValue();
          if (tempPassword.length > 0) {
            if (isValidGoodPassword(tempPassword, false)) {
              thePassword = new char[tempPassword.length];
              for (int i = 0; i < tempPassword.length; i++) {
                thePassword[i] = tempPassword[i];
              }
              lastReadOrCacheCachablePassword = new Date();
              break;
            } else {
              purgeCachedFilePassword(fileName);
            }
          }
          tempPassword = null;
        }
      }
    }
    return thePassword;
  }

  /**
   * Convenience for users who reuse one password across files: with caching enabled and no password
   * cached for the given file, tries each distinct password cached for other files by silently
   * attempting to decrypt this file. If one works it is cached for this file too and returned (with
   * the file content already loaded by the successful attempt), so the user is not asked for it;
   * otherwise an empty array is returned and the caller prompts as usual.
   *
   * @param fileName the password file being opened
   * @param passwordType the file type being opened (file1 or file2)
   * @return a copy of the cached password that opened the file, or an empty array if none did
   */
  static final char[] tryCachedFilePasswordOfOtherFile(String fileName, String passwordType) {
    char[] working = new char[0];
    if (!toCachePasswords) {
      return working;
    }
    if (!(PASSWORD_TYPE_FILE1.equals(passwordType) || PASSWORD_TYPE_FILE2.equals(passwordType))) {
      return working;
    }
    if (!isValidKeyOrFileName(fileName, false)) {
      return working;
    }
    if (cachedFilePasswords == null) {
      throw systemexit("Error - cachedFilePasswords is null, tryCachedFilePasswordOfOtherFile");
    }
    ArrayList<char[]> candidates = new ArrayList<char[]>();
    for (HashMap.Entry<String, char[]> cachedFilePassword : cachedFilePasswords.entrySet()) {
      if (cachedFilePassword == null || cachedFilePassword.getValue() == null) {
        continue;
      }
      char[] value = cachedFilePassword.getValue();
      if (value.length == 0) {
        continue;
      }
      boolean alreadyHave = false;
      for (int i = 0; i < candidates.size(); i++) {
        if (sameChars(candidates.get(i), value)) {
          alreadyHave = true;
          break;
        }
      }
      if (!alreadyHave) {
        char[] copy = new char[value.length];
        for (int i = 0; i < value.length; i++) {
          copy[i] = value[i];
        }
        candidates.add(copy);
      }
    }
    quietFilePasswordTrial = true;
    for (int c = 0; c < candidates.size(); c++) {
      char[] tryPassword = new char[candidates.get(c).length];
      for (int i = 0; i < tryPassword.length; i++) {
        tryPassword[i] = candidates.get(c)[i];
      }
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        clearCharArray(passwordForFile1);
        passwordForFile1 = tryPassword;
      } else {
        clearCharArray(passwordForFile2);
        passwordForFile2 = tryPassword;
      }
      if (getFileContent(fileName, passwordType)) {
        working = new char[tryPassword.length];
        for (int i = 0; i < tryPassword.length; i++) {
          working[i] = tryPassword[i];
        }
        cacheFilePassword(fileName, working);
        outprintln(MESSAGE_USING_CACHED_FILE_PASSWORD + fileName);
        break;
      }
    }
    quietFilePasswordTrial = false;
    for (int c = 0; c < candidates.size(); c++) {
      clearCharArray(candidates.get(c));
    }
    candidates.clear();
    return working;
  }

  /**
   * Returns whether two char arrays hold exactly the same characters.
   *
   * @param a the first array
   * @param b the second array
   * @return true if both are non-null, of equal length, and equal element by element
   */
  private static final boolean sameChars(char[] a, char[] b) {
    if (a == null || b == null || a.length != b.length) {
      return false;
    }
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns a copy of the cached admin password, refreshing the cache timestamp; purges it and
   * returns an empty array if it is invalid or absent.
   *
   * @return a copy of the cached admin password, or an empty array if none is available
   */
  static final char[] getCachedAdminPassword() {
    char[] thePassword = new char[0];
    if (cachedAdminPassword == null) {
      throw systemexit("Error - cachedAdminPassword is null, getCachedAdminPassword");
    }
    if (cachedAdminPassword.length != 0) {
      if (isValidGoodPassword(cachedAdminPassword, false)) {
        thePassword = new char[cachedAdminPassword.length];
        for (int i = 0; i < cachedAdminPassword.length; i++) {
          thePassword[i] = cachedAdminPassword[i];
        }
        lastReadOrCacheCachablePassword = new Date();
      } else {
        purgeCachedAdminPassword();
      }
    }

    return thePassword;
  }

  /**
   * Stores a copy of the given password in the cache under the given file name and updates the
   * cache timestamp, provided the file name and password are valid.
   *
   * @param fileName the file name to cache the password under
   * @param password the password to cache
   */
  static final void cacheFilePassword(String fileName, char[] password) {
    if (isValidKeyOrFileName(fileName, false)) {
      if (isValidGoodPassword(password, true)) {
        purgeCachedFilePassword(fileName);
        char[] tempPassword = new char[password.length];
        for (int i = 0; i < password.length; i++) {
          tempPassword[i] = password[i];
        }
        cachedFilePasswords.put(fileName, tempPassword);
        tempPassword = null;
        lastReadOrCacheCachablePassword = new Date();
      }
    }
  }

  /**
   * Stores a copy of the given password as the cached admin password and updates the cache
   * timestamp, provided the password is valid.
   *
   * @param password the admin password to cache
   */
  static final void cacheAdminPassword(char[] password) {
    if (isValidGoodPassword(password, true)) {
      char[] tempPassword = new char[password.length];
      for (int i = 0; i < password.length; i++) {
        tempPassword[i] = password[i];
      }
      purgeCachedAdminPassword();
      cachedAdminPassword = tempPassword;
      tempPassword = null;
      lastReadOrCacheCachablePassword = new Date();
    }
  }

  /** Purges all cached passwords and reinitializes the file-password map and admin password. */
  static final void cachedPasswordsIni() {
    purgeCachedPasswords();
    cachedFilePasswords = new HashMap<String, char[]>();
    cachedAdminPassword = new char[0];
  }

  /**
   * Reinitializes all cached passwords if the last read/cache time exceeds the configured maximum
   * idle age.
   */
  static final void cachedPasswordsClearIfOld() {
    Date currentTime = new Date();
    if (lastReadOrCacheCachablePassword == null) {
      throw systemexit(
          "Error - lastReadOrCacheCachablePassword is null, cachedPasswordsClearIfOld");
    }
    if ((int) ((currentTime.getTime() - lastReadOrCacheCachablePassword.getTime()) / 1000)
        > APP_MAX_NOT_READ_CACHED_PASSWORD_SECONDS) {
      cachedPasswordsIni();
    }

    currentTime = null;
  }
}
