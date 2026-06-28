package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ClipboardIo.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.KeyCommands.*;
import static com.kisscodesystems.MyPwStock.Log.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.util.ArrayList;

/**
 * Command handlers for showing and changing the password stored under a key, and changing a file's
 * storable-password type, along with related helpers.
 */
final class PasswordCommands {
  /**
   * Decrypts the given password file and displays the password stored under the supplied key.
   *
   * @param fileName the password file to read
   * @param key the key whose password should be shown
   */
  static final void executeCommandPasswordShow(String fileName, String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (isExistingPasswordFile(fileName, true)) {
        readPassword(PASSWORD_TYPE_FILE1, false, fileName);
        if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
          passwordShowFile1(key);
        }
      }
    }
  }

  /**
   * Decrypts the given password file and copies the password stored under the supplied key onto the
   * system clipboard.
   *
   * @param fileName the password file to read
   * @param key the key whose password should be copied
   */
  static final void executeCommandPasswordCopy(String fileName, String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (isExistingPasswordFile(fileName, true)) {
        readPassword(PASSWORD_TYPE_FILE1, false, fileName);
        if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
          passwordCopyFile1(key);
        }
      }
    }
  }

  /**
   * Changes the password stored under the given key in the password file, optionally generating a
   * new password, rewriting the file content in place, logging the change, and saving both the
   * password file and the admin file after admin authentication.
   *
   * @param fileName the password file to modify
   * @param key the key whose password should be changed
   */
  static final void executeCommandPasswordChange(String fileName, String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (isExistingPasswordFile(fileName, true)) {
        readPassword(PASSWORD_TYPE_FILE1, false, fileName);
        if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
          int keyPos = getKeyPos(PASSWORD_TYPE_FILE1, key);
          if (keyPos != -1) {
            if (readYesElseAnything(
                MESSAGE_SURE_CHANGE_PASSWORD, MESSAGE_PASSWORD_WONT_BE_CHANGED)) {
              if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  outprintln(MESSAGE_CHANGE_PASSWORD_AT_LEAST3_DIGITS);
                  boolean generated = false;
                  if (YES.equals(
                      readline(
                          MESSAGE_WOULD_YOU_LIKE_TO_HAVE_A_GENERATED_GOOD_PASSWORD,
                          APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES))) {
                    clearCharArray(passwordForKey);
                    passwordForKey = null;
                    passwordForKey = getGeneratedGoodPassword();
                    generated = true;
                  } else {
                    readPassword(PASSWORD_TYPE_KEY, true, "");
                    generated = false;
                  }
                  int passwordPos = keyPos + key.length() + 1;
                  int nextKeyPos = -1;
                  for (int i = passwordPos; i < fileContent1Orig.length; i++) {
                    if (fileContent1Orig[i] == NEW_LINE_CHAR) {
                      nextKeyPos = i + 1;
                      break;
                    }
                  }
                  int toMoveFromPos = nextKeyPos - 1;
                  int toMoveDiff = passwordForKey.length - (nextKeyPos - passwordPos - 1);
                  if (toMoveDiff != 0) {
                    shiftFileContent(PASSWORD_TYPE_FILE1, toMoveFromPos, toMoveDiff);
                  }
                  for (int i = 0; i < passwordForKey.length; i++) {
                    fileContent1Orig[i + passwordPos] = passwordForKey[i];
                  }
                  if (generated) {
                    if (YES.equals(
                        readline(
                            MESSAGE_WOULD_YOU_LIKE_TO_READ_YOUR_GENERATED_GOOD_PASSWORD,
                            APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES))) {
                      passwordShowFile1(key);
                    }
                  }
                  char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                  clearCharArray(contentToLog);
                  String contentToLog0 =
                      getBeginningOfHistoryEntry()
                          + MESSAGE_LOG_PASSWORD_CHANGE
                          + fileName
                          + SEP1
                          + key
                          + SEP2;
                  int counter = 0;
                  for (int i = 0;
                      i < Math.min(contentToLog0.length(), APP_MAX_LENGTH_TO_LOG);
                      i++) {
                    contentToLog[i] = contentToLog0.charAt(i);
                    counter++;
                  }
                  for (int i = contentToLog0.length();
                      i
                          < Math.min(
                              contentToLog0.length() + passwordForKey.length,
                              APP_MAX_LENGTH_TO_LOG);
                      i++) {
                    contentToLog[i] = passwordForKey[i - contentToLog0.length()];
                    counter++;
                  }
                  contentToLog[counter] = NEW_LINE_CHAR;
                  doLog(contentToLog);
                  clearCharArray(contentToLog);
                  contentToLog = null;
                  contentToLog0 = null;
                  if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                    if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                      outprintln(MESSAGE_PASSWORD_HAS_BEEN_CHANGED);
                    }
                  }
                  generated = false;
                  toMoveFromPos = 0;
                  toMoveDiff = 0;
                  passwordPos = 0;
                  nextKeyPos = 0;
                }
              }
            }
          } else {
            outprintln(MESSAGE_KEY_IS_NOT_FOUND);
          }
          keyPos = 0;
        }
      }
    }
  }

  /**
   * Changes the storable-password type of the given file, first verifying that all stored passwords
   * remain valid when switching to the stricter type, then logging the change and saving both the
   * password file and the admin file after admin authentication.
   *
   * @param fileName the password file whose storable-password type should be changed
   */
  static final void executeCommandPasswordTypeChange(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      readPassword(PASSWORD_TYPE_FILE1, false, fileName);
      if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
        char allowNotesFile1Old = allowNotesFile1;
        readAllowNotesFile1();
        if (allowNotesFile1Old != allowNotesFile1) {
          int counter = 0;
          if (getNumOfKeysInContent(PASSWORD_TYPE_FILE1) > 0
              && allowNotesFile1 == ALLOW_NOTES_NO) {
            ArrayList<String> keys = getSortedKeyList(PASSWORD_TYPE_FILE1, "");
            if (keys == null) {
              throw systemexit("Error - keys is null, executeCommandPasswordTypeChange");
            }
            char[] aPassword = null;
            for (String aKey : keys) {
              if (aKey == null) {
                throw systemexit("Error - aKey is null, executeCommandPasswordTypeChange");
              }
              aPassword = getKeyPasswordFile1(aKey);
              if (aPassword == null) {
                throw systemexit("Error - aPassword is null, executeCommandPasswordTypeChange");
              }
              if (!isValidGoodPassword(aPassword, false)) {
                if (counter == 0) {
                  outprintln("");
                }
                outprintln(MESSAGE_KEY_HAS_NOT_VALID_GOOD_PASSWORD + aKey);
                counter++;
              }

              clearCharArray(aPassword);
              aPassword = null;
            }
            keys.clear();

            keys = null;
          }
          if (counter == 0) {
            if (readYesElseAnything(
                MESSAGE_SURE_CHANGE_TYPE_OF_PASSWORS,
                "" + NEW_LINE_CHAR + MESSAGE_TYPE_OF_PASSWORDS_WONT_BE_CHANGED)) {
              if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  fileContent1Orig[getHeaderLength(fileContent1Orig)] = allowNotesFile1;
                  char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                  clearCharArray(contentToLog);
                  String contentToLog0 =
                      getBeginningOfHistoryEntry()
                          + MESSAGE_LOG_PASSWORD_TYPE_CHANGE
                          + fileName
                          + SEP2
                          + allowNotesFile1
                          + NEW_LINE_CHAR;
                  prepareToLog(contentToLog, contentToLog0);
                  doLog(contentToLog);
                  clearCharArray(contentToLog);
                  contentToLog = null;
                  contentToLog0 = null;
                  if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                    if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                      outprintln(MESSAGE_TYPE_OF_STORABLE_PASSWORDS_HAS_BEEN_CHANGED);
                    }
                  }
                }
              }
            }
          } else {
            outprintln(MESSAGE_TYPE_OF_PASSWORDS_WONT_BE_CHANGED);
          }
          counter = 0;
        } else {
          outprintln(MESSAGE_THE_PASSWORD_TYPE_HAS_ALREADY_SET_TO_THIS);
        }
        allowNotesFile1Old = SPACE_CHAR;
      }
    }
  }

  /**
   * Prints the value stored under the given key on screen, then clears the screen. Whole passwords
   * are shown only after a "make sure nobody is around" confirmation; notes (file modes other than
   * full-passwords-only) are not secrecy-sensitive in the same way and are shown without it.
   *
   * @param key the key whose value should be displayed
   */
  static final void passwordShowFile1(String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (getKeyPos(PASSWORD_TYPE_FILE1, key) != -1) {
        boolean isNote = allowNotesFile1 != ALLOW_NOTES_NO;
        if (isNote || readYesElseAnything(MESSAGE_NOBODY_IS_AROUND, MESSAGE_OK)) {
          outprintln(isNote ? MESSAGE_YOUR_NOTE_IS : MESSAGE_YOUR_PASSWORD_IS);
          char[] thePassword = getKeyPasswordFile1(key);
          if (thePassword == null) {
            throw systemexit("Error - thePassword is null, passwordShowFile1");
          }
          for (int i = 0; i < thePassword.length; i++) {
            outprint(thePassword[i]);
            if (allowNotesFile1 == ALLOW_NOTES_NO) {
              outprint(SPACE_CHAR);
            }
          }
          clearCharArray(thePassword);
          thePassword = null;
          outprint(NEW_LINE_CHAR);
          if (!isNote) {
            outprintln(MESSAGE_CLOSE_THIS_WINDOW);
            displayCountdownStatus(APP_PASSWORD_SHOW_SECONDS);
            clearScreen(APP_NUM_OF_EMPTY_LINES_TO_CLEAR_THE_SCREEN);
            outprint(MESSAGE_SCREEN_HAS_BEEN_CLEARED_BUT);
            outprintln(MESSAGE_CLOSE_THIS_WINDOW);
          }
        }
      } else {
        outprintln(MESSAGE_KEY_IS_NOT_FOUND);
      }
    }
  }

  /**
   * Copies the password stored under the given key onto the system clipboard. Unlike the show
   * command it does not require a safe-screen confirmation. It then displays a countdown (giving
   * the user time to paste) and clears the password from the clipboard when the countdown ends.
   *
   * <p>Notes are not secrecy-sensitive in the same way as whole passwords, so for note files this
   * falls back to displaying the stored value on screen (as {@code password show} does) instead of
   * routing it through the clipboard.
   *
   * @param key the key whose password should be copied
   */
  static final void passwordCopyFile1(String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (getKeyPos(PASSWORD_TYPE_FILE1, key) != -1) {
        if (allowNotesFile1 != ALLOW_NOTES_NO) {
          passwordShowFile1(key);
        } else {
          char[] thePassword = getKeyPasswordFile1(key);
          if (thePassword == null) {
            throw systemexit("Error - thePassword is null, passwordCopyFile1");
          }
          if (copyToClipboard(thePassword)) {
            outprintln(MESSAGE_PASSWORD_HAS_BEEN_COPIED);
            outprintln(MESSAGE_PASTE_IT_NOW);
            displayCountdownStatus(APP_CLIPBOARD_CLEAR_SECONDS);
            clearClipboard();
            outprintln(MESSAGE_CLIPBOARD_HAS_BEEN_CLEARED);
          }
          clearCharArray(thePassword);
          thePassword = null;
        }
      } else {
        outprintln(MESSAGE_KEY_IS_NOT_FOUND);
      }
    }
  }

  /**
   * Extracts and returns the password characters stored under the given key from the decrypted file
   * content.
   *
   * @param key the key whose password should be retrieved
   * @return the password characters for the key, or an empty array if the key is invalid or not
   *     found
   */
  static final char[] getKeyPasswordFile1(String key) {
    char[] thePassword = new char[0];
    if (isValidKeyOrFileName(key, false)) {
      int keyPos = getKeyPos(PASSWORD_TYPE_FILE1, key);
      if (keyPos != -1) {
        int passwordLength = 0;
        if (fileContent1Orig == null) {
          throw systemexit("Error - fileContent1Orig is null, getKeyPasswordFile1");
        }
        for (int i = keyPos + key.length() + 1; i < fileContent1Orig.length; i++) {
          if (fileContent1Orig[i] != NEW_LINE_CHAR) {
            passwordLength++;
          } else {
            break;
          }
        }
        thePassword = new char[passwordLength];
        for (int i = 0; i < thePassword.length; i++) {
          thePassword[i] = fileContent1Orig[keyPos + key.length() + 1 + i];
        }
        passwordLength = 0;
      }
      keyPos = 0;
    }
    return thePassword;
  }
}
