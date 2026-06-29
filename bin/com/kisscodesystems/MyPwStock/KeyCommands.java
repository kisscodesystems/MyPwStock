package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.Log.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.PasswordCommands.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.util.ArrayList;
import java.util.Collections;

/**
 * Command handlers for key operations within a password-container file (list, search, add, change,
 * delete, deleteall, move, moveall), together with their supporting helpers.
 */
final class KeyCommands {
  /**
   * Lists all keys stored in the given password file by delegating to the list/search helper with
   * an empty search term.
   *
   * @param fileName the password-container file whose keys are listed
   */
  static final void executeCommandKeyList(String fileName) {
    keyListOrSearch(fileName, "");
  }

  /**
   * Searches the keys in the given password file for those matching the search term by delegating
   * to the list/search helper.
   *
   * @param fileName the password-container file to search
   * @param toSearch the substring to match key names against
   */
  static final void executeCommandKeySearch(String fileName, String toSearch) {
    keyListOrSearch(fileName, toSearch);
  }

  /**
   * Adds a new key and its password to the given password file, optionally generating a strong
   * password, then logs the action and saves both the password file and the admin file. Aborts on
   * inconsistent state and reports when the key exists or the file is full.
   *
   * @param fileName the password-container file to add the key to
   */
  static final void executeCommandKeyAdd(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      readPassword(PASSWORD_TYPE_FILE1, false, fileName);
      if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
        if (getNumOfKeysInContent(PASSWORD_TYPE_FILE1) < APP_MAX_NUM_OF_KEYS_PER_FILE) {
          int currIndex = getFirstPadCharIndexBefore(fileContent1Orig) + 1;
          if (!(currIndex >= getHeaderLength(fileContent1Orig) + 1 + 1)) {
            throw systemexit("Error - currIndex is negative, executeCommandKeyAdd");
          }
          readKeyFile1();
          if (getKeyPos(PASSWORD_TYPE_FILE1, key1) == -1) {
            if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
              readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
              if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
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

                if (passwordForKey == null) {
                  throw systemexit("Error, passwordForKey is null, executeCommandKeyAdd");
                } else if (passwordForKey.length == 0) {
                  throw systemexit("Error, passwordForKey is empty, executeCommandKeyAdd");
                }
                if (key1 == null) {
                  throw systemexit("Error - key1 is null, executeCommandKeyAdd");
                }
                for (int i = 0 + currIndex; i < key1.length() + currIndex; i++) {
                  fileContent1Orig[i] = key1.charAt(i - currIndex);
                }
                currIndex = currIndex + key1.length();
                fileContent1Orig[currIndex] = NEW_LINE_CHAR;
                currIndex++;
                for (int i = 0 + currIndex; i < passwordForKey.length + currIndex; i++) {
                  fileContent1Orig[i] = passwordForKey[i - currIndex];
                }
                currIndex = currIndex + passwordForKey.length;
                fileContent1Orig[currIndex] = NEW_LINE_CHAR;
                if (generated) {
                  if (YES.equals(
                      readline(
                          MESSAGE_WOULD_YOU_LIKE_TO_READ_YOUR_GENERATED_GOOD_PASSWORD,
                          APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES))) {
                    passwordShowFile1(key1);
                  }
                }
                char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                clearCharArray(contentToLog);
                String contentToLog0 =
                    getBeginningOfHistoryEntry()
                        + MESSAGE_LOG_KEY_ADD
                        + fileName
                        + SEP1
                        + key1
                        + SEP2;
                int counter = 0;
                for (int i = 0; i < Math.min(contentToLog0.length(), APP_MAX_LENGTH_TO_LOG); i++) {
                  contentToLog[i] = contentToLog0.charAt(i);
                  counter++;
                }
                for (int i = contentToLog0.length();
                    i
                        < Math.min(
                            contentToLog0.length() + passwordForKey.length, APP_MAX_LENGTH_TO_LOG);
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
                    outprintln(MESSAGE_KEY_HAS_BEEN_ADDED);
                  }
                }

                generated = false;
              }
            }
          } else {
            outprintln(MESSAGE_NEW_KEY_ALREADY_EXISTS);
          }

          currIndex = 0;
        } else {
          outprintln(MESSAGE_TOO_MANY_KEYS_IN_FILE);
        }
      }
    }
  }

  /**
   * Renames an existing key in the given password file, shifting the file content to fit the new
   * key length, then logs the change and saves the password file and admin file. Validates names,
   * requires confirmation, and reports when the key is missing or the new name already exists.
   *
   * @param fileName the password-container file holding the key
   * @param currentKeyName the existing key name to rename
   * @param newKeyName the new key name
   */
  static final void executeCommandKeyChange(
      String fileName, String currentKeyName, String newKeyName) {
    if (isValidKeyOrFileName(currentKeyName, true) && isValidKeyOrFileName(newKeyName, true)) {
      if (!currentKeyName.equals(newKeyName)) {
        if (isExistingPasswordFile(fileName, true)) {
          readPassword(PASSWORD_TYPE_FILE1, false, fileName);
          if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
            int currentKeyPos = getKeyPos(PASSWORD_TYPE_FILE1, currentKeyName);
            int newKeyPos = getKeyPos(PASSWORD_TYPE_FILE1, newKeyName);
            if (currentKeyPos == -1) {
              outprintln(MESSAGE_KEY_IS_NOT_FOUND);
            } else if (newKeyPos != -1) {
              outprintln(MESSAGE_NEW_KEY_ALREADY_EXISTS);
            } else {
              if (readYesElseAnything(
                  MESSAGE_SURE_CHANGE_KEY + currentKeyName + MESSAGE_SURE2,
                  MESSAGE_KEY_WONT_BE_CHANGED)) {
                if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                  readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                  if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                    int toMoveFromPos = currentKeyPos + currentKeyName.length();
                    int toMoveDiff = newKeyName.length() - currentKeyName.length();
                    if (toMoveDiff != 0) {
                      shiftFileContent(PASSWORD_TYPE_FILE1, toMoveFromPos, toMoveDiff);
                    }
                    for (int i = 0; i < newKeyName.length(); i++) {
                      fileContent1Orig[i + currentKeyPos] = newKeyName.charAt(i);
                    }
                    char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                    clearCharArray(contentToLog);
                    String contentToLog0 =
                        getBeginningOfHistoryEntry()
                            + MESSAGE_LOG_KEY_CHANGE
                            + fileName
                            + SEP1
                            + currentKeyName
                            + SEP2
                            + newKeyName
                            + NEW_LINE_CHAR;
                    prepareToLog(contentToLog, contentToLog0);
                    doLog(contentToLog);
                    clearCharArray(contentToLog);
                    contentToLog = null;
                    contentToLog0 = null;
                    if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                      if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                        outprintln(MESSAGE_KEY_HAS_BEEN_CHANGED);
                      }
                    }
                    toMoveFromPos = 0;
                    toMoveDiff = 0;
                  }
                }
              }
            }
            newKeyPos = 0;
            currentKeyPos = 0;
          }
        }
      } else {
        outprintln(MESSAGE_NEW_KEY_NAME_HAVE_TO_BE_DIFFERENT);
      }
    }
  }

  /**
   * Deletes a single key and its password from the given password file after confirmation, then
   * saves the password file and admin file. Aborts if the deleted content is null or empty and
   * reports when the key is not found.
   *
   * @param fileName the password-container file holding the key
   * @param key the name of the key to delete
   */
  static final void executeCommandKeyDelete(String fileName, String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (isExistingPasswordFile(fileName, true)) {
        readPassword(PASSWORD_TYPE_FILE1, false, fileName);
        if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
          int keyPos = getKeyPos(PASSWORD_TYPE_FILE1, key);
          if (keyPos != -1) {
            if (readYesElseAnything(
                MESSAGE_SURE_DELETE_KEY + key + MESSAGE_SURE2, MESSAGE_KEY_IS_STILL_THERE)) {
              if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  char[] deletedContent = keyDelete(PASSWORD_TYPE_FILE1, key, keyPos, fileName);
                  if (deletedContent == null) {
                    throw systemexit("Error - deletedContent is null, executeCommandKeyDelete");
                  }
                  if (!(deletedContent.length > 0)) {
                    throw systemexit("Error - deletedContent is empty, executeCommandKeyDelete");
                  }
                  if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                    if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                      outprintln(MESSAGE_KEY_HAS_BEEN_DELETED);
                    }
                  }

                  clearCharArray(deletedContent);
                  deletedContent = null;
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
   * Deletes all keys from the given password file after confirmation by blanking the key region
   * with space characters, then logs the action and saves the password file and admin file. Reports
   * when the file contains no keys.
   *
   * @param fileName the password-container file to clear
   */
  static final void executeCommandKeyDeleteall(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      readPassword(PASSWORD_TYPE_FILE1, false, fileName);
      if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
        if (readYesElseAnything(MESSAGE_SURE_DELETE_KEYS, MESSAGE_KEYS_ARE_STILL_THERE)) {
          if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
            readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
            if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              int lastNonSpaceCharIndexOrig = getFirstPadCharIndexBefore(fileContent1Orig);
              int headerLen = getHeaderLength(fileContent1Orig);
              if (lastNonSpaceCharIndexOrig > headerLen + 1) {
                for (int i = headerLen + 2; i <= lastNonSpaceCharIndexOrig; i++) {
                  fileContent1Orig[i] = NUL_CHAR;
                }
                char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                clearCharArray(contentToLog);
                String contentToLog0 =
                    getBeginningOfHistoryEntry()
                        + MESSAGE_LOG_KEYS_DELETE
                        + fileName
                        + NEW_LINE_CHAR;
                prepareToLog(contentToLog, contentToLog0);
                doLog(contentToLog);
                clearCharArray(contentToLog);
                contentToLog = null;
                contentToLog0 = null;
                if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                  if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                    outprintln(MESSAGE_KEYS_HAS_BEEN_DELETED);
                  }
                }
                lastNonSpaceCharIndexOrig = 0;
              } else {
                outprintln(MESSAGE_FILE_DOES_NOT_CONTAIN_ANY_KEY);
              }
            }
          }
        }
      }
    }
  }

  /**
   * Moves a single key from one password file to another after reading both files' passwords and
   * confirming, delegating the move and saving to the helper. Validates that the files differ and
   * are compatible.
   *
   * @param currentFileName the source password-container file
   * @param newFileName the destination password-container file
   * @param key the name of the key to move
   */
  static final void executeCommandKeyMove(String currentFileName, String newFileName, String key) {
    if (isValidKeyOrFileName(key, true)) {
      if (isExistingPasswordFile(currentFileName, true)) {
        if (isExistingPasswordFile(newFileName, true)) {
          if (!currentFileName.equals(newFileName)) {
            outprintln(MESSAGE_PASSWORD_FROM_FILE + currentFileName);
            readPassword(PASSWORD_TYPE_FILE1, false, currentFileName);
            outprintln(MESSAGE_PASSWORD_INTO_FILE + newFileName);
            readPassword(PASSWORD_TYPE_FILE2, false, newFileName);
            if (getFileContent(currentFileName, PASSWORD_TYPE_FILE1)) {
              if (getFileContent(newFileName, PASSWORD_TYPE_FILE2)) {
                if (allowNotesFile1 == allowNotesFile2) {
                  if (readYesElseAnything(
                      MESSAGE_SURE_MOVE_KEY + key + MESSAGE_SURE2, MESSAGE_KEY_IS_STILL_THERE)) {
                    if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                      readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                      if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                        keyMove(currentFileName, newFileName, key, true);
                      }
                    }
                  }
                } else {
                  outprintln(MESSAGE_INCOMPATIBLE_FILES);
                }
              }
            }
          } else {
            outprintln(MESSAGE_FILES_HAVE_TO_BE_DIFFERENT);
          }
        }
      }
    }
  }

  /**
   * Moves all keys from one password file to another after confirmation, iterating over the sorted
   * key list and saving both files plus the admin file. Validates that the files differ and are
   * compatible and reports when the source is empty.
   *
   * @param currentFileName the source password-container file
   * @param newFileName the destination password-container file
   */
  static final void executeCommandKeyMoveall(String currentFileName, String newFileName) {
    if (isExistingPasswordFile(currentFileName, true)) {
      if (isExistingPasswordFile(newFileName, true)) {
        if (!currentFileName.equals(newFileName)) {
          outprintln(MESSAGE_PASSWORD_FROM_FILE + currentFileName);
          readPassword(PASSWORD_TYPE_FILE1, false, currentFileName);
          if (getFileContent(currentFileName, PASSWORD_TYPE_FILE1)) {
            if (getNumOfKeysInContent(PASSWORD_TYPE_FILE1) > 0) {
              outprintln(MESSAGE_PASSWORD_INTO_FILE + newFileName);
              readPassword(PASSWORD_TYPE_FILE2, false, newFileName);
              if (getFileContent(newFileName, PASSWORD_TYPE_FILE2)) {
                if (allowNotesFile1 == allowNotesFile2) {
                  if (readYesElseAnything(MESSAGE_SURE_MOVE_KEYS, MESSAGE_KEYS_ARE_STILL_THERE)) {
                    if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
                      readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
                      if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                        ArrayList<String> keys = getSortedKeyList(PASSWORD_TYPE_FILE1, "");
                        if (keys == null) {
                          throw systemexit("Error - keys is null, executeCommandKeyMoveall");
                        }
                        int counter = 0;
                        for (String aKey : keys) {
                          if (counter == 0) {
                            outprintln("");
                          }
                          keyMove(currentFileName, newFileName, aKey, false);
                          counter++;
                        }
                        if (saveFile(newFileName, PASSWORD_TYPE_FILE2)
                            && saveFile(currentFileName, PASSWORD_TYPE_FILE1)) {
                          if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                            outprintln(MESSAGE_KEYS_HAS_BEEN_HANDLED);
                          }
                        }
                        keys.clear();

                        keys = null;
                      }
                    }
                  }
                } else {
                  outprintln(MESSAGE_INCOMPATIBLE_FILES);
                }
              }
            } else {
              outprintln(MESSAGE_FROM_FILE_EMPTY);
            }
          }
        } else {
          outprintln(MESSAGE_FILES_HAVE_TO_BE_DIFFERENT);
        }
      }
    }
  }

  /**
   * Reads and decrypts the given password file, then prints the sorted (optionally filtered) key
   * names along with counts and the number of remaining available key slots. Aborts on null key
   * list or null key entries.
   *
   * @param fileName the password-container file to read
   * @param toSearch the substring filter for key names, or empty to list all keys
   */
  static final void keyListOrSearch(String fileName, String toSearch) {
    if (isExistingPasswordFile(fileName, true)) {
      readPassword(PASSWORD_TYPE_FILE1, false, fileName);
      if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
        ArrayList<String> keys = getSortedKeyList(PASSWORD_TYPE_FILE1, toSearch);
        if (keys == null) {
          throw systemexit("Error - keys is null, keyListOrSearch");
        }
        int keyCounter = 0;
        for (String aKey : keys) {
          if (aKey == null) {
            throw systemexit("Error - aKey is null, keyListOrSearch");
          }
          if (keyCounter == 0) {
            outprintln("");
          }
          outprintln(FOLD + FOLD2 + aKey);
          keyCounter++;
        }
        if (keyCounter == 0) {
          outprintln(MESSAGE_NO_KEYS_HAVE_BEEN_FOUND);
        } else if (keyCounter == 1) {
          outprintln(MESSAGE_KEY_COUNT_HAS_BEEN_FOUND);
        } else {
          outprintln(NEW_LINE_CHAR + FOLD + keyCounter + MESSAGE_KEYS_COUNT_FOUND);
        }
        if ("".equals(toSearch)) {
          outprintln(MESSAGE_AVAILABLE_KEYS_COUNT + (APP_MAX_NUM_OF_KEYS_PER_FILE - keyCounter));
        }
        keyCounter = 0;
        keys.clear();

        keys = null;
      }
    }
  }

  /**
   * Removes the key/password block starting at the given position from the in-memory file content,
   * shifting subsequent content to fill the gap, logs the deletion, and returns the removed block.
   * Aborts on a negative position, null content, or an invalid computed range.
   *
   * @param passwordType selects which in-memory file content (file 1 or file 2) to operate on
   * @param key the name of the key being deleted
   * @param keyPos the start index of the key within the file content
   * @param fileName the password-container file name, used for logging
   * @return the removed key/password content as a char array
   */
  static final char[] keyDelete(String passwordType, String key, int keyPos, String fileName) {
    char[] deletedContent = new char[0];
    if (!(keyPos > -1)) {
      throw systemexit("Error - keyPos is negative, keyDelete");
    }
    if (isValidKeyOrFileName(key, false) && isValidKeyOrFileName(fileName, false)) {
      int newLineCounter = 0;
      int nextKeyPos = -1;
      char[] fileContentOrig = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        fileContentOrig = fileContent1Orig;
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        fileContentOrig = fileContent2Orig;
      }

      if (fileContentOrig == null) {
        throw systemexit("Error - fileContentOrig is null, keyDelete");
      }
      for (int i = keyPos; i < fileContentOrig.length; i++) {
        if (fileContentOrig[i] == NEW_LINE_CHAR) {
          newLineCounter++;
        }
        if (newLineCounter == 2) {
          nextKeyPos = i + 1;
          break;
        }
      }
      if (!(nextKeyPos - keyPos > -1)) {
        throw systemexit("Error - nextKeyPos - keyPos is negative, keyDelete");
      }
      deletedContent = new char[nextKeyPos - keyPos];
      for (int i = keyPos; i < nextKeyPos; i++) {
        deletedContent[i - keyPos] = fileContentOrig[i];
      }
      int toMoveFromPos = nextKeyPos;
      int toMoveDiff = keyPos - nextKeyPos;
      if (toMoveDiff != 0) {
        shiftFileContent(PASSWORD_TYPE_FILE1, toMoveFromPos, toMoveDiff);
      }
      toMoveFromPos = 0;
      toMoveDiff = 0;
      char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
      clearCharArray(contentToLog);
      String contentToLog0 =
          getBeginningOfHistoryEntry()
              + MESSAGE_LOG_KEY_DELETE
              + fileName
              + SEP1
              + key
              + NEW_LINE_CHAR;
      prepareToLog(contentToLog, contentToLog0);
      doLog(contentToLog);
      clearCharArray(contentToLog);
      contentToLog = null;
      contentToLog0 = null;

      newLineCounter = 0;
      nextKeyPos = -1;
      fileContentOrig = null;
    }

    return deletedContent;
  }

  /**
   * Moves a single key from file 1's content to file 2's content by deleting it from the source and
   * appending it to the destination, logging the move and optionally saving both files and the
   * admin file. Aborts on inconsistent state and reports when the key is missing, already present
   * in the destination, or the destination is full.
   *
   * @param currentFileName the source password-container file name
   * @param newFileName the destination password-container file name
   * @param key the name of the key to move
   * @param toSave whether to save the files after moving (true for single move, false for batch)
   */
  static final void keyMove(
      String currentFileName, String newFileName, String key, boolean toSave) {
    if (isValidKeyOrFileName(currentFileName, false)
        && isValidKeyOrFileName(newFileName, false)
        && isValidKeyOrFileName(key, false)) {
      int keyPosInCurrent = getKeyPos(PASSWORD_TYPE_FILE1, key);
      if (keyPosInCurrent != -1) {
        int keyPosInNew = getKeyPos(PASSWORD_TYPE_FILE2, key);
        if (keyPosInNew == -1) {
          if (getNumOfKeysInContent(PASSWORD_TYPE_FILE2) < APP_MAX_NUM_OF_KEYS_PER_FILE) {
            char[] deletedContent =
                keyDelete(PASSWORD_TYPE_FILE1, key, keyPosInCurrent, currentFileName);
            if (deletedContent == null) {
              throw systemexit("Error - deletedContent is null, KeyMove");
            }
            if (!(deletedContent.length > 0)) {
              throw systemexit("Error - deletedContent is empty, keyMove");
            }
            if (fileContent2Orig == null) {
              throw systemexit("Error - fileContent2Orig is null, keyMove");
            }
            if (!(fileContent2Orig.length > 0)) {
              throw systemexit("Error - fileContent2Orig is empty, keyMove");
            }
            int posToAppend = getFirstPadCharIndexBefore(fileContent2Orig) + 1;
            if (!(posToAppend > -1)) {
              throw systemexit("Error - key pos is negative, keyMove");
            }
            if (!(posToAppend + 1 + deletedContent.length < fileContent2Orig.length)) {
              throw systemexit("Error - content is too long to move, keyMove");
            }
            for (int i = 0; i < deletedContent.length; i++) {
              fileContent2Orig[posToAppend + i] = deletedContent[i];
            }
            char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
            clearCharArray(contentToLog);
            String contentToLog0 =
                getBeginningOfHistoryEntry()
                    + MESSAGE_LOG_KEY_MOVE
                    + currentFileName
                    + SEP1
                    + newFileName
                    + SEP1
                    + key
                    + NEW_LINE_CHAR;
            prepareToLog(contentToLog, contentToLog0);
            doLog(contentToLog);
            clearCharArray(contentToLog);
            contentToLog = null;
            contentToLog0 = null;
            if (toSave) {
              if (saveFile(newFileName, PASSWORD_TYPE_FILE2)
                  && saveFile(currentFileName, PASSWORD_TYPE_FILE1)) {
                if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  outprintln("");
                  outprintln(MESSAGE_KEY_HAS_BEEN_MOVED_WITH_FILE_SAVING + key);
                }
              }
            } else {
              outprintln(MESSAGE_KEY_HAS_BEEN_MOVED + key);
            }
            posToAppend = 0;

            clearCharArray(deletedContent);
            deletedContent = null;
          } else {
            if (toSave) {
              outprintln("");
            }
            outprintln(MESSAGE_TOO_MANY_KEYS_IN_FILE_NEW);
          }
        } else {
          if (toSave) {
            outprintln("");
          }
          outprintln(MESSAGE_KEY_FOUND_IN_NEW + key);
        }
        keyPosInNew = 0;
      } else {
        if (toSave) {
          outprintln("");
        }
        outprintln(MESSAGE_KEY_IS_NOT_FOUND_IN_CURRENT + key);
      }
      keyPosInCurrent = 0;
    }
  }

  /**
   * Parses the selected in-memory file content to extract key names, filtering them by the optional
   * search term, and returns the matching names sorted alphabetically. Aborts if the file content
   * is null.
   *
   * @param passwordType selects which in-memory file content (file 1 or file 2) to parse
   * @param toSearch the case-insensitive substring filter, or empty to include all keys
   * @return a sorted list of matching key names (empty if the search term is invalid)
   */
  static final ArrayList<String> getSortedKeyList(String passwordType, String toSearch) {
    ArrayList<String> keys = new ArrayList<String>();
    if (isASCIIandNONSPACE(toSearch)) {
      String key = "";
      boolean inKey = true;
      int newLineCounter = 0;
      char[] fileContentOrig = null;
      if (PASSWORD_TYPE_FILE1.equals(passwordType)) {
        fileContentOrig = fileContent1Orig;
      } else if (PASSWORD_TYPE_FILE2.equals(passwordType)) {
        fileContentOrig = fileContent2Orig;
      }
      if (fileContentOrig == null) {
        throw systemexit("Error - fileContentOrig is null, getSortedKeyList");
      }
      for (int i = 0; i < fileContentOrig.length; i++) {
        if (newLineCounter >= 2) {
          if (fileContentOrig[i] != NUL_CHAR) {
            if (fileContentOrig[i] != NEW_LINE_CHAR) {
              if (inKey) {
                key = key + fileContentOrig[i];
              }
            } else {
              inKey = !inKey;
              if (!"".equals(key)) {
                if ("".equals(toSearch)
                    || (!"".equals(toSearch)
                        && key.toLowerCase().contains(toSearch.toLowerCase()))) {
                  keys.add(key);
                }
                key = "";
              }
            }
          } else {
            break;
          }
        }
        if (fileContentOrig[i] == NEW_LINE_CHAR) {
          newLineCounter++;
        }
      }
      Collections.sort(keys);

      key = "";
      inKey = false;
      newLineCounter = 0;
      fileContentOrig = null;
    }
    return keys;
  }
}
