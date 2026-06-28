package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.Log.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.io.File;

/**
 * Command handlers for password-container files (list, search, add, describe, password change,
 * delete, deleteall) together with their supporting helpers.
 */
final class FileCommands {
  /** Lists all password-container files in the password directory. */
  static final void executeCommandFileList() {
    fileListOrSearch("", passwordDirFolder, false);
  }

  /**
   * Lists the password-container files in the password directory whose names match the given search
   * term.
   *
   * @param toSearch substring to match against file names
   */
  static final void executeCommandFileSearch(String toSearch) {
    fileListOrSearch(toSearch, passwordDirFolder, false);
  }

  /**
   * Creates a new empty password-container file: validates the name, enforces the file-count limit
   * and uniqueness, authenticates the admin file, builds the file header, logs the action and saves
   * both the new file and the admin file.
   *
   * @param fileName name of the password-container file to create
   */
  static final void executeCommandFileAdd(String fileName) {
    if (isValidKeyOrFileName(fileName, true)) {
      int counter = countPasswordContainerFiles(passwordDirFolder);
      boolean exists = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX).isFile();
      if (counter >= APP_MAX_NUM_OF_FILES) {
        outprintln(MESSAGE_TOO_MANY_FILES);
      } else if (exists) {
        outprintln(MESSAGE_FILE_ALREADY_EXISTS);
      } else {
        if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
          readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
          if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
            outprintln(MESSAGE_DO_NOT_FORGET_YOUR_FILE_PASSWORD);
            readPassword(PASSWORD_TYPE_FILE1, true, fileName);
            clearCharArray(fileContent1Orig);
            // A fresh char[] is NUL-filled by default, which is the password-file padding sentinel,
            // so the buffer is left NUL-padded (no space-fill) and note values may contain spaces.
            fileContent1Orig = new char[APP_FILE_CONTENT_MAX_LENGTH];
            counter = 0;
            char[] header = generateRandomHeader();
            for (int i = 0; i < header.length; i++) {
              fileContent1Orig[i] = header[i];
              counter++;
            }
            header = null;
            readAllowNotesFile1();
            fileContent1Orig[counter] = allowNotesFile1;
            counter++;
            fileContent1Orig[counter] = NEW_LINE_CHAR;
            char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
            clearCharArray(contentToLog);
            String contentToLog0 =
                getBeginningOfHistoryEntry() + MESSAGE_LOG_FILE_ADD + fileName + SEP2;
            counter = 0;
            for (int i = 0; i < Math.min(contentToLog0.length(), APP_MAX_LENGTH_TO_LOG); i++) {
              contentToLog[i] = contentToLog0.charAt(i);
              counter++;
            }
            for (int i = contentToLog0.length();
                i
                    < Math.min(
                        contentToLog0.length() + passwordForFile1.length, APP_MAX_LENGTH_TO_LOG);
                i++) {
              contentToLog[i] = passwordForFile1[i - contentToLog0.length()];
              counter++;
            }
            contentToLog[counter] = NEW_LINE_CHAR;
            doLog(contentToLog);
            clearCharArray(contentToLog);
            contentToLog = null;
            contentToLog0 = null;
            if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
              if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                outprintln(MESSAGE_FILE_HAS_BEEN_CREATED);
              }
            }
          }
        }
      }
      exists = false;
      counter = 0;
    }
  }

  /**
   * Counts the password-container files (those whose names end with the password-file postfix) in
   * the given folder.
   *
   * @param folder the directory to scan
   * @return the number of password-container files found
   */
  static final int countPasswordContainerFiles(File folder) {
    int counter = 0;
    if (folder == null) {
      throw systemexit("Error - folder is null, countPasswordContainerFiles");
    }
    File[] passwordFiles = folder.listFiles();
    if (passwordFiles == null) {
      throw systemexit("Error - passwordFiles is null, countPasswordContainerFiles");
    }
    for (File passwordFile : passwordFiles) {
      if (passwordFile == null) {
        throw systemexit("Error - passwordFile is null, countPasswordContainerFiles");
      }
      if (passwordFile.getName() == null) {
        throw systemexit("Error - passwordFile . getName ( ) is null, countPasswordContainerFiles");
      }
      if (passwordFile.isFile() && passwordFile.getName().endsWith(APP_PD_POSTFIX)) {
        counter++;
      }
    }

    passwordFiles = null;
    return counter;
  }

  /**
   * Prints metadata about a password-container file: last-modified date, size, number of keys and
   * its password type, after reading and decrypting its content.
   *
   * @param fileName name of the password-container file to describe
   */
  static final void executeCommandFileDescribe(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      readPassword(PASSWORD_TYPE_FILE1, false, fileName);
      if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
        File file = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX);
        outprintln(
            MESSAGE_DESCRIBE_FILE_LAST_MODIFIED + SIMPLE_DATE_FORMAT.format(file.lastModified()));
        outprintln(MESSAGE_DESCRIBE_FILE_SIZE + Math.round(file.length() / 1024));
        outprintln(MESSAGE_DESCRIBE_FILE_NUM_OF_KEYS + getNumOfKeysInContent(PASSWORD_TYPE_FILE1));
        outprintln(
            MESSAGE_DESCRIBE_FILE_PASSWORD_TYPE
                + (allowNotesFile1 == ALLOW_NOTES_NO
                    ? MESSAGE_ALLOW_FULL_PASSWORDS_ONLY
                    : MESSAGE_ALLOW_NOTES_AND_FULL_PASSWORDS));

        file = null;
      }
    }
  }

  /**
   * Changes the password protecting a password-container file: confirms the action, reads the
   * current content, authenticates the admin file, reads the new password, logs the change and
   * re-saves both the file and the admin file.
   *
   * @param fileName name of the password-container file whose password is changed
   */
  static final void executeCommandFilePasswordChange(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      if (readYesElseAnything(
          MESSAGE_SURE_CHANGE_FILE_PASSWORD + fileName + MESSAGE_SURE2,
          MESSAGE_FILE_PASSWORD_WONT_BE_CHANGED)) {
        readPassword(PASSWORD_TYPE_FILE1, false, fileName);
        if (getFileContent(fileName, PASSWORD_TYPE_FILE1)) {
          if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
            readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
            if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              outprintln(MESSAGE_DO_NOT_FORGET_YOUR_FILE_PASSWORD);
              readPassword(PASSWORD_TYPE_FILE1, true, fileName);
              char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
              clearCharArray(contentToLog);
              String contentToLog0 =
                  getBeginningOfHistoryEntry() + MESSAGE_LOG_FILE_PASSWORD_CHANGE + fileName + SEP2;
              int counter = 0;
              for (int i = 0; i < Math.min(contentToLog0.length(), APP_MAX_LENGTH_TO_LOG); i++) {
                contentToLog[i] = contentToLog0.charAt(i);
                counter++;
              }
              for (int i = contentToLog0.length();
                  i
                      < Math.min(
                          contentToLog0.length() + passwordForFile1.length, APP_MAX_LENGTH_TO_LOG);
                  i++) {
                contentToLog[i] = passwordForFile1[i - contentToLog0.length()];
                counter++;
              }
              contentToLog[counter] = NEW_LINE_CHAR;
              doLog(contentToLog);
              clearCharArray(contentToLog);
              contentToLog = null;
              contentToLog0 = null;
              if (saveFile(fileName, PASSWORD_TYPE_FILE1)) {
                if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  outprintln(MESSAGE_FILE_PASSWORD_HAS_BEEN_CHANGED);
                }
              }
              counter = 0;
            }
          }
        }
      }
    }
  }

  /**
   * Deletes a password-container file together with its salt and IV side files: confirms the
   * action, authenticates the admin file, deletes the files, purges any cached password, logs the
   * deletion and re-saves the admin file.
   *
   * @param fileName name of the password-container file to delete
   */
  static final void executeCommandFileDelete(String fileName) {
    if (isExistingPasswordFile(fileName, true)) {
      if (readYesElseAnything(
          MESSAGE_SURE_DELETE_FILE + fileName + MESSAGE_SURE2, MESSAGE_FILE_WONT_BE_DELETED)) {
        if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
          readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
          if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
            File file = new File(APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX);
            if (file.delete()) {
              char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
              clearCharArray(contentToLog);
              String contentToLog0 =
                  getBeginningOfHistoryEntry() + MESSAGE_LOG_FILE_DELETE + fileName + NEW_LINE_CHAR;
              prepareToLog(contentToLog, contentToLog0);
              doLog(contentToLog);
              clearCharArray(contentToLog);
              contentToLog = null;
              contentToLog0 = null;
              if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                outprintln(MESSAGE_FILE_HAS_BEEN_DELETED);
                File slFile = new File(APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX);
                if (slFile.delete()) {
                  outprintln(MESSAGE_FILE_HAS_BEEN_DELETED_SL);
                } else {
                  outprintln(MESSAGE_FILE_HAS_NOT_BEEN_DELETED_SL);
                }
                File ivFile = new File(APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX);
                if (ivFile.delete()) {
                  outprintln(MESSAGE_FILE_HAS_BEEN_DELETED_IV);
                } else {
                  outprintln(MESSAGE_FILE_HAS_NOT_BEEN_DELETED_IV);
                }
                if (toCachePasswords) {
                  purgeCachedFilePassword(fileName);
                }
                slFile = null;
                ivFile = null;
              }
            } else {
              outprintln(MESSAGE_FILE_HAS_NOT_BEEN_DELETED);
            }

            file = null;
          }
        }
      }
    }
  }

  /**
   * Deletes all password-container files: confirms the action, authenticates the admin file,
   * removes every container file and re-saves the admin file.
   */
  static final void executeCommandFileDeleteall() {
    if (readYesElseAnything(MESSAGE_SURE_DELETE_ALL_FILES, MESSAGE_ALL_FILES_ARE_STILL_THERE)) {
      if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
        readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
        if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
          if (deleteAllPasswordContainerFiles()) {
            if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              outprintln(MESSAGE_ALL_FILES_HAVE_BEEN_DELETED);
            }
          }
        }
      }
    }
  }

  /**
   * Prints the password-container files in the given folder, optionally filtered by a search term,
   * followed by a count message and (unless searching or in backup mode) the number of remaining
   * available file slots.
   *
   * @param toSearch substring to match against file names, or empty string to list all
   * @param folder directory to scan for password-container files
   * @param inBackup whether the listing is performed in the backup context
   */
  static final void fileListOrSearch(String toSearch, File folder, boolean inBackup) {
    int counter = 0;
    if (folder == null) {
      throw systemexit("Error - folder is null, fileListOrSearch");
    }
    File[] passwordFiles = folder.listFiles();
    if (passwordFiles == null) {
      throw systemexit("Error - passwordFiles is null, fileListOrSearch");
    }
    for (File passwordFile : passwordFiles) {
      if (passwordFile == null) {
        throw systemexit("Error - passwordFile is null, fileListOrSearch");
      }
      if (passwordFile.exists() && passwordFile.isFile()) {
        if (passwordFile.getName() == null) {
          throw systemexit("Error - passwordFileGetName is null, fileListOrSearch");
        }
        if (passwordFile.getName().endsWith(APP_PD_POSTFIX)) {
          if (toSearch == null) {
            throw systemexit("Error - toSearch is null, fileListOrSearch");
          }
          if ("".equals(toSearch)
              || (!"".equals(toSearch)
                  && passwordFile.getName().toLowerCase().contains(toSearch.toLowerCase()))) {
            if (counter == 0) {
              outprintln("");
            }
            outprintln(
                FOLD
                    + FOLD2
                    + passwordFile
                        .getName()
                        .substring(0, passwordFile.getName().length() - APP_PD_POSTFIX.length()));
            counter++;
          }
        }
      }
    }
    if (counter == 0) {
      outprintln(MESSAGE_FILES_COUNT_EMPTY);
    } else if (counter == 1) {
      outprintln(MESSAGE_FILES_COUNT_ONE);
    } else {
      outprintln("" + NEW_LINE_CHAR + FOLD + counter + MESSAGE_FILES_COUNT_MORE);
    }
    if ("".equals(toSearch) && !inBackup) {
      outprintln(MESSAGE_AVAILABLE_FILES_COUNT + (APP_MAX_NUM_OF_FILES - counter));
    }

    passwordFiles = null;

    counter = 0;
  }

  /**
   * Deletes every password-container file and its salt and IV side files from the password
   * directory, purges cached passwords if caching is enabled and logs the bulk deletion.
   *
   * @return {@code true} once the deletion and logging have completed
   */
  static final boolean deleteAllPasswordContainerFiles() {
    boolean success = false;
    File[] passwordFiles = passwordDirFolder.listFiles();
    if (passwordFiles == null) {
      throw systemexit("Error - passwordFiles is null, deleteAllPasswordContainerFiles");
    }
    for (File passwordFile : passwordFiles) {
      if (passwordFile == null) {
        throw systemexit("Error - passwordFile is null, deleteAllPasswordContainerFiles");
      }
      if (passwordFile.isFile() && passwordFile.exists()) {
        if (passwordFile.getName() == null) {
          throw systemexit(
              "Error - passwordFile . getName ( ) is null, deleteAllPasswordContainerFiles");
        }
        if (passwordFile.getName().endsWith(APP_PD_POSTFIX)
            || passwordFile.getName().endsWith(APP_SL_POSTFIX)
            || passwordFile.getName().endsWith(APP_IV_POSTFIX)) {
          if (!passwordFile.delete()) {
            outprintln(MESSAGE_UNABLE_TO_DELETE_FILE + passwordFile.getName());
          }
        }
      }
    }
    passwordFiles = null;
    if (toCachePasswords) {
      purgeCachedFilePasswords();
    }
    char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
    clearCharArray(contentToLog);
    String contentToLog0 = getBeginningOfHistoryEntry() + MESSAGE_LOG_FILES_DELETE + NEW_LINE_CHAR;
    prepareToLog(contentToLog, contentToLog0);
    doLog(contentToLog);
    clearCharArray(contentToLog);
    contentToLog = null;
    contentToLog0 = null;
    success = true;

    return success;
  }
}
