package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.FileCommands.*;
import static com.kisscodesystems.MyPwStock.FileStore.*;
import static com.kisscodesystems.MyPwStock.Log.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.io.File;
import java.util.Date;

/**
 * Command handlers for backups (list, add, delete, deleteall, file list/search/searchall, restore,
 * restoreall) together with their supporting helpers.
 */
final class BackupCommands {
  /**
   * Lists all available backups by delegating to the list/search helper with an empty search term.
   */
  static final void executeCommandBackupList() {
    backupListOrFileSearch("");
  }

  /**
   * Creates a new backup after confirming with the user and unlocking the admin file, prompting for
   * a description and saving the admin file once the backup is added.
   */
  static final void executeCommandBackupAdd() {
    if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
      if (readYesElseAnything(MESSAGE_SURE_MAKE_BACKUP, MESSAGE_BACKUP_WONT_BE_MADE)) {
        readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
        if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
          String description = readBackupDescription();
          if (addBackup(description)) {
            if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              outprintln(MESSAGE_BACKUP_HAS_BEEN_FINISHED_SUCCESSFULLY);
            }
          }
          description = null;
        }
      }
    }
  }

  /**
   * Deletes a single named backup after validating the name, confirming with the user and unlocking
   * the admin file, then saves the admin file.
   *
   * @param backupName the name of the backup folder to delete
   */
  static final void executeCommandBackupDelete(String backupName) {
    if (isValidKeyOrFileName(backupName, true)) {
      if (isExistingFolder(APP_BACKUP_DIR + SEP + backupName, true)) {
        if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
          if (readYesElseAnything(
              MESSAGE_SURE_DELETE_BACKUP1 + backupName + MESSAGE_SURE_DELETE_BACKUP2,
              MESSAGE_BACKUP_WONT_BE_DELETED)) {
            readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
            if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              if (deleteBackup(backupName)) {
                if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                  outprintln(MESSAGE_BACKUP_HAS_BEEN_DELETED_SUCCESSFULLY);
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * Deletes every existing backup after confirming with the user and unlocking the admin file,
   * iterating over all backup folders and saving the admin file at the end.
   */
  static final void executeCommandBackupDeleteall() {
    if (backupDirFolder == null) {
      throw systemexit("Error - backupDirFolder is null, executeCommandBackupDeleteall");
    }
    if (!(backupDirFolder.exists())) {
      throw systemexit("Error - backupDirFolder is not existing, executeCommandBackupDeleteall");
    }
    File[] backupFolders = backupDirFolder.listFiles();
    if (backupFolders == null) {
      throw systemexit("Error - backupFolders is null, executeCommandBackupDeleteall");
    }
    if (backupFolders.length > 0) {
      if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
        if (readYesElseAnything(MESSAGE_SURE_DELETE_BACKUPS, MESSAGE_BACKUPS_WONT_BE_DELETED)) {
          readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
          if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
            for (File backupFolder : backupFolders) {
              if (backupFolder == null) {
                throw systemexit("Error - backupFolder is null, executeCommandBackupDeleteall");
              }
              if (!deleteBackup(backupFolder.getName())) {
                throw systemexit("Error - deleteBackup is false!, executeCommandBackupDeleteall");
              }
            }
            if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              outprintln(MESSAGE_ALL_BACKUPS_HAVE_BEEN_HANDELED);
            }
          }
        }
      }
    } else {
      outprintln(MESSAGE_NO_BACKUPS_HAVE_BEEN_FOUND);
    }

    backupFolders = null;
  }

  /**
   * Lists all files contained in the given backup after validating the name and checking the backup
   * folder exists.
   *
   * @param backupName the name of the backup folder whose files are listed
   */
  static final void executeCommandBackupFileList(String backupName) {
    if (isValidKeyOrFileName(backupName, true)) {
      if (isExistingFolder(APP_BACKUP_DIR + SEP + backupName, true)) {
        fileListOrSearch("", new File(APP_BACKUP_DIR + SEP + backupName), true);
      }
    }
  }

  /**
   * Searches the files within a single named backup for the given term after validating the name
   * and checking the backup folder exists.
   *
   * @param backupName the name of the backup folder to search within
   * @param toSearch the search term to match against file names
   */
  static final void executeCommandBackupFileSearch(String backupName, String toSearch) {
    if (isValidKeyOrFileName(backupName, true)) {
      if (isExistingFolder(APP_BACKUP_DIR + SEP + backupName, true)) {
        fileListOrSearch(toSearch, new File(APP_BACKUP_DIR + SEP + backupName), true);
      }
    }
  }

  /**
   * Searches the files across all backups for the given term by delegating to the list/search
   * helper.
   *
   * @param toSearch the search term to match against file names in every backup
   */
  static final void executeCommandBackupFileSearchall(String toSearch) {
    backupListOrFileSearch(toSearch);
  }

  /**
   * Restores a single password file from a named backup after validating the names, confirming with
   * the user and unlocking the admin file, then saves the admin file.
   *
   * @param backupName the name of the backup folder to restore from
   * @param fileName the name of the password file to restore
   */
  static final void executeCommandBackupRestore(String backupName, String fileName) {
    if (isValidKeyOrFileName(backupName, true)) {
      if (isValidKeyOrFileName(fileName, true)) {
        if (isExistingBackedUpPasswordFile(backupName, fileName, true)) {
          if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
            if (readYesElseAnything(
                MESSAGE_SURE_RESTORE_FILE1
                    + fileName
                    + MESSAGE_SURE_RESTORE_FILE2
                    + backupName
                    + MESSAGE_SURE_RESTORE_FILE3,
                MESSAGE_FILE_WONT_BE_RESTORED)) {
              readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
              if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                if (restoreFile(backupName, fileName)) {
                  if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                    outprintln(MESSAGE_YOUR_FILE_HAS_BEEN_RESTORED_SUCCESSFULLY);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * Restores all password files from a named backup, first taking an automatic backup of the
   * current state and removing all current password files, then restores every backed-up file and
   * saves the admin file.
   *
   * @param backupName the name of the backup folder to fully restore from
   */
  static final void executeCommandBackupRestoreall(String backupName) {
    if (isValidKeyOrFileName(backupName, true)) {
      if (isExistingFolder(APP_BACKUP_DIR + SEP + backupName, true)) {
        if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
          if (readYesElseAnything(MESSAGE_SURE_RESTORE_FILES, MESSAGE_FILES_WONT_BE_RESTORED)) {
            readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
            if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
              outprintln("" + NEW_LINE_CHAR + FOLD + MESSAGE_AUTOMATED_BACKUP_BEFORE_RESTORING);
              if (addBackup(MESSAGE_AUTOMATED_BACKUP_BEFORE_RESTORING)) {
                outprintln(MESSAGE_BACKUP_HAS_BEEN_FINISHED_SUCCESSFULLY);
                if (deleteAllPasswordContainerFiles()) {
                  File backupFolder = new File(APP_BACKUP_DIR + SEP + backupName);
                  File[] files = backupFolder.listFiles();
                  if (files == null) {
                    throw systemexit("Error - files is null, executeCommandBackupRestoreall");
                  }
                  for (File file : files) {
                    if (file != null) {
                      if (file.getName() == null) {
                        throw systemexit(
                            "Error - file . getName ( ) is null,"
                                + " executeCommandBackupRestoreall");
                      }
                      if (file.getName().endsWith(APP_PD_POSTFIX)) {
                        if (!restoreFile(
                            backupName,
                            file.getName()
                                .substring(0, file.getName().length() - APP_PD_POSTFIX.length()))) {
                          throw systemexit(
                              "Error - restoreFile is false!," + " executeCommandBackupRestoreall");
                        }
                      }
                    }
                  }
                  if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
                    outprintln(MESSAGE_ALL_BACKED_UP_FILES_HAVE_BEEN_HANDELED);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * Restores a single password file from a backup by copying its data, IV and salt files into place
   * (optionally confirming overwrite of an existing file), swapping in the new files, writing a
   * history log entry and purging any cached password.
   *
   * @param backupName the name of the backup folder to restore from
   * @param fileName the name of the password file to restore
   * @return true if the file was restored successfully, false otherwise
   */
  static final boolean restoreFile(String backupName, String fileName) {
    boolean success = false;
    if (isValidKeyOrFileName(backupName, false)) {
      if (isValidKeyOrFileName(fileName, false)) {
        if (isExistingBackedUpPasswordFile(backupName, fileName, false)) {
          boolean canBring = true;
          if (isExistingPasswordFile(fileName, false)) {
            if (!readYesElseAnything(
                MESSAGE_SURE_BRING_BACKED_UP_FILE_AND_OVERWRITE_CURRENT_FILE,
                MESSAGE_FILE_WONT_BE_OVERWRITTEN_BY_BACKED_UP_FILE)) {
              canBring = false;
            }
          }
          if (canBring) {
            if (copySingleFile(
                APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_PD_POSTFIX,
                APP_PASSWORD_DIR + SEP + fileName + APP_PD_POSTFIX + APP_NW_POSTFIX)) {
              if (copySingleFile(
                  APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_IV_POSTFIX,
                  APP_PASSWORD_DIR + SEP + fileName + APP_IV_POSTFIX + APP_NW_POSTFIX)) {
                if (copySingleFile(
                    APP_BACKUP_DIR + SEP + backupName + SEP + fileName + APP_SL_POSTFIX,
                    APP_PASSWORD_DIR + SEP + fileName + APP_SL_POSTFIX + APP_NW_POSTFIX)) {
                  if (removeOldFilesAndRenameNewFiles(fileName, PASSWORD_TYPE_FILE1)) {
                    char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
                    clearCharArray(contentToLog);
                    String contentToLog0 =
                        getBeginningOfHistoryEntry()
                            + MESSAGE_LOG_RESTORE_FILE
                            + backupName
                            + SEP3
                            + fileName
                            + NEW_LINE_CHAR;
                    prepareToLog(contentToLog, contentToLog0);
                    doLog(contentToLog);
                    clearCharArray(contentToLog);
                    contentToLog = null;
                    contentToLog0 = null;
                    if (toCachePasswords) {
                      purgeCachedFilePassword(fileName);
                    }
                    success = true;
                  }
                } else {
                  outprintln(MESSAGE_UNABLE_TO_CREATE_NW_FILES + fileName);
                }
              } else {
                outprintln(MESSAGE_UNABLE_TO_CREATE_NW_FILES + fileName);
              }
            } else {
              outprintln(MESSAGE_UNABLE_TO_CREATE_NW_FILES + fileName);
            }
          }
          canBring = false;
        }
      }
    }
    return success;
  }

  /**
   * Iterates over all backup folders, printing each backup's name and description; when a search
   * term is given it also searches the files within each backup, and finally prints summary counts.
   *
   * @param toSearch the search term, or an empty string to simply list backups
   */
  static final void backupListOrFileSearch(String toSearch) {
    if (backupDirFolder == null) {
      throw systemexit("Error - backupDirFolder is null, backupListOrFileSearch");
    }
    if (isASCIIandNONSPACE(toSearch)) {
      File[] files = backupDirFolder.listFiles();
      if (files == null) {
        throw systemexit("Error - files is null, backupListOrFileSearch");
      }
      int counter = 0;
      String backupName = null;
      String backupDescription = null;
      for (File file : files) {
        if (counter == 0 || !"".equals(toSearch)) {
          outprintln("");
        }
        if (file == null) {
          throw systemexit("Error - file is null, backupListOrFileSearch");
        }
        if (file.isDirectory()) {
          backupName = file.getName();
          backupDescription =
              readSingleLinedFile(
                  APP_BACKUP_DIR + SEP + backupName + SEP + APP_BACKUP_DESCRIPTION_FILE_NAME);
          outprintln(FOLD + backupName + SEP9 + backupDescription);
          if (!"".equals(toSearch)) {
            fileListOrSearch(toSearch, file, true);
          }
        }

        counter++;
      }
      if (counter == 0) {
        outprintln(MESSAGE_NO_BACKUPS_HAVE_BEEN_FOUND);
      } else if (counter == 1) {
        outprintln(MESSAGE_ONE_BACKUP_HAS_BEEN_FOUND);
      } else {
        outprintln(NEW_LINE_CHAR + FOLD + counter + MESSAGE_BACKUPS_HAVE_BEEN_FOUND);
      }
      if ("".equals(toSearch)) {
        outprintln(MESSAGE_THE_COUNT_OF_AVAILABLE_BACKUPS_IS + (APP_MAX_NUM_OF_BACKUPS - counter));
      }
      counter = 0;
      backupName = null;
      backupDescription = null;

      files = null;
    }
  }

  /**
   * Creates a new timestamp-named backup folder, copies all current password data/IV/salt files and
   * a description file into it, then writes a history log entry, provided the maximum number of
   * backups is not exceeded.
   *
   * @param description the description text stored with the backup
   * @return true if the backup was created successfully, false otherwise
   */
  static final boolean addBackup(String description) {
    boolean success = false;
    String backupName = BACKUP_DATE_FORMAT.format(new Date());
    String backupPath = APP_BACKUP_DIR + SEP + backupName;
    if (backupDirFolder == null) {
      throw systemexit("Error - backupDirFolder is null, addBackup");
    }
    File[] backups = backupDirFolder.listFiles();
    if (backups == null) {
      throw systemexit("Error - backups is null, addBackup");
    }
    int numOfBackups = backups.length;
    if (numOfBackups < APP_MAX_NUM_OF_BACKUPS) {
      if (!(isValidBackupDescription(description))) {
        throw systemexit("Error - description is not valid, addBackup");
      }
      threadsleep(1024);
      outprintln(MESSAGE_YOUR_BACKUP_IS + backupName);
      File backupFolder = new File(backupPath);
      backupFolder.mkdirs();
      if (isExistingFolder(backupPath, false)) {
        if (passwordDirFolder == null) {
          throw systemexit("Error - passwordDirFolder is null, addBackup");
        }
        File[] files = passwordDirFolder.listFiles();
        if (files == null) {
          throw systemexit("Error - files is null, addBackup");
        }
        for (File file : files) {
          if (file == null) {
            throw systemexit("Error - file is null, addBackup");
          }
          if (file.getName() == null) {
            throw systemexit("Error - file . getName ( ) is null, addBackup");
          }
          if (file.getName().endsWith(APP_PD_POSTFIX)
              || file.getName().endsWith(APP_SL_POSTFIX)
              || file.getName().endsWith(APP_IV_POSTFIX)) {
            if (!copySingleFile(
                APP_PASSWORD_DIR + SEP + file.getName(), backupPath + SEP + file.getName())) {
              throw systemexit("Error - file copy has failed: " + file.getName() + ", addBackup");
            }
          }
        }
        if (!createSingleFile(backupPath + SEP + APP_BACKUP_DESCRIPTION_FILE_NAME, description)) {
          throw systemexit("Error - failed to make description of backup, addBackup");
        }
        char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
        clearCharArray(contentToLog);
        String contentToLog0 =
            getBeginningOfHistoryEntry()
                + MESSAGE_LOG_BACKUP_MAKE
                + backupName
                + SEP9
                + description
                + NEW_LINE_CHAR;
        prepareToLog(contentToLog, contentToLog0);
        doLog(contentToLog);
        clearCharArray(contentToLog);
        contentToLog = null;
        contentToLog0 = null;
        success = true;

        files = null;
      }

      backupFolder = null;

    } else {
      outprintln(MESSAGE_TOO_MANY_BACKUPS_ARE_THERE + APP_MAX_NUM_OF_BACKUPS);
    }
    numOfBackups = 0;

    backups = null;

    backupName = null;
    backupPath = null;
    if (!success) {
      outprintln(MESSAGE_BACKUP_HAS_NOT_BEEN_DELETED_SUCCESSFULLY + backupName);
    }

    return success;
  }

  /**
   * Deletes the named backup folder and all of its contained files, recording any delete errors and
   * writing a history log entry reflecting the outcome.
   *
   * @param backupName the name of the backup folder to delete
   * @return true if the deletion was processed successfully, false otherwise
   */
  static final boolean deleteBackup(String backupName) {
    boolean success = false;
    if (isValidKeyOrFileName(backupName, false)) {
      File backupFolder = new File(APP_BACKUP_DIR + SEP + backupName);
      if (backupFolder.exists()) {
        if (!(backupFolder.isDirectory())) {
          throw systemexit("Error - backupFolder is a file, deleteBackup");
        }
        boolean fileDeleteError = false;
        boolean folderDeleteError = false;
        File[] files = backupFolder.listFiles();
        if (files == null) {
          throw systemexit("Error - files is null, deleteBackup");
        }
        for (File file : files) {
          if (file == null) {
            throw systemexit("Error - file is null, deleteBackup");
          }
          if (!file.delete()) {
            outprintln(MESSAGE_ERROR_WHILE_DELETING_FILE + file.getName());
            if (!fileDeleteError) {
              fileDeleteError = true;
            }
          }
        }

        if (!backupFolder.delete()) {
          outprintln(MESSAGE_ERROR_WHILE_DELETING_FOLDER + backupName);
          folderDeleteError = true;
        }
        char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
        clearCharArray(contentToLog);
        String contentToLog0 =
            getBeginningOfHistoryEntry()
                + MESSAGE_LOG_BACKUP_DELETE
                + backupName
                + SEP9
                + (!fileDeleteError && !folderDeleteError)
                + NEW_LINE_CHAR;
        prepareToLog(contentToLog, contentToLog0);
        doLog(contentToLog);
        clearCharArray(contentToLog);
        contentToLog = null;
        contentToLog0 = null;
        success = true;
        fileDeleteError = false;
        folderDeleteError = false;
        files = null;

      } else {
        outprintln(MESSAGE_FOLDER_DOES_NOT_EXIST + APP_BACKUP_DIR + SEP + backupName);
      }

      backupFolder = null;
    }
    if (!success) {
      outprintln(MESSAGE_THE_BACKUP_CREATION_HAS_NOT_BEEN_FINISHED_SUCCESSFULLY);
    }
    return success;
  }
}
