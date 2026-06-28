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

/**
 * Command handlers for the admin review and search of the application history and for changing the
 * admin password, along with related helpers.
 */
final class AdminCommands {
  /**
   * Runs an admin search of the history for the given search string.
   *
   * @param toSearch the string to search for in the history
   */
  static final void executeCommandAdminSearch(String toSearch) {
    adminReviewOrSearch(toSearch);
  }

  /** Runs an admin review that prints the whole application history. */
  static final void executeCommandAdminReview() {
    adminReviewOrSearch("");
  }

  /**
   * Changes the admin password after confirmation and authentication, logging the change and saving
   * the admin file.
   */
  static final void executeCommandAdminPasswordChange() {
    if (isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
      if (readYesElseAnything(
          MESSAGE_SURE_CHANGE_ADMIN_PASSWORD, MESSAGE_ADMIN_PASSWORD_WONT_BE_CHANGED)) {
        readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
        if (getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
          outprintln(MESSAGE_DO_NOT_FORGET_YOUR_ADMIN_PASSWORD);
          readPassword(PASSWORD_TYPE_ADMIN, true, APP_ADMIN_FILE_NAME);
          char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
          clearCharArray(contentToLog);
          String contentToLog0 =
              getBeginningOfHistoryEntry() + MESSAGE_LOG_ADMIN_PASSWORD_CHANGE + NEW_LINE_CHAR;
          prepareToLog(contentToLog, contentToLog0);
          doLog(contentToLog);
          clearCharArray(contentToLog);
          contentToLog = null;
          contentToLog0 = null;
          if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
            outprintln(MESSAGE_ADMIN_PASSWORD_HAS_BEEN_CHANGED);
          }
        }
      }
    }
  }

  /**
   * Validates and authenticates the request, then either prints the full history (empty search) or
   * the matching lines, logs the operation and saves the admin file.
   *
   * @param toSearch the search string, or an empty string to review the whole history
   */
  static final void adminReviewOrSearch(String toSearch) {
    if (!isASCIIandNONSPACE(toSearch)) {
      return;
    }
    if (!isExistingAdminFile(APP_ADMIN_FILE_NAME, true)) {
      return;
    }
    readPassword(PASSWORD_TYPE_ADMIN, false, APP_ADMIN_FILE_NAME);
    if (!getFileContent(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
      return;
    }
    if (!readYesElseAnything(MESSAGE_NOBODY_IS_AROUND, MESSAGE_OK)) {
      return;
    }
    if (fileContentAdminOrig == null) {
      throw systemexit("Error - fileContentAdminOrig is null, adminReviewOrSearch");
    }
    if (!(fileContentAdminOrig.length > 0)) {
      throw systemexit("Error - fileContentAdminOrig is empty, adminReviewOrSearch");
    }
    int startPos = adminHistoryStartPos();
    int endPos = adminHistoryEndPos(startPos);
    if ("".equals(toSearch)) {
      printAdminHistory(startPos, endPos);
    } else {
      printAdminSearchHits(toSearch, startPos, endPos);
    }
    logAdminReviewOrSearch(toSearch);
    saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN);
  }

  /**
   * Computes the start position of the history within the decrypted admin content, just after the
   * first newline.
   *
   * @return the index of the first history character, or 0 if no newline is found
   */
  private static final int adminHistoryStartPos() {
    for (int i = 0; i < fileContentAdminOrig.length; i++) {
      if (fileContentAdminOrig[i] == NEW_LINE_CHAR) {
        return i + 1;
      }
    }
    return 0;
  }

  /**
   * Computes the end position of the history within the decrypted admin content, stopping before a
   * newline that is followed by a space.
   *
   * @param startPos the position from which to begin scanning
   * @return the index of the last history character
   */
  private static final int adminHistoryEndPos(int startPos) {
    for (int i = startPos; i < fileContentAdminOrig.length - 1; i++) {
      if (fileContentAdminOrig[i] == NEW_LINE_CHAR && fileContentAdminOrig[i + 1] == SPACE_CHAR) {
        return i;
      }
    }
    return fileContentAdminOrig.length - 1;
  }

  /**
   * Prints the history characters in the given range to the console.
   *
   * @param startPos the first index to print
   * @param endPos the last index to print
   */
  private static final void printAdminHistory(int startPos, int endPos) {
    outprintln(MESSAGE_THE_HISTORY_OF_APPLICATION);
    for (int i = startPos; i <= endPos; i++) {
      outprint(fileContentAdminOrig[i]);
    }
  }

  /**
   * Scans the history line by line within the given range, prints each line that contains the
   * search string, and prints a summary of how many hits were found.
   *
   * @param toSearch the string to search for
   * @param startPos the first index of the history range
   * @param endPos the last index of the history range
   */
  private static final void printAdminSearchHits(String toSearch, int startPos, int endPos) {
    int hitsCount = 0;
    int currLinePos = startPos;
    while (currLinePos <= endPos) {
      int theLineLength = 0;
      for (int i = 0; i <= endPos; i++) {
        theLineLength++;
        if (fileContentAdminOrig[i + currLinePos] == NEW_LINE_CHAR) {
          break;
        }
      }
      char[] theLine = new char[theLineLength];
      for (int i = 0; i < theLine.length; i++) {
        theLine[i] = fileContentAdminOrig[i + currLinePos];
      }
      if (lineContainsSearch(theLine, toSearch)) {
        if (hitsCount == 0) {
          outprintln("");
        }
        for (int i = 0; i < theLine.length; i++) {
          outprint(theLine[i]);
        }
        hitsCount++;
      }
      currLinePos = currLinePos + theLineLength;
      clearCharArray(theLine);
    }
    if (hitsCount == 0) {
      outprintln(NEW_LINE_CHAR + FOLD + MESSAGE_NO_HITS_HAVE_BEEN_FOUND + toSearch);
    } else if (hitsCount == 1) {
      outprintln(NEW_LINE_CHAR + FOLD + hitsCount + MESSAGE_HIT_HAS_BEEN_FOUND + toSearch);
    } else {
      outprintln(NEW_LINE_CHAR + FOLD + hitsCount + MESSAGE_HITS_HAVE_BEEN_FOUND + toSearch);
    }
  }

  /**
   * Tests whether the given line contains the search string as a contiguous substring.
   *
   * @param theLine the line characters to scan
   * @param toSearch the string to search for
   * @return {@code true} if the line contains the search string, otherwise {@code false}
   */
  private static final boolean lineContainsSearch(char[] theLine, String toSearch) {
    for (int i = 0; i < theLine.length; i++) {
      if (toSearch.length() <= theLine.length - i) {
        boolean matches = true;
        for (int j = 0; j < toSearch.length(); j++) {
          if (theLine[i + j] != toSearch.charAt(j)) {
            matches = false;
            break;
          }
        }
        if (matches) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Builds and writes a history log entry recording an admin review or an admin search with the
   * given search string.
   *
   * @param toSearch the search string, or an empty string for a review
   */
  private static final void logAdminReviewOrSearch(String toSearch) {
    char[] contentToLog = new char[APP_MAX_LENGTH_TO_LOG];
    clearCharArray(contentToLog);
    String contentToLog0 = getBeginningOfHistoryEntry();
    if ("".equals(toSearch)) {
      contentToLog0 = contentToLog0 + MESSAGE_LOG_ADMIN_REVIEW;
    } else {
      contentToLog0 = contentToLog0 + MESSAGE_LOG_ADMIN_SEARCH + toSearch;
    }
    contentToLog0 = contentToLog0 + NEW_LINE_CHAR;
    prepareToLog(contentToLog, contentToLog0);
    doLog(contentToLog);
    clearCharArray(contentToLog);
  }
}
