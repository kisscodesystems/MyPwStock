package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.util.Date;

/**
 * Writes timestamped entries into the encrypted admin history file, managing rotation so the
 * in-memory admin content stays within its maximum length.
 */
final class Log {
  /**
   * Builds the prefix of a history entry: the current timestamp followed by a separator.
   *
   * @return the formatted timestamp prefix for a new history entry
   */
  static final String getBeginningOfHistoryEntry() {
    return (SIMPLE_DATE_FORMAT.format(new Date()) + SEP9);
  }

  /**
   * Copies the characters of the given string into the target buffer, up to the smaller of the
   * string length, the buffer length, and the maximum log length.
   *
   * @param toLog the destination character buffer to fill
   * @param whatToLog the string content to copy into the buffer
   */
  static final void prepareToLog(char[] toLog, String whatToLog) {
    if (isASCII(toLog)) {
      if (isASCIIorNEWLINE(whatToLog)) {
        int upper = Math.min(Math.min(whatToLog.length(), APP_MAX_LENGTH_TO_LOG), toLog.length);
        for (int i = 0; i < upper; i++) {
          toLog[i] = whatToLog.charAt(i);
        }
        upper = 0;
      }
    }
  }

  /**
   * Appends the given log content to the in-memory admin file content, first evicting the oldest
   * history entries as needed to keep the content within its maximum length.
   *
   * @param toLog the validated log entry to append to the admin history
   */
  static final void doLog(char[] toLog) {
    if (!(isASCIIorNEWLINE(toLog))) {
      throw systemexit("Error - toLog is not good formatted, doLog");
    }
    if (!(toLog.length <= APP_MAX_LENGTH_TO_LOG)) {
      throw systemexit("Error - Too long content in toLog, doLog");
    }
    if (fileContentAdminOrig == null) {
      throw systemexit("Error - fileContentAdminOrig is null, doLog");
    }
    if (fileContentAdminOrig.length != APP_FILE_CONTENT_MAX_LENGTH) {
      throw systemexit("Error - fileContentAdminOrig length proglem, doLog");
    }
    int startPos = -1;
    int newLineCounter = 0;
    int endPos = -1;
    while (getFirstNewLineAndSpaceCharIndex(toLog)
        > APP_FILE_CONTENT_MAX_LENGTH
            - 1
            - getFirstNewLineAndSpaceCharIndex(fileContentAdminOrig)) {
      newLineCounter = 0;
      startPos = -1;
      for (int i = 0; i < fileContentAdminOrig.length; i++) {
        if (fileContentAdminOrig[i] == NEW_LINE_CHAR) {
          newLineCounter++;
        }
        if (fileContentAdminOrig[i] == NEW_LINE_CHAR && newLineCounter == 2) {
          startPos = i + 1;
          break;
        }
      }
      endPos = -1;
      for (int i = startPos; i < fileContentAdminOrig.length; i++) {
        if (fileContentAdminOrig[i] == NEW_LINE_CHAR) {
          endPos = i + 1;
          break;
        }
      }
      int toMoveFromPos = endPos;
      int toMoveDiff = startPos - endPos;
      if (toMoveDiff != 0) {
        shiftFileContent(PASSWORD_TYPE_ADMIN, toMoveFromPos, toMoveDiff);
      } else {
        break;
      }
      toMoveFromPos = 0;
      toMoveDiff = 0;
    }
    int lastNewLineCharPos = getFirstNewLineAndSpaceCharIndex(fileContentAdminOrig);
    if (lastNewLineCharPos == -1) {
      throw systemexit("Error - lastNewLineCharPos is wrong, doLog");
    }
    int posToAppend = lastNewLineCharPos + 1;
    for (int i = 0; i < Math.min(toLog.length, APP_FILE_CONTENT_MAX_LENGTH - posToAppend); i++) {
      fileContentAdminOrig[i + posToAppend] = toLog[i];
      if (toLog[i] == NEW_LINE_CHAR) {
        break;
      }
    }
    posToAppend = 0;

    lastNewLineCharPos = 0;
    startPos = 0;
    newLineCounter = 0;
    endPos = 0;
  }
}
