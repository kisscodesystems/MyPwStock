package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.AdminCommands.*;
import static com.kisscodesystems.MyPwStock.AppCommands.*;
import static com.kisscodesystems.MyPwStock.Args.*;
import static com.kisscodesystems.MyPwStock.BackupCommands.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.FileCommands.*;
import static com.kisscodesystems.MyPwStock.KeyCommands.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.PasswordCommands.*;

/**
 * Parses the command-line argument array and dispatches to the matching command handler. Its {@code
 * letsWork} method is the central dispatcher that maps argument count and keywords to the correct
 * command execution.
 */
final class Router {
  /**
   * Validates the argument array and routes it, based on its length and keyword contents, to the
   * appropriate command handler; prints usage on unrecognized argument combinations.
   *
   * @param args the command-line arguments to parse and dispatch
   */
  static final void letsWork(String[] args) {
    if (args == null) {
      throw systemexit("Error - args is null, letsWork");
    }
    if (args.length == 0) {
      outprintln(MESSAGE_NO_ARGUMENTS);
    } else if (args.length == 1) {
      if (ARG_QUESTION_MARK.equals(args[0].toLowerCase())) {
        executeCommandHints();
      } else if (ARG_HELP.equals(args[0].toLowerCase())) {
        executeCommandHelp();
      } else {
        usageWrongParameters();
      }
    } else if (args.length == 2) {
      if (ARG_INTERACTIVE.equals(args[0].toLowerCase()) && ARG_MODE.equals(args[1].toLowerCase())) {
        executeCommandInteractiveMode();
      } else if (ARG_APPLICATION.equals(args[0].toLowerCase())
          && ARG_DESCRIBE.equals(args[1].toLowerCase())) {
        executeCommandApplicationDescribe();
      } else if (ARG_APPLICATION.equals(args[0].toLowerCase())
          && ARG_STORY.equals(args[1].toLowerCase())) {
        executeCommandApplicationStory();
      } else if (ARG_WELCOME.equals(args[0].toLowerCase())
          && ARG_SCREEN.equals(args[1].toLowerCase())) {
        executeCommandWelcomeScreen();
      } else if (ARG_GOOD.equals(args[0].toLowerCase())
          && ARG_PASSWORD.equals(args[1].toLowerCase())) {
        executeCommandGoodPassword();
      } else if (ARG_PASSWORD.equals(args[0].toLowerCase())
          && ARG_NOTE.equals(args[1].toLowerCase())) {
        executeCommandNote();
      } else if (ARG_FILE.equals(args[0].toLowerCase()) && ARG_LIST.equals(args[1].toLowerCase())) {
        executeCommandFileList();
      } else if (ARG_FILE.equals(args[0].toLowerCase())
          && ARG_DELETEALL.equals(args[1].toLowerCase())) {
        executeCommandFileDeleteall();
      } else if (ARG_ADMIN.equals(args[0].toLowerCase())
          && ARG_REVIEW.equals(args[1].toLowerCase())) {
        executeCommandAdminReview();
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_ADD.equals(args[1].toLowerCase())) {
        executeCommandBackupAdd();
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_LIST.equals(args[1].toLowerCase())) {
        executeCommandBackupList();
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_DELETEALL.equals(args[1].toLowerCase())) {
        executeCommandBackupDeleteall();
      } else {
        usageWrongParameters();
      }
    } else if (args.length == 3) {
      if (ARG_CLEAR.equals(args[0].toLowerCase()) && ARG_SCREEN.equals(args[1].toLowerCase())) {
        executeCommandClearScreen(args[2]);
      } else if (ARG_FILE.equals(args[0].toLowerCase())
          && ARG_SEARCH.equals(args[1].toLowerCase())) {
        executeCommandFileSearch(args[2]);
      } else if (ARG_FILE.equals(args[0].toLowerCase()) && ARG_ADD.equals(args[1].toLowerCase())) {
        executeCommandFileAdd(args[2]);
      } else if (ARG_FILE.equals(args[0].toLowerCase())
          && ARG_DESCRIBE.equals(args[1].toLowerCase())) {
        executeCommandFileDescribe(args[2]);
      } else if (ARG_FILE.equals(args[0].toLowerCase())
          && ARG_DELETE.equals(args[1].toLowerCase())) {
        executeCommandFileDelete(args[2]);
      } else if (ARG_KEY.equals(args[0].toLowerCase()) && ARG_LIST.equals(args[1].toLowerCase())) {
        executeCommandKeyList(args[2]);
      } else if (ARG_KEY.equals(args[0].toLowerCase()) && ARG_ADD.equals(args[1].toLowerCase())) {
        executeCommandKeyAdd(args[2]);
      } else if (ARG_KEY.equals(args[0].toLowerCase())
          && ARG_DELETEALL.equals(args[1].toLowerCase())) {
        executeCommandKeyDeleteall(args[2]);
      } else if (ARG_ADMIN.equals(args[0].toLowerCase())
          && ARG_SEARCH.equals(args[1].toLowerCase())) {
        executeCommandAdminSearch(args[2]);
      } else if (ARG_ADMIN.equals(args[0].toLowerCase())
          && ARG_PASSWORD.equals(args[1].toLowerCase())
          && ARG_CHANGE.equals(args[2].toLowerCase())) {
        executeCommandAdminPasswordChange();
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_DELETE.equals(args[1].toLowerCase())) {
        executeCommandBackupDelete(args[2]);
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_RESTOREALL.equals(args[1].toLowerCase())) {
        executeCommandBackupRestoreall(args[2]);
      } else {
        usageWrongParameters();
      }
    } else if (args.length == 4) {
      if (ARG_FILE.equals(args[0].toLowerCase())
          && ARG_PASSWORD.equals(args[1].toLowerCase())
          && ARG_CHANGE.equals(args[2].toLowerCase())) {
        executeCommandFilePasswordChange(args[3]);
      } else if (ARG_KEY.equals(args[0].toLowerCase())
          && ARG_SEARCH.equals(args[1].toLowerCase())) {
        executeCommandKeySearch(args[2], args[3]);
      } else if (ARG_KEY.equals(args[0].toLowerCase())
          && ARG_DELETE.equals(args[1].toLowerCase())) {
        executeCommandKeyDelete(args[2], args[3]);
      } else if (ARG_KEY.equals(args[0].toLowerCase())
          && ARG_MOVEALL.equals(args[1].toLowerCase())) {
        executeCommandKeyMoveall(args[2], args[3]);
      } else if (ARG_PASSWORD.equals(args[0].toLowerCase())
          && ARG_SHOW.equals(args[1].toLowerCase())) {
        executeCommandPasswordShow(args[2], args[3]);
      } else if (ARG_PASSWORD.equals(args[0].toLowerCase())
          && ARG_COPY.equals(args[1].toLowerCase())) {
        executeCommandPasswordCopy(args[2], args[3]);
      } else if (ARG_PASSWORD.equals(args[0].toLowerCase())
          && ARG_CHANGE.equals(args[1].toLowerCase())) {
        executeCommandPasswordChange(args[2], args[3]);
      } else if (ARG_PASSWORD.equals(args[0].toLowerCase())
          && ARG_TYPE.equals(args[1].toLowerCase())
          && ARG_CHANGE.equals(args[2].toLowerCase())) {
        executeCommandPasswordTypeChange(args[3]);
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_FILE.equals(args[1].toLowerCase())
          && ARG_LIST.equals(args[2].toLowerCase())) {
        executeCommandBackupFileList(args[3]);
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_FILE.equals(args[1].toLowerCase())
          && ARG_SEARCHALL.equals(args[2].toLowerCase())) {
        executeCommandBackupFileSearchall(args[3]);
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_RESTORE.equals(args[1].toLowerCase())) {
        executeCommandBackupRestore(args[2], args[3]);
      } else {
        usageWrongParameters();
      }
    } else if (args.length == 5) {
      if (ARG_KEY.equals(args[0].toLowerCase()) && ARG_CHANGE.equals(args[1].toLowerCase())) {
        executeCommandKeyChange(args[2], args[3], args[4]);
      } else if (ARG_KEY.equals(args[0].toLowerCase()) && ARG_MOVE.equals(args[1].toLowerCase())) {
        executeCommandKeyMove(args[2], args[3], args[4]);
      } else if (ARG_BACKUP.equals(args[0].toLowerCase())
          && ARG_FILE.equals(args[1].toLowerCase())
          && ARG_SEARCH.equals(args[2].toLowerCase())) {
        executeCommandBackupFileSearch(args[3], args[4]);
      } else {
        usageWrongParameters();
      }
    } else {
      usageWrongParameters();
    }
  }
}
