package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.Args.*;
import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.LineReader.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.Router.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

/**
 * Informational and utility commands such as help, hints, application describe/story, the welcome
 * screen, good-password and note info, clearing the screen, interactive mode, and password
 * cache toggles.
 */
final class AppCommands {
  /**
   * Runs the interactive mode read-eval loop, repeatedly reading a command line, normalizing
   * whitespace, handling exit and password cache enable/purge commands, and otherwise dispatching
   * parsed arguments to the router until the user exits.
   */
  static final void executeCommandInteractiveMode() {
    outprintln(MESSAGE_WELCOME_TO_INTERACTIVE_MODE);
    String requestString = null;
    String[] requestParams = null;
    while (true) {
      clearCharArrays();
      clearByteArrays();
      requestString = readiline(PROMPT);
      if (isASCII(requestString)) {
        while (requestString.contains(DOUBLE_SPACE)) {
          requestString = requestString.replace(DOUBLE_SPACE, SINGLE_SPACE);
        }
        requestParams = requestString.split(SINGLE_SPACE);
        if (toCachePasswords) {
          cachedPasswordsClearIfOld();
        }
        if (ARG_EXIT.equals(requestString.toLowerCase())) {
          break;
        } else if ((ARG_PASSWORDS + SPACE_CHAR + ARG_CACHE).equals(requestString.toLowerCase())) {
          toCachePasswords = true;
          cachedPasswordsIni();
          outprintln(MESSAGE_PASSWORDS_CACHE_ENABLED);
        } else if ((ARG_PASSWORDS + SPACE_CHAR + ARG_PURGE).equals(requestString.toLowerCase())) {
          toCachePasswords = false;
          cachedPasswordsIni();
          outprintln(MESSAGE_PASSWORDS_CACHE_DISABLED);
        } else {
          if (isGoodArgsObject(requestParams)) {
            letsWork(requestParams);
          }
        }
      } else {
        usageWrongParameters();
      }
      outprintln("");
      clearCharArrays();
      clearByteArrays();
    }
    requestString = null;
    requestParams = null;
    clearHistory();
    outprintln(MESSAGE_BYE);
  }

  /** Prints the application description message. */
  static final void executeCommandApplicationDescribe() {
    outprintln(MESSAGE_APPLICATION_DESCRIBE);
  }

  /** Prints the application story message. */
  static final void executeCommandApplicationStory() {
    outprintln(MESSAGE_APPLICATION_STORY);
  }

  /** Prints the welcome screen message. */
  static final void executeCommandWelcomeScreen() {
    outprintln(MESSAGE_WELCOME_SCREEN);
  }

  /** Prints information about what constitutes a good password. */
  static final void executeCommandGoodPassword() {
    outprintln(MESSAGE_GOOD_PASSWORD);
  }

  /** Prints information about the note feature. */
  static final void executeCommandNote() {
    outprintln(MESSAGE_NOTE);
  }

  /**
   * Clears the screen by printing the requested number of empty lines (when greater than one) and
   * prints a confirmation message.
   *
   * @param numOfEmptyLinesToPrintOut the number of empty lines to print, as a numeric string
   */
  static final void executeCommandClearScreen(String numOfEmptyLinesToPrintOut) {
    int num = Integer.parseInt(numOfEmptyLinesToPrintOut);
    if (num > 1) {
      clearScreen(num);
      outprintln(MESSAGE_SCREEN_HAS_BEEN_CLEARED1 + num + MESSAGE_SCREEN_HAS_BEEN_CLEARED2);
    }
  }

  /** Prints the command hints message. */
  static final void executeCommandHints() {
    outprintln(MESSAGE_HINTS);
  }

  /** Prints the full help message. */
  static final void executeCommandHelp() {
    outprintln(MESSAGE_HELP);
  }

  /** Prints the wrong-parameters message followed by the full help message. */
  static final void usageWrongParameters() {
    outprintln(MESSAGE_WRONG_PARAMETERS);
    executeCommandHelp();
  }
}
