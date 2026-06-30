package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.LineReader.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.util.Date;

/**
 * Console input/output and process control for MyPwStock: printing, debug output, reading lines and
 * passwords, clearing the screen, sleeping, and terminating the JVM.
 */
final class ConsoleIo {
  /**
   * Reads a line from the console using the given prompt, enforcing that input arrives within the
   * configured timeout and does not exceed the given maximum length; aborts the program on any
   * failure.
   *
   * @param s the prompt to display
   * @param maxLength the maximum allowed length of the read line
   * @return the line read from the console, or an empty string if the input exceeded maxLength
   */
  static final String readline(String s, int maxLength) {
    String read = "";
    if (s == null) {
      throw systemexit("Error - s is null, readline");
    }
    if (CONSOLE == null) {
      throw systemexit("Error - console is null, readline");
    }
    Date wait = new Date();
    read = CONSOLE.readLine(s);
    if (read == null) {
      throw systemexit("Error - read is null, readline");
    }
    if ((int) ((new Date().getTime() - wait.getTime()) / 1000) > APP_MAX_NOT_READ_INPUTS_SECONDS) {
      throw systemexit("Error - Waited too long, readline");
    }
    if (read.length() > maxLength) {
      // Over-long input is reported and rejected (returned as empty) rather than aborting the JVM,
      // so the caller's prompt/validation loop can ask again. This matters in interactive mode,
      // where exiting would tear down the whole session.
      outprintln(MESSAGE_INPUT_TOO_LONG);
      read = "";
    }

    wait = null;

    return read;
  }

  /**
   * Reads a line from the console for a note: enforces the input timeout but does NOT enforce a
   * maximum length, because over-long input is folded and truncated to the allowed note length by
   * the caller rather than rejected. Aborts the program on read failure or timeout.
   *
   * @param s the prompt to display
   * @return the line read from the console (may be longer than the allowed note length)
   */
  static final String readlineForNote(String s) {
    String read = "";
    if (s == null) {
      throw systemexit("Error - s is null, readlineForNote");
    }
    if (CONSOLE == null) {
      throw systemexit("Error - console is null, readlineForNote");
    }
    Date wait = new Date();
    read = CONSOLE.readLine(s);
    if (read == null) {
      throw systemexit("Error - read is null, readlineForNote");
    }
    if ((int) ((new Date().getTime() - wait.getTime()) / 1000) > APP_MAX_NOT_READ_INPUTS_SECONDS) {
      throw systemexit("Error - Waited too long, readlineForNote");
    }

    wait = null;

    return read;
  }

  /**
   * Reads a line from the console using the given prompt and returns its trimmed value if it is
   * ASCII and within the allowed length; returns an empty string for non-ASCII input and aborts the
   * program on read failures or excessive length.
   *
   * @param s the prompt to display
   * @return the trimmed ASCII line read, or an empty string if the input was not ASCII
   */
  static final String readiline(String s) {
    String read = "";
    if (s == null) {
      throw systemexit("Error - s is null, readiline");
    }
    if (CONSOLE == null) {
      throw systemexit("Error - console is null, readiline");
    }
    read = null;
    if (isSupported()) {
      read = readLineWithHistory(s);
    }
    if (read == null) {
      read = CONSOLE.readLine(s);
    }
    if (read == null) {
      throw systemexit("Error - read is null, readiline");
    }
    if (isASCII(read)) {
      read = read.trim();
      if (read.length() > APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES * 3 + 25) {
        // Reject the over-long command line with a message instead of aborting the JVM, so the
        // interactive read-eval loop keeps running and simply prompts again.
        outprintln(MESSAGE_INPUT_TOO_LONG);
        read = "";
      }
    } else {
      read = "";
    }

    return read;
  }

  /**
   * Reads a password from the console without echo, enforcing the input timeout; returns an empty
   * array if the input is not non-space ASCII or exceeds the maximum length (reporting the latter
   * with a message so the caller can prompt again), and aborts the program only on read failures.
   *
   * @param s the prompt to display
   * @return the password characters read, or an empty array if the input was not non-space ASCII or
   *     was too long
   */
  static final char[] readpassword(String s) {
    char[] read = new char[0];
    if (s == null) {
      throw systemexit("Error - s is null, readpassword");
    }
    if (CONSOLE == null) {
      throw systemexit("Error - console is null, readpassword");
    }
    Date wait = new Date();
    read = CONSOLE.readPassword(s);
    if (read == null) {
      throw systemexit("Error - read is null, readpassword");
    }
    if ((int) ((new Date().getTime() - wait.getTime()) / 1000) > APP_MAX_NOT_READ_INPUTS_SECONDS) {
      throw systemexit("Error - Waited too long, readpassword");
    }
    if (read.length > APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES) {
      // Over-long input is reported and rejected (returned as empty) rather than aborting the JVM,
      // so the caller's prompt/validation loop can ask again instead of killing the session.
      outprintln(MESSAGE_INPUT_TOO_LONG);
      read = new char[0];
    } else {
      if (!isASCIIandNONSPACE(read)) {
        read = new char[0];
      }
    }
    wait = null;

    return read;
  }

  /**
   * Displays an animated progress indicator (a row of status characters filled over the given
   * duration), used as a visible countdown while a password is shown on screen or held on the
   * clipboard; aborts the program if the close-window message is empty. If the terminal supports
   * it, pressing any key in the (focused) terminal jumps to the end of the countdown immediately.
   *
   * @param seconds the total duration of the countdown, in seconds
   */
  static final void displayCountdownStatus(int seconds) {
    String margin = "";
    if (!(MESSAGE_CLOSE_THIS_WINDOW.length() > 0)) {
      throw systemexit("Error - messageCloseThisWindow is empty, displayCountdownStatus");
    }
    while (margin.length() < MESSAGE_CLOSE_THIS_WINDOW.length()) {
      margin = margin + PASSWORD_STATUS_MARGIN;
    }
    outprintln(margin);
    int counter = 0;
    int msToSleep = (int) (seconds * 1000 / MESSAGE_CLOSE_THIS_WINDOW.length());
    boolean watching = beginKeyWatch();
    boolean skip = false;
    while (counter < MESSAGE_CLOSE_THIS_WINDOW.length()) {
      outprint(PASSWORD_STATUS_STATUS);
      if (!skip) {
        if (watching) {
          int slept = 0;
          while (slept < msToSleep) {
            if (keyPressed()) {
              skip = true;
              break;
            }
            int slice = Math.min(50, msToSleep - slept);
            threadsleep(slice);
            slept = slept + slice;
          }
        } else {
          threadsleep(msToSleep);
        }
      }
      counter++;
    }
    if (watching) {
      endKeyWatch();
    }
    outprint(NEW_LINE_CHAR);
    msToSleep = 0;
    counter = 0;
    skip = false;

    margin = null;
  }

  /**
   * Clears the screen by printing the given number of empty lines.
   *
   * @param numOfEmptyLinesToPrintOut the number of newline characters to print
   */
  static final void clearScreen(int numOfEmptyLinesToPrintOut) {
    String clearScreenString = "";
    for (int i = 0; i < numOfEmptyLinesToPrintOut; i++) {
      clearScreenString = clearScreenString + NEW_LINE_CHAR;
    }
    outprintln(clearScreenString);
    clearScreenString = null;
  }

  /**
   * Sleeps the current thread for the given number of milliseconds; aborts the program if the sleep
   * is interrupted.
   *
   * @param ms the number of milliseconds to sleep
   */
  static final void threadsleep(int ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      throw systemexit("Exception - InterruptedException, threadsleep");
    }
  }

  /**
   * Prints an exiting message with the given detail and terminates the JVM with exit code 1;
   * returns a RuntimeException so callers can write {@code throw systemexit(...)}.
   *
   * @param s the error detail to append to the exiting message
   * @return a RuntimeException (never actually returned, as the JVM exits first)
   */
  static final RuntimeException systemexit(String s) {
    outprintln(MESSAGE_EXITING + s);
    System.exit(1);
    return new RuntimeException();
  }

  /**
   * Prints the given string followed by a line separator to standard output, but only if it
   * consists of printable ASCII or newline characters.
   *
   * @param s the string to print
   */
  static final void outprintln(String s) {
    if (isASCIIorNEWLINE(s)) {
      System.out.println(s);
    }
  }

  /**
   * Prints the given character followed by a line separator to standard output, but only if it is a
   * printable ASCII or newline character.
   *
   * @param c the character to print
   */
  static final void outprintln(char c) {
    if (isASCIIorNEWLINE(c)) {
      System.out.println(c);
    }
  }

  /**
   * Prints the given string to standard output without a trailing line separator, but only if it
   * consists of printable ASCII or newline characters.
   *
   * @param s the string to print
   */
  static final void outprint(String s) {
    if (isASCIIorNEWLINE(s)) {
      System.out.print(s);
    }
  }

  /**
   * Prints the given character to standard output without a trailing line separator, but only if it
   * is a printable ASCII or newline character.
   *
   * @param c the character to print
   */
  static final void outprint(char c) {
    if (isASCIIorNEWLINE(c)) {
      System.out.print(c);
    }
  }

  /**
   * Prints the given string as a debug line, prefixed with "# " and followed by a line separator.
   *
   * @param s the debug message to print
   */
  static final void debugln(String s) {
    outprintln("# " + s);
  }

  /**
   * Prints the given character as a debug line, prefixed with "# " and followed by a line
   * separator.
   *
   * @param c the debug character to print
   */
  static final void debugln(char c) {
    outprintln("# " + c);
  }

  /**
   * Prints the given string for debugging without a trailing line separator.
   *
   * @param s the debug message to print
   */
  static final void debug(String s) {
    outprint(s);
  }

  /**
   * Prints the given character for debugging without a trailing line separator.
   *
   * @param c the debug character to print
   */
  static final void debug(char c) {
    outprint(c);
  }
}
