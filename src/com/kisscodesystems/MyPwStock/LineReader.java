package com.kisscodesystems.MyPwStock;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * A minimal raw-mode line reader that adds terminal-style command history (Up/Down recall) and
 * Backspace editing to the interactive prompt. On Unix-like systems it puts the terminal into
 * character-at-a-time, no-echo mode via {@code stty} (signals such as CTRL+C are left enabled) and
 * draws the line itself; on Windows (or whenever raw mode cannot be entered) it reports itself as
 * unavailable so the caller falls back to the plain {@link java.io.Console} read.
 *
 * <p>The history is held in memory only - it is never written to disk - and contains the command
 * lines typed at the prompt (file and key names), never the passwords, which are read through a
 * separate masked prompt. It can be wiped with {@link #clearHistory()} when interactive mode ends.
 */
final class LineReader {
  private static final ArrayList<String> history = new ArrayList<String>();
  private static String savedSttyState = null;
  private static boolean shutdownHookRegistered = false;

  /**
   * Reports whether raw-mode line editing is supported on this platform (Unix-like systems only).
   *
   * @return true if the raw-mode reader can be used, false to fall back to the plain console read
   */
  static final boolean isSupported() {
    String os = System.getProperty("os.name");
    return os != null && !os.toLowerCase().contains("win");
  }

  /** Wipes the in-memory command history. */
  static final void clearHistory() {
    history.clear();
  }

  /**
   * Reads a single command line from the terminal in raw mode, echoing input and supporting
   * Backspace and Up/Down history recall, then records the line in the in-memory history.
   *
   * @param prompt the prompt to display
   * @return the line entered, or null if raw mode could not be entered (caller should fall back)
   */
  static final String readLineWithHistory(String prompt) {
    if (!enterRawMode()) {
      return null;
    }
    StringBuilder buf = new StringBuilder();
    int histIndex = history.size();
    String stash = "";
    try {
      System.out.print(prompt);
      System.out.flush();
      int c;
      while ((c = System.in.read()) != -1) {
        if (c == '\r' || c == '\n') {
          System.out.print('\n');
          System.out.flush();
          break;
        } else if (c == 127 || c == 8) {
          if (buf.length() > 0) {
            buf.deleteCharAt(buf.length() - 1);
            System.out.print("\b \b");
            System.out.flush();
          }
        } else if (c == 27) {
          int c1 = System.in.read();
          if (c1 == '[' || c1 == 'O') {
            int c2 = System.in.read();
            if (c2 == 'A') {
              if (histIndex > 0) {
                if (histIndex == history.size()) {
                  stash = buf.toString();
                }
                histIndex--;
                setLine(prompt, buf, history.get(histIndex));
              }
            } else if (c2 == 'B') {
              if (histIndex < history.size()) {
                histIndex++;
                setLine(prompt, buf, histIndex == history.size() ? stash : history.get(histIndex));
              }
            } else if (c2 >= '0' && c2 <= '9') {
              int x = c2;
              while (x != '~' && x != -1) {
                x = System.in.read();
              }
            }
          }
        } else if (c >= 32 && c <= 126) {
          buf.append((char) c);
          System.out.print((char) c);
          System.out.flush();
        }
      }
    } catch (Exception e) {
      // fall through, restore the terminal and return what was read so far
    } finally {
      restoreMode();
    }
    String line = buf.toString();
    if (line.length() > 0 && (history.isEmpty() || !history.get(history.size() - 1).equals(line))) {
      history.add(line);
    }
    return line;
  }

  /**
   * Enters raw mode (if supported) and discards any pending input so that a subsequent {@link
   * #keyPressed()} only reports keys pressed from this moment on. Used to let the user cut the
   * password countdown short by pressing any key in the (focused) terminal.
   *
   * @return true if raw mode was entered and key watching is active, false otherwise
   */
  static final boolean beginKeyWatch() {
    if (!enterRawMode()) {
      return false;
    }
    drainInput();
    return true;
  }

  /**
   * Reports whether any key has been pressed since key watching began, consuming the pending input
   * so it does not leak into a later prompt.
   *
   * @return true if a key was pressed, false otherwise
   */
  static final boolean keyPressed() {
    try {
      if (System.in.available() > 0) {
        drainInput();
        return true;
      }
    } catch (Exception e) {
      // treat as no key available
    }
    return false;
  }

  /** Restores the terminal after key watching. */
  static final void endKeyWatch() {
    restoreMode();
  }

  /** Discards any currently buffered terminal input. */
  private static final void drainInput() {
    try {
      while (System.in.available() > 0) {
        System.in.read();
      }
    } catch (Exception e) {
      // best effort
    }
  }

  /**
   * Replaces the currently displayed line with the given text, redrawing the prompt and clearing to
   * the end of the line.
   *
   * @param prompt the prompt to redraw
   * @param buf the line buffer to update in place
   * @param text the new line text
   */
  private static final void setLine(String prompt, StringBuilder buf, String text) {
    buf.setLength(0);
    buf.append(text);
    System.out.print('\r');
    System.out.print(prompt);
    System.out.print(text);
    System.out.print("\u001b[K");
    System.out.flush();
  }

  /**
   * Saves the current terminal settings and switches the terminal into character-at-a-time, no-echo
   * mode, registering a shutdown hook that restores a sane terminal on exit.
   *
   * @return true if raw mode was entered, false otherwise
   */
  private static final boolean enterRawMode() {
    try {
      String saved = stty("-g");
      if (saved == null || saved.trim().length() == 0) {
        return false;
      }
      savedSttyState = saved.trim();
      stty("-icanon -echo min 1 time 0");
      registerRestoreHook();
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /** Restores the terminal to the previously saved settings, or to a sane state as a fallback. */
  private static final void restoreMode() {
    try {
      if (savedSttyState != null) {
        stty(savedSttyState);
        savedSttyState = null;
      } else {
        stty("sane");
      }
    } catch (Exception e) {
      // best effort
    }
  }

  /**
   * Registers, once, a shutdown hook that restores a sane terminal on exit, so an abrupt exit (for
   * example CTRL+C while editing) does not leave the terminal without echo.
   */
  private static final void registerRestoreHook() {
    if (!shutdownHookRegistered) {
      Runtime.getRuntime()
          .addShutdownHook(
              new Thread() {
                public void run() {
                  try {
                    stty("sane");
                  } catch (Exception e) {
                    // best effort
                  }
                }
              });
      shutdownHookRegistered = true;
    }
  }

  /**
   * Runs {@code stty} against the controlling terminal with the given arguments and returns its
   * standard output.
   *
   * @param args the arguments to pass to stty
   * @return the standard output produced by stty
   * @throws Exception if the stty process cannot be run or is interrupted
   */
  private static final String stty(String args) throws Exception {
    String[] cmd = {"sh", "-c", "stty " + args + " < /dev/tty"};
    Process p = Runtime.getRuntime().exec(cmd);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    InputStream is = p.getInputStream();
    byte[] b = new byte[256];
    int n;
    while ((n = is.read(b)) != -1) {
      out.write(b, 0, n);
    }
    p.waitFor();
    return out.toString();
  }
}
