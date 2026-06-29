package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Messages.*;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/**
 * System-clipboard access for the password copy feature: places a password value on the system
 * clipboard and wipes it again. A JVM shutdown hook wipes the clipboard on exit (including abrupt
 * exits such as CTRL+C) if it still holds a password placed by this application, so a password is
 * never left behind; the held-secret flag ensures unrelated clipboard contents are never touched.
 * AWT errors (for example on a headless system without a clipboard) are caught so the application
 * degrades gracefully instead of aborting.
 */
final class ClipboardIo {
  private static boolean clipboardHoldsSecret = false;
  private static boolean shutdownHookRegistered = false;

  /**
   * Copies the given characters onto the system clipboard, registering the exit-time clipboard wipe
   * on first use. Placing the value on the clipboard unavoidably creates an immutable string copy
   * of it, which cannot be wiped from memory.
   *
   * @param value the characters to place on the clipboard
   * @return true if the clipboard was written, false if no clipboard is available
   */
  static final boolean copyToClipboard(char[] value) {
    boolean success = false;
    if (value == null) {
      throw systemexit("Error - value is null, copyToClipboard");
    }
    try {
      Toolkit.getDefaultToolkit()
          .getSystemClipboard()
          .setContents(new StringSelection(new String(value)), null);
      clipboardHoldsSecret = true;
      registerShutdownHook();
      success = true;
    } catch (Exception e) {
      outprintln(MESSAGE_CLIPBOARD_NOT_AVAILABLE);
    }
    return success;
  }

  /** Overwrites the system clipboard with an empty string, if a clipboard is available. */
  static final void clearClipboard() {
    try {
      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(""), null);
      clipboardHoldsSecret = false;
    } catch (Exception e) {
      // no clipboard available, nothing to clear
    }
  }

  /**
   * Registers, once, a JVM shutdown hook that wipes the clipboard on exit if it still holds a
   * password placed by this application.
   */
  private static final void registerShutdownHook() {
    if (!shutdownHookRegistered) {
      Runtime.getRuntime()
          .addShutdownHook(
              new Thread() {
                public void run() {
                  if (clipboardHoldsSecret) {
                    clearClipboard();
                  }
                }
              });
      shutdownHookRegistered = true;
    }
  }
}
