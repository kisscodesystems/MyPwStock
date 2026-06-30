package com.kisscodesystems.MyPwStock;

import java.io.Console;
import java.io.File;
import java.net.URL;
import java.security.CodeSource;
import java.text.SimpleDateFormat;

/**
 * Application-wide constants: miscellaneous chars, strings and bytes, size and length limits,
 * directory names and file postfixes, password-type tags, crypto parameters, date formatters, and
 * the shared {@link java.io.Console} object.
 */
final class Const {
  static final byte NULL_BYTE = '\0';
  // In-memory padding/end-of-content sentinel for password-file (file1/file2) content buffers.
  // Using NUL instead of a space lets stored note values legally contain spaces; the admin file
  // keeps its own newline+space sentinel.
  static final char NUL_CHAR = '\0';
  static final char NEW_LINE_CHAR = '\n';
  static final char SPACE_CHAR = ' ';
  static final String DOUBLE_SPACE = "" + SPACE_CHAR + SPACE_CHAR;
  static final String SINGLE_SPACE = "" + SPACE_CHAR;

  // The content of every encrypted file starts with a header line: a random number of random
  // lowercase letters terminated by a newline. It carries no fixed/known plaintext (so it is not a
  // recognizable marker and gives an offline attacker no constant to verify guesses against);
  // integrity and "correct key" detection come from the authenticated cipher (AES-GCM) instead.
  static final int APP_HEADER_MIN_LETTERS = 8;
  static final int APP_HEADER_MAX_LETTERS = 19;

  static final char ALLOW_NOTES_YES = 'y';
  static final char ALLOW_NOTES_NO = 'n';
  // Rich-note storage mode (file flag 'r'): key values may contain spaces and be up to
  // APP_MAX_LENGTH_OF_NOTE characters. Only newly created note files use this mode; legacy 'y'
  // files keep the old ASCII, no-space behavior.
  static final char ALLOW_NOTES_RICH = 'r';

  static final String PASSWORD_TYPE_FILE1 = "file1";
  static final String PASSWORD_TYPE_FILE2 = "file2";
  static final String PASSWORD_TYPE_KEY = "key";
  static final String PASSWORD_TYPE_ADMIN = "admin";

  static final String APP_NAME = "MyPwStock";
  static final String APP_VERSION = "2.3";
  static final int APP_MAX_NUM_OF_FILES = 9;
  static final int APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES = 99;
  static final int APP_MAX_NUM_OF_KEYS_PER_FILE = 999;
  static final int APP_MAX_LENGTH_OF_GENERATED_PASSWORDS = 21;
  // Maximum length of a rich note (key value in a 'r'-mode file). Keys and good passwords stay
  // bounded by APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES.
  static final int APP_MAX_LENGTH_OF_NOTE = 999;
  static final int APP_MAX_LENGTH_TO_LOG = 100
      + APP_MAX_LENGTH_OF_NOTE
      + 2 * APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES;
  // Sized for the worst case of a full file: every key line is up to
  // (key length + newline) and every value line up to (note length + newline).
  static final int APP_FILE_CONTENT_MAX_LENGTH =
      APP_MAX_NUM_OF_KEYS_PER_FILE * APP_MAX_LENGTH_TO_LOG
      + 2 * APP_HEADER_MAX_LETTERS;
  // The data, admin and backup directories are anchored next to the running jar so the application
  // behaves identically on every platform, in any drive or subfolder, regardless of the process
  // working directory (e.g. a double-clicked jar on Windows runs with the working directory set to
  // System32, not the jar's folder). When the classes are run loose from a directory (the test/dev
  // classpath) the base stays empty, keeping the working-directory-relative behavior the tests rely
  // on.
  static final String APP_DATA_BASE_DIR = resolveDataBaseDir();
  static final String APP_PASSWORD_DIR = APP_DATA_BASE_DIR + "pd";
  static final String APP_ADMIN_DIR = APP_DATA_BASE_DIR + "an";
  static final String APP_BACKUP_DIR = APP_DATA_BASE_DIR + "bp";
  static final String APP_PD_POSTFIX = ".pd";
  static final String APP_IV_POSTFIX = ".iv";
  static final String APP_SL_POSTFIX = ".sl";
  static final String APP_NW_POSTFIX = ".nw";
  static final String APP_AN_POSTFIX = ".an";
  static final String APP_ADMIN_FILE_NAME = "admin";
  static final String APP_BACKUP_DESCRIPTION_FILE_NAME = "description";
  static final int APP_MIN_LENGTH_OF_KEYS_AND_FILE_NAMES = 1;
  static final int APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS = 4;
  static final int APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS = 4;
  static final int APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS = 3;
  static final int APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS = 2;
  static final int APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS = APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS + APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS + APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS + APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS;
  static final int APP_MIN_LENGTH_OF_NOTE = 1;
  static final int APP_SALT_LENGTH = 256;
  static final int FILE_PASSWORD_MAX_ATTEMPTS = 3;
  static final int APP_PBE_KEY_SPEC_ITERATIONS = 600000;
  static final int APP_PBE_KEY_SPEC_KEY_LENGTH = 256;
  static final String APP_SECRET_KEY_FACTORY_INSTANCE = "PBKDF2WithHmacSHA512";
  static final String APP_SECRET_KEY_SPEC_ALGORYTHM = "AES";
  static final String APP_CIPHER_INSTANCE = "AES/GCM/NoPadding";
  static final int APP_GCM_TAG_LENGTH_BITS = 128;
  static final int APP_GCM_IV_LENGTH = 12;
  static final String APP_DATE_FORMAT = "MM/dd/yyyy HH:mm:ss";
  static final String APP_BACKUP_NAME_FORMAT = "yyyy.MM.dd-HHmmss";
  static final int APP_NUM_OF_EMPTY_LINES_TO_CLEAR_THE_SCREEN = 10000;
  static final int APP_PASSWORD_SHOW_SECONDS = 30;
  static final int APP_CLIPBOARD_CLEAR_SECONDS = 30;
  static final int APP_MAX_NOT_READ_CACHED_PASSWORD_SECONDS = 300;
  static final int APP_MAX_NOT_READ_INPUTS_SECONDS = 60;
  static final int APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION = 70;
  static final int APP_MAX_NUM_OF_BACKUPS = 70;

  static final String FOLD = "" + SPACE_CHAR + SPACE_CHAR;
  static final String FOLD2 = "" + SPACE_CHAR + SPACE_CHAR + SPACE_CHAR + SPACE_CHAR + SPACE_CHAR;

  static final String SEP1 = "," + SPACE_CHAR;
  static final String SEP2 = SPACE_CHAR + "->" + SPACE_CHAR;
  static final String SEP3 = SPACE_CHAR + ":" + SPACE_CHAR;
  static final String SEP9 = SPACE_CHAR + "|" + SPACE_CHAR;

  static final String YES = "yes";

  static final String SEP = File.separator;

  static final String PASSWORD_STATUS_MARGIN = "_";
  static final String PASSWORD_STATUS_STATUS = "-";

  static final String PROMPT = APP_NAME + "> ";

  static final String LETTERS_UCAZ = "[A-Z]";
  static final String LETTERS_LCAZ = "[a-z]";
  static final String LETTERS09 = "[0-9]";
  static final String LETTERS_SPEC_CHARS = "[.?!,;:-+_*@=<>]";

  static final SimpleDateFormat SIMPLE_DATE_FORMAT = new SimpleDateFormat(APP_DATE_FORMAT);

  static final SimpleDateFormat BACKUP_DATE_FORMAT = new SimpleDateFormat(APP_BACKUP_NAME_FORMAT);

  static final Console CONSOLE = System.console();

  /**
   * Resolves the base directory under which the password, admin and backup directories live, ending
   * with the platform file separator (or empty for the working directory). When the application runs
   * from a jar the base is the jar's own directory, so the data folders sit next to the jar on every
   * platform no matter what the process working directory is; when it runs from loose class files
   * (the test/dev classpath) the base is empty, preserving working-directory-relative behavior.
   *
   * @return the absolute base directory ending with the file separator, or an empty string to anchor
   *     at the working directory
   */
  private static final String resolveDataBaseDir() {
    try {
      CodeSource codeSource = Const.class.getProtectionDomain().getCodeSource();
      if (codeSource == null) {
        return "";
      }
      URL location = codeSource.getLocation();
      if (location == null) {
        return "";
      }
      File codeSourceFile = new File(location.toURI());
      if (codeSourceFile.isFile()) {
        File baseDir = codeSourceFile.getParentFile();
        if (baseDir != null) {
          return baseDir.getAbsolutePath() + File.separator;
        }
      }
    } catch (Exception e) {
      // Fall through to the working-directory-relative default below.
    }
    return "";
  }
}
