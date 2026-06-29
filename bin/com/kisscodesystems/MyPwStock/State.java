package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.Const.*;

import java.io.File;
import java.util.Date;
import java.util.HashMap;

/**
 * Mutable runtime state: folder handles, password and file-content char arrays, salt/IV byte
 * arrays, current keys, and the password caches.
 */
final class State {
  static File passwordDirFolder = null;
  static File adminDirFolder = null;
  static File backupDirFolder = null;

  static char[] passwordFromInputOriginal = new char[0];

  static char[] passwordFromInputVerified = new char[0];

  static char[] passwordForFile1 = new char[0];

  static char[] passwordForFile2 = new char[0];

  static char[] passwordForKey = new char[0];

  static char[] fileContent1Orig = new char[0];

  static char[] fileContent1Trim = new char[0];

  static char[] fileContent2Orig = new char[0];
  static char[] fileContent2Trim = new char[0];

  static String key1 = "";
  static String key2 = "";

  static char allowNotesFile1 = SPACE_CHAR;
  static char allowNotesFile2 = SPACE_CHAR;

  static byte[] sl1 = new byte[0];
  static byte[] iv1 = new byte[0];
  static byte[] sl2 = new byte[0];
  static byte[] iv2 = new byte[0];

  static char[] passwordForAdmin = new char[0];

  static char[] fileContentAdminOrig = new char[0];
  static char[] fileContentAdminTrim = new char[0];

  static byte[] slAdmin = new byte[0];
  static byte[] ivAdmin = new byte[0];

  static boolean toCachePasswords = false;

  // True only while silently trying a cached file password against a different file, so
  // getFileContent does not print the "incorrect file password" message for failed attempts.
  static boolean quietFilePasswordTrial = false;

  static HashMap<String, char[]> cachedFilePasswords = new HashMap<String, char[]>();

  static char[] cachedAdminPassword = new char[0];

  static Date lastReadOrCacheCachablePassword = new Date();
}
