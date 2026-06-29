package com.kisscodesystems.MyPwStock;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Random;
import org.junit.Test;

/**
 * Regression tests for the MyPwStock validators, password generation and the encrypted-file format.
 * Validator behaviour is checked against oracles derived from the CURRENT {@link Const} thresholds
 * (so the tests stay correct as the policy is tuned), and the crypto/file-format tests exercise the
 * code end to end.
 */
public final class MyPwStockTest {
  private static String[] sampleStrings() {
    ArrayList<String> l = new ArrayList<String>();
    String[] base = {
      "",
      " ",
      "  ",
      "a",
      "A",
      "1",
      ".",
      "ab cd",
      "Abc123.!",
      "WTb7u.-84",
      "84",
      "noUpper1.",
      "NOLOWER1.",
      "NoDigits.",
      "NoSpecial11",
      "with\nnewline",
      "tab\there",
      "verylongname",
      "ász",
      "éüö",
      " nul",
      "trailing ",
      " leading",
      "MixedCASE_With-Specials@99",
      "0123456789",
      "ABCDEFGabcdefg",
      "../etc/passwd",
      "name/with/slash",
      "name.pd",
      "key1",
      "Aa1.",
      "Aa1.!!!"
    };
    for (String s : base) {
      l.add(s);
    }
    Random r = new Random(424242L);
    for (int i = 0; i < 400; i++) {
      int len = r.nextInt(12);
      char[] cs = new char[len];
      for (int j = 0; j < len; j++) {
        cs[j] = (char) (30 + r.nextInt(110));
      }
      l.add(new String(cs));
    }
    // Boundary-length samples that exercise the current Const length limits (so the changed
    // thresholds are actually covered). Built from "Aa1." so longer ones also satisfy the
    // good-password character-class counts.
    int[] boundaryLengths = {
      Const.APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS - 1,
      Const.APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS,
      Const.APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS + 1,
      Const.APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION - 1,
      Const.APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION,
      Const.APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION + 1,
      Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES - 1,
      Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES,
      Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES + 1,
      Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES + 50
    };
    String pattern = "Aa1.";
    for (int len : boundaryLengths) {
      if (len < 0) {
        continue;
      }
      char[] cs = new char[len];
      for (int j = 0; j < len; j++) {
        cs[j] = pattern.charAt(j % pattern.length());
      }
      l.add(new String(cs));
    }
    return l.toArray(new String[0]);
  }

  @Test
  public void isValidKeyOrFileNameMatchesPolicy() {
    for (String s : sampleStrings()) {
      boolean expected =
          Validate.isASCIIandNONSPACE(s)
              && s.length() <= Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES
              && s.length() >= Const.APP_MIN_LENGTH_OF_KEYS_AND_FILE_NAMES;
      boolean actual = Validate.isValidKeyOrFileName(s, false);
      assertEquals("isValidKeyOrFileName(" + s + ")", expected, actual);
    }
  }

  @Test
  public void isValidBackupDescriptionMatchesPolicy() {
    for (String s : sampleStrings()) {
      boolean expected =
          s != null
              && Validate.isASCII(s)
              && s.length() < Const.APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION;
      boolean actual = Validate.isValidBackupDescription(s);
      assertEquals("isValidBackupDescription(" + s + ")", expected, actual);
    }
  }

  @Test
  public void isValidGoodPasswordMatchesPolicy() {
    for (String s : sampleStrings()) {
      char[] p = s.toCharArray();
      boolean expected;
      if (!Validate.isASCIIandNONSPACE(p)
          || p.length > Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES
          || p.length < Const.APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS) {
        expected = false;
      } else {
        int uc = 0;
        int lc = 0;
        int dg = 0;
        int sp = 0;
        for (int i = 0; i < p.length; i++) {
          char c = p[i];
          if (c >= 65 && c <= 90) {
            uc++;
          } else if (c >= 97 && c <= 122) {
            lc++;
          } else if (c >= 48 && c <= 57) {
            dg++;
          } else {
            sp++;
          }
        }
        expected =
            uc >= Const.APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS
                && lc >= Const.APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS
                && dg >= Const.APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS
                && sp >= Const.APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS;
      }
      boolean actual = Validate.isValidGoodPassword(p.clone(), false);
      assertEquals("isValidGoodPassword(" + s + ")", expected, actual);
    }
  }

  // A note (non-space ASCII, within the key/file-name max, at least the configured note minimum).
  @Test
  public void isValidNoteMatchesPolicy() {
    for (String s : sampleStrings()) {
      char[] p = s.toCharArray();
      boolean expected =
          Validate.isASCIIandNONSPACE(p)
              && p.length <= Const.APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES
              && p.length >= Const.APP_MIN_LENGTH_OF_NOTE;
      boolean actual = Validate.isValidNote(p.clone(), false);
      assertEquals("isValidNote(" + s + ")", expected, actual);
    }
  }

  // Rich notes ('r'-mode values) allow spaces (printable ASCII 32-126) up to APP_MAX_LENGTH_OF_NOTE.
  @Test
  public void isValidRichNoteMatchesPolicy() {
    for (String s : sampleStrings()) {
      char[] p = s.toCharArray();
      boolean expected =
          Validate.isASCII(p)
              && p.length <= Const.APP_MAX_LENGTH_OF_NOTE
              && p.length >= Const.APP_MIN_LENGTH_OF_NOTE;
      boolean actual = Validate.isValidRichNote(p.clone(), false);
      assertEquals("isValidRichNote(" + s + ")", expected, actual);
    }
  }

  // Password files are padded with NUL: getFirstPadCharIndexBefore returns the index just before
  // the first NUL (the last meaningful character), or -1 when there is no NUL. Checked on inputs
  // that actually contain NUL at various positions (the sampleStrings never do).
  @Test
  public void getFirstPadCharIndexBeforeMatchesPolicy() {
    char[][] cases = {
      new char[0],
      "abc".toCharArray(),
      new char[] {Const.NUL_CHAR},
      new char[] {'a', Const.NUL_CHAR, 'b'},
      new char[] {'a', 'b', 'c', Const.NUL_CHAR},
      new char[] {Const.NUL_CHAR, 'a', Const.NUL_CHAR},
      new char[] {' ', ' ', Const.NUL_CHAR},
      new char[] {'x', 'y', 'z'}
    };
    for (char[] cs : cases) {
      int expected = -1;
      for (int i = 0; i < cs.length; i++) {
        if (cs[i] == Const.NUL_CHAR) {
          expected = i - 1;
          break;
        }
      }
      assertEquals(
          "getFirstPadCharIndexBefore",
          expected,
          ArrayUtils.getFirstPadCharIndexBefore(cs.clone()));
    }
  }

  @Test
  public void generatedGoodPasswordIsValid() {
    for (int i = 0; i < 200; i++) {
      char[] p = Crypto.getGeneratedGoodPassword();
      assertTrue("generated good password must be valid", Validate.isValidGoodPassword(p, false));
    }
  }

  @Test
  public void countsOnlyPasswordContainerFiles() throws Exception {
    File dir = Files.createTempDirectory("mypwstock-count").toFile();
    try {
      createEmptyFile(dir, "a" + Const.APP_PD_POSTFIX);
      createEmptyFile(dir, "b" + Const.APP_PD_POSTFIX);
      createEmptyFile(dir, "c" + Const.APP_PD_POSTFIX);
      // side files and unrelated files must not be counted
      createEmptyFile(dir, "a" + Const.APP_SL_POSTFIX);
      createEmptyFile(dir, "a" + Const.APP_IV_POSTFIX);
      createEmptyFile(dir, "notes.txt");
      // a directory whose name ends with the postfix must not be counted
      new File(dir, "sub" + Const.APP_PD_POSTFIX).mkdir();
      assertEquals(3, FileCommands.countPasswordContainerFiles(dir));
    } finally {
      deleteRecursively(dir);
    }
  }

  @Test
  public void fileAddLimitTracksMaxNumOfFiles() throws Exception {
    File dir = Files.createTempDirectory("mypwstock-limit").toFile();
    try {
      int max = Const.APP_MAX_NUM_OF_FILES;
      for (int i = 0; i < max - 1; i++) {
        createEmptyFile(dir, "f" + i + Const.APP_PD_POSTFIX);
      }
      // one below the cap: add is still allowed and exactly one slot remains
      int count = FileCommands.countPasswordContainerFiles(dir);
      assertEquals(max - 1, count);
      assertTrue("below cap should allow add", count < max);
      assertEquals("available slots", 1, max - count);
      // at the cap: add is blocked and no slots remain
      createEmptyFile(dir, "last" + Const.APP_PD_POSTFIX);
      count = FileCommands.countPasswordContainerFiles(dir);
      assertEquals(max, count);
      assertTrue("at cap should block add", count >= max);
      assertEquals("no slots left", 0, max - count);
      // over the cap: still blocked
      createEmptyFile(dir, "extra" + Const.APP_PD_POSTFIX);
      count = FileCommands.countPasswordContainerFiles(dir);
      assertTrue("over cap should block add", count >= max);
    } finally {
      deleteRecursively(dir);
    }
  }

  // End-to-end check of the encrypted-file format: build content with a random header, save it
  // (AES-GCM encrypt to pd/), wipe memory, load it back, look the key up, and confirm a wrong
  // password is rejected by the authenticated cipher. Runs against pd/ and an/ under the current
  // working directory.
  @Test
  public void cryptoFileRoundTripWithGcmAndRandomHeader() throws Exception {
    new File("pd").mkdirs();
    new File("an").mkdirs();
    try {
      State.toCachePasswords = false;
      char[] filePw = "ABCDabcd123..".toCharArray();
      State.passwordForFile1 = filePw.clone();

      char[] content = new char[Const.APP_FILE_CONTENT_MAX_LENGTH];
      int p = 0;
      for (char c : Crypto.generateRandomHeader()) {
        content[p++] = c;
      }
      content[p++] = Const.ALLOW_NOTES_NO;
      content[p++] = '\n';
      String key = "mykey";
      String val = "Secr3t.Value!";
      for (char c : key.toCharArray()) {
        content[p++] = c;
      }
      content[p++] = '\n';
      for (char c : val.toCharArray()) {
        content[p++] = c;
      }
      content[p++] = '\n';
      // Password files are padded with NUL: saveFile/getFirstPadCharIndexBefore use the first NUL
      // to mark the end of meaningful content (a space would be treated as content, since notes may
      // contain spaces).
      for (int i = p; i < content.length; i++) {
        content[i] = Const.NUL_CHAR;
      }
      State.fileContent1Orig = content;

      assertTrue("saveFile", Crypto.saveFile("f", Const.PASSWORD_TYPE_FILE1));

      // wipe in-memory content; reload purely from the encrypted files on disk
      ArrayUtils.clearCharArray(State.fileContent1Orig);
      State.fileContent1Orig = new char[0];
      State.passwordForFile1 = filePw.clone();
      assertTrue(
          "getFileContent with correct password",
          Crypto.getFileContent("f", Const.PASSWORD_TYPE_FILE1));

      assertTrue("key located", Crypto.getKeyPos(Const.PASSWORD_TYPE_FILE1, "mykey") != -1);
      assertEquals(
          "value round-trips", val, new String(PasswordCommands.getKeyPasswordFile1("mykey")));

      // wrong password must be rejected by the GCM tag, not silently decrypt to garbage
      ArrayUtils.clearCharArray(State.fileContent1Orig);
      State.fileContent1Orig = new char[0];
      State.passwordForFile1 = "WRONGpass123..".toCharArray();
      assertFalse("wrong password rejected", Crypto.getFileContent("f", Const.PASSWORD_TYPE_FILE1));
    } finally {
      deleteRecursively(new File("pd"));
      deleteRecursively(new File("an"));
    }
  }

  // Builds a password file with a single key/value pair and saves it to disk, leaving a valid,
  // mutually consistent .pd/.iv/.sl triple under "pd/".
  private static void buildAndSaveFile1(String fileName, String key, String val, char[] pw) {
    State.toCachePasswords = false;
    State.passwordForFile1 = pw.clone();
    char[] content = new char[Const.APP_FILE_CONTENT_MAX_LENGTH];
    int p = 0;
    for (char c : Crypto.generateRandomHeader()) {
      content[p++] = c;
    }
    content[p++] = Const.ALLOW_NOTES_NO;
    content[p++] = '\n';
    for (char c : key.toCharArray()) {
      content[p++] = c;
    }
    content[p++] = '\n';
    for (char c : val.toCharArray()) {
      content[p++] = c;
    }
    content[p++] = '\n';
    for (int i = p; i < content.length; i++) {
      content[i] = Const.NUL_CHAR;
    }
    State.fileContent1Orig = content;
    assertTrue("saveFile " + fileName, Crypto.saveFile(fileName, Const.PASSWORD_TYPE_FILE1));
  }

  // Reloads a password file purely from disk and returns the value stored under the given key.
  private static String readValueFile1(String fileName, String key, char[] pw) {
    ArrayUtils.clearCharArray(State.fileContent1Orig);
    State.fileContent1Orig = new char[0];
    State.passwordForFile1 = pw.clone();
    assertTrue(
        "getFileContent " + fileName, Crypto.getFileContent(fileName, Const.PASSWORD_TYPE_FILE1));
    return new String(PasswordCommands.getKeyPasswordFile1(key));
  }

  private static void rename(String from, String to) {
    assertTrue("rename " + from, new File(from).renameTo(new File(to)));
  }

  @Test
  public void recoverRollsForwardWhenRenameInterrupted() throws Exception {
    new File("pd").mkdirs();
    new File("an").mkdirs();
    try {
      char[] pw = "ABCDabcd123..".toCharArray();
      buildAndSaveFile1("rf", "k", "NewValue.1!", pw);
      // Simulate a crash after the new parts were written and the old parts deleted, but before any
      // ".nw" part was renamed back: the whole live set is gone, the new bytes survive only in .nw.
      rename("pd/rf.pd", "pd/rf.pd.nw");
      rename("pd/rf.iv", "pd/rf.iv.nw");
      rename("pd/rf.sl", "pd/rf.sl.nw");
      Crypto.recoverInterruptedSaves(new File("pd"), Const.APP_PD_POSTFIX);
      assertTrue("live data restored", new File("pd/rf.pd").isFile());
      assertTrue("live iv restored", new File("pd/rf.iv").isFile());
      assertTrue("live sl restored", new File("pd/rf.sl").isFile());
      assertFalse("nw consumed", new File("pd/rf.pd.nw").exists());
      assertEquals("rolled-forward content decrypts", "NewValue.1!", readValueFile1("rf", "k", pw));
    } finally {
      deleteRecursively(new File("pd"));
      deleteRecursively(new File("an"));
    }
  }

  @Test
  public void recoverRollsBackWhenLiveSetComplete() throws Exception {
    new File("pd").mkdirs();
    new File("an").mkdirs();
    try {
      char[] pw = "ABCDabcd123..".toCharArray();
      buildAndSaveFile1("rb", "k", "KeepThis.1!", pw);
      // Simulate a crash after the new parts were written but before the rename phase began (its
      // first act deletes a live part), so the live set is still complete and authoritative.
      java.nio.file.Files.write(new File("pd/rb.pd.nw").toPath(), new byte[] {1, 2, 3});
      java.nio.file.Files.write(new File("pd/rb.iv.nw").toPath(), new byte[] {4, 5, 6});
      java.nio.file.Files.write(new File("pd/rb.sl.nw").toPath(), new byte[] {7, 8, 9});
      Crypto.recoverInterruptedSaves(new File("pd"), Const.APP_PD_POSTFIX);
      assertFalse("data nw discarded", new File("pd/rb.pd.nw").exists());
      assertFalse("iv nw discarded", new File("pd/rb.iv.nw").exists());
      assertFalse("sl nw discarded", new File("pd/rb.sl.nw").exists());
      assertEquals("previous content kept", "KeepThis.1!", readValueFile1("rb", "k", pw));
    } finally {
      deleteRecursively(new File("pd"));
      deleteRecursively(new File("an"));
    }
  }

  @Test
  public void recoverMergesPartiallyRenamedParts() throws Exception {
    new File("pd").mkdirs();
    new File("an").mkdirs();
    try {
      char[] pw = "ABCDabcd123..".toCharArray();
      buildAndSaveFile1("mg", "k", "Merged.9!", pw);
      // Simulate a crash midway through the rename phase: the data part was already renamed back
      // (so its .nw is gone and the live part is the new one), while iv and sl are still pending in
      // .nw with their live counterparts already deleted. Recovery must take .nw where it exists and
      // the live part where the .nw is already gone.
      rename("pd/mg.iv", "pd/mg.iv.nw");
      rename("pd/mg.sl", "pd/mg.sl.nw");
      Crypto.recoverInterruptedSaves(new File("pd"), Const.APP_PD_POSTFIX);
      assertTrue("iv completed", new File("pd/mg.iv").isFile());
      assertTrue("sl completed", new File("pd/mg.sl").isFile());
      assertFalse("iv nw consumed", new File("pd/mg.iv.nw").exists());
      assertEquals("merged content decrypts", "Merged.9!", readValueFile1("mg", "k", pw));
    } finally {
      deleteRecursively(new File("pd"));
      deleteRecursively(new File("an"));
    }
  }

  @Test
  public void recoverLeavesUnrecoverableStateUntouched() throws Exception {
    new File("pd").mkdirs();
    new File("an").mkdirs();
    try {
      // A lone data ".nw" with no live parts and no iv/sl ".nw": the save cannot be completed.
      // Recovery must not throw and must not present the file as a usable (complete) container.
      java.nio.file.Files.write(new File("pd/lost.pd.nw").toPath(), new byte[] {1, 2, 3});
      Crypto.recoverInterruptedSaves(new File("pd"), Const.APP_PD_POSTFIX);
      assertFalse(
          "incomplete file not treated as existing",
          Validate.isExistingPasswordFile("lost", false));
    } finally {
      deleteRecursively(new File("pd"));
      deleteRecursively(new File("an"));
    }
  }

  private static void createEmptyFile(File dir, String name) throws Exception {
    if (!new File(dir, name).createNewFile()) {
      throw new RuntimeException("could not create " + name);
    }
  }

  private static void deleteRecursively(File f) {
    File[] kids = f.listFiles();
    if (kids != null) {
      for (File k : kids) {
        deleteRecursively(k);
      }
    }
    f.delete();
  }
}
