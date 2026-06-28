package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.State.*;

import java.text.Normalizer;

/**
 * Low-level helpers for char and byte arrays: secure clearing/wiping, index scanning, and ASCII
 * char-to-byte and byte-to-char conversion.
 */
final class ArrayUtils {
  /**
   * Best-effort conversion of arbitrary text to printable ASCII (32-126), used to fold non-ASCII
   * note input into the ASCII-only storage format. Accented Latin letters are decomposed and their
   * diacritics removed (for example "café" becomes "cafe"), common typographic punctuation and a
   * few non-decomposing Latin letters/ligatures are mapped to ASCII equivalents (for example "ß"
   * becomes "ss" and smart quotes become straight quotes), and anything left without an ASCII
   * representation (other scripts, emoji, control characters, line breaks) is dropped. The result
   * is therefore lossy and may be shorter than the input or empty.
   *
   * @param s the text to fold (may be null)
   * @return the folded printable-ASCII text (never null)
   */
  static final String foldToAscii(String s) {
    if (s == null) {
      return "";
    }
    // Map punctuation and Latin letters/ligatures that NFKD does not decompose to ASCII.
    s =
        s.replace('‘', '\'')
            .replace('’', '\'')
            .replace('‚', '\'')
            .replace('‛', '\'')
            .replace('′', '\'')
            .replace('“', '"')
            .replace('”', '"')
            .replace('„', '"')
            .replace('‟', '"')
            .replace('″', '"')
            .replace('–', '-')
            .replace('—', '-')
            .replace('―', '-')
            .replace(' ', ' ')
            .replace(' ', ' ')
            .replace(' ', ' ')
            .replace("…", "...")
            .replace("ß", "ss")
            .replace("æ", "ae")
            .replace("Æ", "AE")
            .replace("œ", "oe")
            .replace("Œ", "OE")
            .replace("ø", "o")
            .replace("Ø", "O")
            .replace("ł", "l")
            .replace("Ł", "L")
            .replace("đ", "d")
            .replace("Đ", "D")
            .replace("ð", "d")
            .replace("Ð", "D")
            .replace("þ", "th")
            .replace("Þ", "Th");
    String n = Normalizer.normalize(s, Normalizer.Form.NFKD);
    StringBuilder sb = new StringBuilder(n.length());
    for (int i = 0; i < n.length(); i++) {
      char c = n.charAt(i);
      if (c >= 32 && c <= 126) {
        sb.append(c);
      }
    }
    return sb.toString();
  }
  /**
   * Converts a char array to a byte array by narrowing each char to a byte (ASCII).
   *
   * @param chars the characters to convert
   * @return a new byte array holding the ASCII bytes of the given characters
   */
  static final byte[] toBytesASCII(char[] chars) {
    byte[] bytes = new byte[0];
    if (chars == null) {
      throw systemexit("Error - chars is null, toBytesASCII");
    }
    bytes = new byte[chars.length];
    for (int i = 0; i < chars.length; i++) {
      bytes[i] = (byte) chars[i];
    }

    return bytes;
  }

  /**
   * Converts a byte array to a char array by widening each byte to a char (ASCII).
   *
   * @param bytes the bytes to convert
   * @return a new char array holding the ASCII characters of the given bytes
   */
  static final char[] toCharsASCII(byte[] bytes) {
    char[] chars = new char[0];
    if (bytes == null) {
      throw systemexit("Error - bytes is null, toCharsASCII");
    }
    chars = new char[bytes.length];
    for (int i = 0; i < bytes.length; i++) {
      chars[i] = (char) bytes[i];
    }

    return chars;
  }

  /** Securely clears all in-memory password and file-content char arrays held in state. */
  static final void clearCharArrays() {
    clearCharArray(passwordFromInputOriginal);
    clearCharArray(passwordFromInputVerified);
    clearCharArray(passwordForFile1);
    clearCharArray(passwordForFile2);
    clearCharArray(passwordForKey);
    clearCharArray(passwordForAdmin);
    clearCharArray(fileContent1Orig);
    clearCharArray(fileContent1Trim);
    clearCharArray(fileContent2Orig);
    clearCharArray(fileContent2Trim);
    clearCharArray(fileContentAdminOrig);
    clearCharArray(fileContentAdminTrim);
  }

  /**
   * Overwrites every element of the given char array with the space character. Does nothing if the
   * array is null.
   *
   * @param charArray the char array to wipe
   */
  static final void clearCharArray(char[] charArray) {
    if (charArray != null) {
      for (int i = 0; i < charArray.length; i++) {
        charArray[i] = SPACE_CHAR;
      }
    }
  }

  /** Securely clears all in-memory salt and IV byte arrays held in state. */
  static final void clearByteArrays() {
    clearByteArray(sl1);
    clearByteArray(iv1);
    clearByteArray(sl2);
    clearByteArray(iv2);
    clearByteArray(slAdmin);
    clearByteArray(ivAdmin);
  }

  /**
   * Overwrites every element of the given byte array with the null byte. Does nothing if the array
   * is null.
   *
   * @param byteArray the byte array to wipe
   */
  static final void clearByteArray(byte[] byteArray) {
    if (byteArray != null) {
      for (int i = 0; i < byteArray.length; i++) {
        byteArray[i] = NULL_BYTE;
      }
    }
  }

  /**
   * Returns the index immediately before the first padding (NUL) character in the array. Password
   * file (file1/file2) content buffers are NUL-padded, so the first NUL marks the end of content;
   * this lets stored note values legally contain spaces.
   *
   * @param orig the char array to scan
   * @return the index one position before the first NUL character, or -1 if none is found
   */
  static final int getFirstPadCharIndexBefore(char[] orig) {
    int index = -1;
    if (orig == null) {
      throw systemexit("Error - orig is null, getFirstPadCharIndexBefore");
    }
    for (int i = 0; i < orig.length; i++) {
      if (orig[i] == NUL_CHAR) {
        index = i - 1;
        break;
      }
    }

    return index;
  }

  /**
   * Returns the length of the leading header line of decrypted file content, i.e. the number of
   * characters up to and including the first newline. Because the header has a random length, this
   * is used instead of a fixed offset to locate the content that follows it.
   *
   * @param content the decrypted file content to scan
   * @return the index just past the first newline (the header length)
   */
  static final int getHeaderLength(char[] content) {
    if (content == null) {
      throw systemexit("Error - content is null, getHeaderLength");
    }
    for (int i = 0; i < content.length; i++) {
      if (content[i] == NEW_LINE_CHAR) {
        return i + 1;
      }
    }
    throw systemexit("Error - no header newline found, getHeaderLength");
  }

  /**
   * Returns the index of the first newline character that is immediately followed by a space.
   *
   * @param orig the char array to scan
   * @return the index of the matching newline character, or -1 if no such pair is found
   */
  static final int getFirstNewLineAndSpaceCharIndex(char[] orig) {
    int index = -1;
    if (orig == null) {
      throw systemexit("Error - orig is null, getFirstNewLineAndSpaceCharIndex");
    }
    for (int i = 0; i < orig.length - 1; i++) {
      if (orig[i] == NEW_LINE_CHAR && orig[i + 1] == SPACE_CHAR) {
        index = i;
        break;
      }
    }

    return index;
  }
}
