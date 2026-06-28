package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Low-level filesystem I/O helpers: reading and writing raw bytes, copying a file, reading a
 * single-line file and creating a file.
 */
final class FileStore {
  /**
   * Reads the entire content of the file at the given path into a byte array.
   *
   * @param filePath path of the file to read
   * @return the file's bytes, or an empty array if the path is not valid
   */
  static final byte[] readFileBytes(String filePath) {
    byte[] bytes = new byte[0];
    if (isValidFilePath(filePath)) {
      File file = new File(filePath);
      if (!(file.exists() && file.isFile())) {
        throw systemexit("Error - File does not exist or it is not a file, readFileBytes");
      }
      bytes = new byte[(int) file.length()];
      FileInputStream fis = null;
      try {
        fis = new FileInputStream(filePath);
      } catch (FileNotFoundException e) {
        throw systemexit("Exception - FileNotFoundException, readFileBytes");
      }
      try {
        fis.read(bytes);
      } catch (IOException e) {
        throw systemexit("Exception - IOException, readFileBytes");
      } finally {
        try {
          fis.close();
        } catch (Exception e) {
          throw systemexit("Exception - Exception, readFileBytes");
        }
      }

      fis = null;
    }
    return bytes;
  }

  /**
   * Writes the given byte array to the file at the given path, overwriting any existing content.
   *
   * @param filePath path of the file to write
   * @param bytes bytes to write
   */
  static final void writeFileBytes(String filePath, byte[] bytes) {
    if (isValidFilePath(filePath)) {
      if (bytes == null) {
        throw systemexit("Error - bytes is null, writeFileBytes");
      }
      FileOutputStream fos = null;
      try {
        fos = new FileOutputStream(filePath);
      } catch (FileNotFoundException e) {
        throw systemexit("Exception - FileNotFoundException, writeFileBytes");
      }
      try {
        fos.write(bytes);
      } catch (IOException e) {
        throw systemexit("Exception - IOException, writeFileBytes");
      } finally {
        try {
          fos.close();
        } catch (Exception e) {
          throw systemexit("Exception - Exception, writeFileBytes");
        }
      }

      fos = null;
    }
  }

  /**
   * Copies the source file to the target path, deleting any pre-existing target file first and
   * streaming the content through a 1 KB buffer.
   *
   * @param sourceFilePath path of the file to copy from
   * @param targetFilePath path of the file to copy to
   * @return {@code true} once the copy has completed successfully
   */
  static final boolean copySingleFile(String sourceFilePath, String targetFilePath) {
    boolean success = false;
    if (!(isValidFilePath(sourceFilePath))) {
      throw systemexit("Error - sourceFilePath is not valid, copySingleFile");
    }
    if (!(isValidFilePath(targetFilePath))) {
      throw systemexit("Error - targetFilePath is not valid, copySingleFile");
    }
    File sourceFile = null;
    File targetFile = null;
    FileInputStream fis = null;
    FileOutputStream fos = null;
    int length;
    byte[] buffer;
    sourceFile = new File(sourceFilePath);
    targetFile = new File(targetFilePath);
    if (targetFile.exists()) {
      if (!targetFile.delete()) {
        throw systemexit("Error - unable to delete file: " + targetFilePath + ", copySingleFile");
      }
    }
    try {
      fis = new FileInputStream(sourceFile);
    } catch (FileNotFoundException e) {
      throw systemexit("Exception - FileNotFoundException (0), copySingleFile");
    }
    try {
      fos = new FileOutputStream(targetFile);
    } catch (FileNotFoundException e) {
      throw systemexit("Exception - FileNotFoundException (1), copySingleFile");
    }
    buffer = new byte[1024];
    length = 0;
    try {
      while ((length = fis.read(buffer)) > 0) {
        fos.write(buffer, 0, length);
        clearByteArray(buffer);
      }
    } catch (IOException e) {
      throw systemexit("Exception - IOException (0), copySingleFile");
    }
    try {
      fis.close();
    } catch (IOException e) {
      throw systemexit("Exception - IOException (1), copySingleFile");
    }
    try {
      fos.close();
    } catch (IOException e) {
      throw systemexit("Exception - IOException (2), copySingleFile");
    }
    success = true;

    fis = null;
    fos = null;
    sourceFile = null;
    targetFile = null;
    length = 0;
    buffer = null;

    return success;
  }

  /**
   * Reads the first line of the file at the given path.
   *
   * @param filePath path of the file to read
   * @return the first line of the file, or an empty string if the path is not valid or the file has
   *     no line
   */
  static final String readSingleLinedFile(String filePath) {
    String line = null;
    if (isValidFilePath(filePath)) {
      File file = null;
      FileInputStream fis = null;
      InputStreamReader isr = null;
      BufferedReader br = null;
      file = new File(filePath);
      if (!(file.exists() && file.isFile())) {
        throw systemexit("Error - File does not exist or it is not a file, readSingleLinedFile");
      }
      try {
        fis = new FileInputStream(file);
      } catch (FileNotFoundException e) {
        throw systemexit("Exception - FileNotFoundException, readSingleLinedFile");
      }
      isr = new InputStreamReader(fis);
      br = new BufferedReader(isr);
      try {
        line = br.readLine();
      } catch (IOException e) {
        throw systemexit("Exception - IOException (0), readSingleLinedFile");
      } finally {
        try {
          br.close();
        } catch (IOException e) {
          throw systemexit("Exception - IOException (1), readSingleLinedFile");
        }
      }
    }
    if (line == null) {
      line = "";
    }
    return line;
  }

  /**
   * Creates a new file at the given path (deleting any existing file first) and writes the given
   * ASCII content into it.
   *
   * @param filePath path of the file to create
   * @param content ASCII text to write into the file
   * @return {@code true} if the file was created and written, {@code false} if the content is not
   *     ASCII
   */
  static final boolean createSingleFile(String filePath, String content) {
    boolean success = false;
    if (!(isValidFilePath(filePath))) {
      throw systemexit("Error - filePath is not valid, createSingleFile");
    }
    if (isASCII(content)) {
      File file = null;
      FileOutputStream fop = null;
      file = new File(filePath);
      file.delete();
      try {
        file.createNewFile();
      } catch (IOException e) {
        throw systemexit("Exception - IOException (0), createSingleFile");
      }
      try {
        fop = new FileOutputStream(file);
      } catch (FileNotFoundException e) {
        throw systemexit("Exception - FileNotFoundException, createSingleFile");
      }
      try {
        fop.write(content.getBytes());
      } catch (IOException e) {
        throw systemexit("Exception - IOException (1), createSingleFile");
      } finally {
        try {
          fop.close();
        } catch (IOException e) {
          throw systemexit("Exception - IOException (2), createSingleFile");
        }
      }
      fop = null;
      file = null;
      success = true;
    }

    return success;
  }
}
