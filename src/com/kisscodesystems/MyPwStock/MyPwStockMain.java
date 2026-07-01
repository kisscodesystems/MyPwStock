/*
 ** MyPwStock application.
 **
 ** Description:    : This tiny application stores passwords
 **                   or any key - value sensitive data in encrypted format.
 **
 ** Published       : 02.01.2017
 **
 ** Current version : 2.4
 **
 ** Developed by    : Jozsef Kiss
 **                   KissCode Systems Kft
 **                   <http://www.prdare.com>
 **
 ** Changelog       : 1.0 - 02.01.2017
 **                   Initial release.
 **                   1.1 - 04.05.2017
 **                   Smaller improvements.
 **                   1.2 - 08.19.2017
 **                   Smaller improvements.
 **                   2.0 - 06.27.2026
 **                   Refactorings, adding new features.
 **                   2.1 - 06.29.2026
 **                   Improve failsafe saving of encryption.
 **                   2.2 - 06.29.2026
 **                   Improve failsafe password entering.
 **                   2.3 - 06.30.2026
 **                   Increase length of logging, add small features.
 **                   2.4 - 06.30.2026
 **                   Improve copy display.
 **
 ** MyPwStock is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** Free Software Foundation, version 3.
 **
 ** MyPwStock is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with MyPwStock. If not, see <http://www.gnu.org/licenses/>.
 */
package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.Args.*;
import static com.kisscodesystems.MyPwStock.ArrayUtils.*;
import static com.kisscodesystems.MyPwStock.Auth.*;
import static com.kisscodesystems.MyPwStock.ConsoleIo.*;
import static com.kisscodesystems.MyPwStock.Const.*;
import static com.kisscodesystems.MyPwStock.Crypto.*;
import static com.kisscodesystems.MyPwStock.Messages.*;
import static com.kisscodesystems.MyPwStock.Router.*;
import static com.kisscodesystems.MyPwStock.State.*;
import static com.kisscodesystems.MyPwStock.Validate.*;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Date;

/**
 * Application entry point: bootstraps the password, backup and admin directories and the admin file
 * on first run, then hands control to the dispatcher.
 */
public final class MyPwStockMain {
  /**
   * Blocks deserialization of this class by always failing.
   *
   * @param in the object input stream that would supply the serialized data
   * @throws IOException always, to prevent deserialization
   */
  private final void readObject(ObjectInputStream in) throws IOException {
    throw new IOException("");
  }

  /**
   * Blocks serialization of this class by always failing.
   *
   * @param out the object output stream that would receive the serialized data
   * @throws IOException always, to prevent serialization
   */
  private final void writeObject(ObjectOutputStream out) throws IOException {
    throw new IOException("");
  }

  /**
   * Application entry point: verifies the console is available, resolves the password, admin and
   * backup directories, and on first run (when admin handling is required) creates the directories,
   * prompts for and stores the admin password, and writes the initial admin file, before clearing
   * sensitive buffers, dispatching the arguments to the router, and exiting the JVM.
   *
   * @param args the command-line arguments supplied to the application
   */
  public static final void main(String[] args) {
    if (CONSOLE == null) {
      throw systemexit("Error - console is null, main");
    }
    if (isGoodArgsObject(args)) {
      passwordDirFolder = new File(APP_PASSWORD_DIR);
      adminDirFolder = new File(APP_ADMIN_DIR);
      backupDirFolder = new File(APP_BACKUP_DIR);
      boolean adminStuffNeeded = true;
      if (args.length == 0
          || ((args.length == 1)
              && (ARG_QUESTION_MARK.equals(args[0].toLowerCase())
                  || ARG_HELP.equals(args[0].toLowerCase())))
          || ((args.length == 2)
              && ((ARG_APPLICATION.equals(args[0].toLowerCase())
                      && ARG_DESCRIBE.equals(args[1].toLowerCase()))
                  || (ARG_APPLICATION.equals(args[0].toLowerCase())
                      && ARG_STORY.equals(args[1].toLowerCase()))
                  || (ARG_WELCOME.equals(args[0].toLowerCase())
                      && ARG_SCREEN.equals(args[1].toLowerCase()))
                  || (ARG_GOOD.equals(args[0].toLowerCase())
                      && ARG_PASSWORD.equals(args[1].toLowerCase()))
                  || (ARG_PASSWORD.equals(args[0].toLowerCase())
                      && ARG_NOTE.equals(args[1].toLowerCase()))))
          || ((args.length == 3)
              && ((ARG_CLEAR.equals(args[0].toLowerCase())
                  && ARG_SCREEN.equals(args[1].toLowerCase()))))) {
        adminStuffNeeded = false;
      }
      if (passwordDirFolder == null) {
        throw systemexit("Error - passwordDirFolder is null, main");
      }
      if (!passwordDirFolder.exists() && adminStuffNeeded) {
        if (!(YES.equals(
            readline(
                MESSAGE_IS_FOLDER_SAFE, APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES)))) {
          throw systemexit("Error - Folder is not safe by answer, main");
        }
        if (!passwordDirFolder.mkdirs()) {
          throw systemexit(
              "Error - unable to create the password folder: "
                  + passwordDirFolder.getAbsolutePath()
                  + ", main");
        }
        if (backupDirFolder == null) {
          throw systemexit("Error - backupDirFolder is null, main");
        }
        if (backupDirFolder.exists()) {
          throw systemexit("Error - backupDirFolder already exists, main");
        }
        if (!backupDirFolder.mkdirs()) {
          throw systemexit(
              "Error - unable to create the backup folder: "
                  + backupDirFolder.getAbsolutePath()
                  + ", main");
        }
        if (adminDirFolder == null) {
          throw systemexit("Error - adminDirFolder is null, main");
        }
        if (adminDirFolder.exists()) {
          throw systemexit("Error - adminDirFolder already exists, main");
        }
        if (!adminDirFolder.mkdirs()) {
          throw systemexit(
              "Error - unable to create the admin folder: "
                  + adminDirFolder.getAbsolutePath()
                  + ", main");
        }
        File[] adminFiles = adminDirFolder.listFiles();
        if (adminFiles == null) {
          throw systemexit("Error - adminFiles is null , main");
        }
        if (adminFiles.length != 0) {
          throw systemexit("Error - Admin folder is not empty, main");
        }
        outprintln(MESSAGE_WELCOME_SCREEN);
        outprintln(MESSAGE_DO_NOT_FORGET_YOUR_ADMIN_PASSWORD);
        readPassword(PASSWORD_TYPE_ADMIN, true, APP_ADMIN_FILE_NAME);
        clearCharArray(fileContentAdminOrig);
        fileContentAdminOrig = new char[APP_FILE_CONTENT_MAX_LENGTH];
        clearCharArray(fileContentAdminOrig);
        String adminIniContent =
            ""
                + new String(generateRandomHeader())
                + SIMPLE_DATE_FORMAT.format(new Date())
                + SEP9
                + MESSAGE_LOG_APPLICATION_INSTANCE_INITIALIZE
                + NEW_LINE_CHAR;
        for (int i = 0; i < Math.min(adminIniContent.length(), APP_MAX_LENGTH_TO_LOG); i++) {
          fileContentAdminOrig[i] = adminIniContent.charAt(i);
        }
        if (saveFile(APP_ADMIN_FILE_NAME, PASSWORD_TYPE_ADMIN)) {
          outprintln(MESSAGE_ADMIN_FILE_HAS_BEEN_CREATED);
        }
        clearCharArray(fileContentAdminOrig);

        adminIniContent = null;

        adminFiles = null;
      }

      // Complete or discard any save that a previous run left half-applied (crashed between
      // deleting the old file parts and renaming the new ".nw" parts in), before anything is read.
      recoverInterruptedSaves(passwordDirFolder, APP_PD_POSTFIX);
      recoverInterruptedSaves(adminDirFolder, APP_AN_POSTFIX);

      clearCharArrays();
      clearByteArrays();
      letsWork(args);
      clearCharArrays();
      clearByteArrays();
      adminStuffNeeded = false;
    }

    System.exit(0);
  }
}
