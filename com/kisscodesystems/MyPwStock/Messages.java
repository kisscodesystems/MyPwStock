package com.kisscodesystems.MyPwStock;

import static com.kisscodesystems.MyPwStock.Args.*;
import static com.kisscodesystems.MyPwStock.Const.*;

/** User-facing and log message strings used throughout the application. */
final class Messages {
  static final String MESSAGE_THE_HISTORY_OF_APPLICATION =
      "" + NEW_LINE_CHAR + "The history of this " + APP_NAME + " instance." + NEW_LINE_CHAR;
  static final String MESSAGE_LOG_APPLICATION_INSTANCE_INITIALIZE =
      "Application instance initialize.";
  static final String MESSAGE_LOG_ADMIN_PASSWORD_CHANGE = "Admin password change.";
  static final String MESSAGE_LOG_ADMIN_REVIEW = "Admin review.";
  static final String MESSAGE_LOG_ADMIN_SEARCH = "Admin search: ";
  static final String MESSAGE_LOG_KEY_MOVE =
      "Key move (from file" + SEP1 + "to file" + SEP1 + "key): ";
  static final String MESSAGE_LOG_PASSWORD_CHANGE =
      "Key password change (file" + SEP1 + "key" + SEP2 + "new password): ";
  static final String MESSAGE_LOG_KEY_CHANGE =
      "Key change (file" + SEP1 + "old key" + SEP2 + "new key): ";
  static final String MESSAGE_LOG_KEY_DELETE = "Key delete (file" + SEP1 + "key): ";
  static final String MESSAGE_LOG_KEYS_DELETE = "Keys delete (file): ";
  static final String MESSAGE_LOG_FILE_ADD = "File add (file" + SEP2 + "password): ";
  static final String MESSAGE_LOG_FILE_DELETE = "File delete (file): ";
  static final String MESSAGE_LOG_FILES_DELETE = "Files delete.";
  static final String MESSAGE_LOG_FILE_PASSWORD_CHANGE =
      "File password change (file" + SEP2 + "new password): ";
  static final String MESSAGE_LOG_KEY_ADD = "Key add (file" + SEP1 + "key" + SEP2 + "password): ";
  static final String MESSAGE_LOG_PASSWORD_TYPE_CHANGE =
      "Password type change (file" + SEP2 + "new password type ): ";
  static final String MESSAGE_LOG_BACKUP_MAKE = "Backup make (name" + SEP9 + "description): ";
  static final String MESSAGE_LOG_BACKUP_DELETE = "Backup delete (name" + SEP9 + "success): ";
  static final String MESSAGE_LOG_RESTORE_FILE = "File restore (backup" + SEP3 + "file): ";

  static final String MESSAGE_YOUR_FILE_NAME = "<your_file_name>";
  static final String MESSAGE_YOUR_KEY_NAME = "<your_key_name>";
  static final String MESSAGE_YOUR_FILE_NAME_CURRENT = "<your_current_file_name>";
  static final String MESSAGE_YOUR_FILE_NAME_NEW = "<your_new_file_name>";
  static final String MESSAGE_YOUR_CURRENT_KEY_NAME = "<your_current_key_name>";
  static final String MESSAGE_YOUR_NEW_KEY_NAME = "<your_new_key_name>";
  static final String MESSAGE_YOUR_EXPRESSION_TO_SEARCH = "<your_expression_to_search>";
  static final String MESSAGE_YOUR_NUM_OF_EMPTY_LINES_TO_PRINT_OUT =
      "<your_number_of_empty_lines_to_print_out>";
  static final String MESSAGE_YOUR_BACKUP = "<your_backup>";

  static final String MESSAGE_APPLICATION_DESCRIBE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + APP_NAME
          + " information."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Current version: "
          + APP_VERSION
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "File specific information."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum number of password container files      : "
          + APP_MAX_NUM_OF_FILES
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum length of passwords and keys            : "
          + APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum number of passwords per file            : "
          + APP_MAX_NUM_OF_KEYS_PER_FILE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum length of generated passwords           : "
          + APP_MAX_LENGTH_OF_GENERATED_PASSWORDS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum length of log entries                   : "
          + APP_MAX_LENGTH_TO_LOG
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum length of the content of a file (bytes) : "
          + APP_FILE_CONTENT_MAX_LENGTH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Directory name of the file containers           : "
          + APP_PASSWORD_DIR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Directory name of the admin tasks               : "
          + APP_ADMIN_DIR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Directory name of the backups                   : "
          + APP_BACKUP_DIR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Postfix of password files                       : "
          + APP_PD_POSTFIX
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Postfix of initialization vector files          : "
          + APP_IV_POSTFIX
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Postfix of salt files                           : "
          + APP_SL_POSTFIX
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Postfix of newly created files of above         : "
          + APP_NW_POSTFIX
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Postfix of admin file                           : "
          + APP_AN_POSTFIX
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Name of admin file                              : "
          + APP_ADMIN_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Name of backup description file                 : "
          + APP_BACKUP_DESCRIPTION_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum length of keys and file names           : "
          + APP_MIN_LENGTH_OF_KEYS_AND_FILE_NAMES
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Storable password specific information."
          + NEW_LINE_CHAR
          + FOLD
          + " - fully stored good password:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum count of uppercase letters              : "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum count of lowercase letters              : "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum count of digits                         : "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum count of special chars                  : "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum length of passwords                     : "
          + APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS
          + NEW_LINE_CHAR
          + FOLD
          + " - note only:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Minimum length of a note                        : "
          + APP_MIN_LENGTH_OF_NOTE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Maximum length of a note                        : "
          + APP_MAX_LENGTH_OF_NOTE
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Encrypt/decrypt information."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Salt length                                     : "
          + APP_SALT_LENGTH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Pbe key spec iterations                         : "
          + APP_PBE_KEY_SPEC_ITERATIONS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Pbe key spec key length                         : "
          + APP_PBE_KEY_SPEC_KEY_LENGTH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Secret key factory instance                     : "
          + APP_SECRET_KEY_FACTORY_INSTANCE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Secret key spec algorithm                       : "
          + APP_SECRET_KEY_SPEC_ALGORYTHM
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Cipher instance                                 : "
          + APP_CIPHER_INSTANCE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Gcm tag length (bits)                           : "
          + APP_GCM_TAG_LENGTH_BITS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Gcm iv length                                   : "
          + APP_GCM_IV_LENGTH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Header minimum number of random letters         : "
          + APP_HEADER_MIN_LETTERS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Header maximum number of random letters         : "
          + APP_HEADER_MAX_LETTERS
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Other information."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The format of the displayed dates               : "
          + APP_DATE_FORMAT
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The format of the name of the backups           : "
          + APP_BACKUP_NAME_FORMAT
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Number of empty lines to clear the screen       : "
          + APP_NUM_OF_EMPTY_LINES_TO_CLEAR_THE_SCREEN
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Seconds to show the password                    : "
          + APP_PASSWORD_SHOW_SECONDS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Seconds to clear the clipboard                  : "
          + APP_CLIPBOARD_CLEAR_SECONDS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Max seconds to not read any cached password     : "
          + APP_MAX_NOT_READ_CACHED_PASSWORD_SECONDS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Max seconds to enter any input                  : "
          + APP_MAX_NOT_READ_INPUTS_SECONDS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Max length of backup description                : "
          + APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Max number of backups to create                 : "
          + APP_MAX_NUM_OF_BACKUPS
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Max attempts to enter a file password           : "
          + FILE_PASSWORD_MAX_ATTEMPTS;

  static final String MESSAGE_APPLICATION_STORY =
      NEW_LINE_CHAR
          + FOLD
          + "The application story."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "The situation."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "The most efficient way to identify a person in e-world is still the password."
          + NEW_LINE_CHAR
          + FOLD
          + "(Year: 2017)"
          + NEW_LINE_CHAR
          + FOLD
          + "Based on the fact that we cannot see into other people's heads."
          + NEW_LINE_CHAR
          + FOLD
          + "For example, if someone has thought a number, we cannot know that number."
          + NEW_LINE_CHAR
          + FOLD
          + "It is known only by who has thought it."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "The problem."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "If I thought a couple of numbers yesterday, it may be very hard for me to"
          + NEW_LINE_CHAR
          + FOLD
          + "remember each now."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "A person can have many good and different passwords in an ideal case."
          + NEW_LINE_CHAR
          + FOLD
          + "(Good password is long enough and contains many kind of characters"
          + NEW_LINE_CHAR
          + FOLD
          + " -> strong enough and hard to guess password is good password.)"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "But. We are humans and the password is just a password, right?"
          + NEW_LINE_CHAR
          + FOLD
          + "This is not the most important thing in our life."
          + NEW_LINE_CHAR
          + FOLD
          + "Hard to guess password usually means hard to remember password too."
          + NEW_LINE_CHAR
          + FOLD
          + "There are people who can hardly memorize their passwords."
          + NEW_LINE_CHAR
          + FOLD
          + "(A good and monthly changed password can be forgotten easily"
          + NEW_LINE_CHAR
          + FOLD
          + "if not used for a couple of weeks, believe me.)"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "To remember a password I can write it to a postit or save on a computer"
          + NEW_LINE_CHAR
          + FOLD
          + "in a text file. The basic idea that the password should be known only by the"
          + NEW_LINE_CHAR
          + FOLD
          + "person who has constructed it is breached in this case. Because it can be read"
          + NEW_LINE_CHAR
          + FOLD
          + "by anyone who has access to my postit or to my file."
          + NEW_LINE_CHAR
          + FOLD
          + "So we should avoid these methods to store our passwords! These are the part"
          + NEW_LINE_CHAR
          + FOLD
          + "of our most sensitive data so we have to take care about our passwords to be"
          + NEW_LINE_CHAR
          + FOLD
          + "known only by us to avoid the unauthorized operations on our behalf in the"
          + NEW_LINE_CHAR
          + FOLD
          + "electronic world."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "The problem with the plain text stored passwords is that it can be read"
          + NEW_LINE_CHAR
          + FOLD
          + "sitting in front of the computer or stolen on the network."
          + NEW_LINE_CHAR
          + FOLD
          + "The problem with the postit stored password is that it can be read by"
          + NEW_LINE_CHAR
          + FOLD
          + "everyone who walks around my desk."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "The simplest way is to save this sensitive data into encrypted files while"
          + NEW_LINE_CHAR
          + FOLD
          + "there are several good and known algorithms and their implementations!"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "A solution for this problem above."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "You can defend your real passwords using "
          + APP_NAME
          + " application even one"
          + NEW_LINE_CHAR
          + FOLD
          + "password!"
          + NEW_LINE_CHAR
          + FOLD
          + "You now have to memorize just 1 password to know the other good and hard to"
          + NEW_LINE_CHAR
          + FOLD
          + "guess (and hard to memorize) passwords."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "This application has been developed in java technology and can be used in"
          + NEW_LINE_CHAR
          + FOLD
          + "command line in every operating system that contains (min 1.8) java installed."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "The AES encryption uses a 256 bit encryption key, derived from your password"
          + NEW_LINE_CHAR
          + FOLD
          + "with PBKDF2 (HMAC-SHA512). Modern Java runtimes (1.8u161 and newer) support"
          + NEW_LINE_CHAR
          + FOLD
          + "this key length out of the box, so no extra policy files are needed."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "The most important goals we have achieved:"
          + NEW_LINE_CHAR
          + FOLD
          + "- there are no passwords written to disk in plain text format"
          + NEW_LINE_CHAR
          + FOLD
          + "- there are unencrypted passwords in the system memory only in mutable objects"
          + NEW_LINE_CHAR
          + FOLD
          + "- there are unencrypted passwords in the system memory while they are needed"
          + NEW_LINE_CHAR
          + FOLD
          + "  (it is possible to use "
          + APP_NAME
          + " in an insecure way to speed up the manual"
          + NEW_LINE_CHAR
          + FOLD
          + "  password handling job: it can cache the admin and file passwords to not have"
          + NEW_LINE_CHAR
          + FOLD
          + "  to type these every time, this is for the user's exact command)"
          + NEW_LINE_CHAR
          + FOLD
          + "- the file and password operations are fully logged."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "The types of the passwords in "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "There are 3 kinds of password in this application."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "Admin password:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "This is the password to access the previous modifications and to manage"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "our file container files."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "File password:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "These files or password container files are to store our user passwords"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "named as key passwords."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "These files are defended by password."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Every file can be set by the same file password and these passwords can"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "be the same as the admin password. So it is really possible to handle the"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "application using just one password."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "But, the secure way is to construct the file passwords and the admin"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "passwords as different strings, differing in at least 3 characters and with no"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "file names in these."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "Password:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "These are our passwords or key passwords or user passwords we want to"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "store in a secure and unreadable way. These passwords will go into the"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "file containers for future use. (For example you can log in into your"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "internet banking application because you will know your strong but not"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "recently used password.)"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It is possible to have a generated good password by "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Just type "
          + YES
          + " if it will be questioned."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It is not applicable to your file and admin passwords. These passwords"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "have to be created by you because you have to memorize them!"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "Password storing in "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "Password storing has been implemented in this application by key - value pair."
          + NEW_LINE_CHAR
          + FOLD
          + "We have to name the password (this will be the key) and this name will"
          + NEW_LINE_CHAR
          + FOLD
          + "identify this password for reading or handling in the future."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "An exact example for the password storing."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "ATTENTION!"
          + NEW_LINE_CHAR
          + FOLD
          + "If you forget your file password then the passwords contained by that file can"
          + NEW_LINE_CHAR
          + FOLD
          + "be handled as unreadable. If you forget your admin password then further"
          + NEW_LINE_CHAR
          + FOLD
          + "modification of your password container files cannot be done and you cannot"
          + NEW_LINE_CHAR
          + FOLD
          + "read the history of your "
          + APP_NAME
          + " instance."
          + NEW_LINE_CHAR
          + FOLD
          + "We cannot give you any solution for these cases."
          + NEW_LINE_CHAR
          + FOLD
          + "(This is one of our main goals: nobody can help you in case of forgotten"
          + NEW_LINE_CHAR
          + FOLD
          + "file or admin passwords. The only solution is in the user's head as the"
          + NEW_LINE_CHAR
          + FOLD
          + "correct admin and file passwords. Or delete everything to start over.)"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "1. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_WELCOME
          + SINGLE_SPACE
          + ARG_SCREEN
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Read and do this."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Please copy the "
          + APP_NAME
          + ".jar into a safe place according to this"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "information."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "2. Open a command line and navigate into the new place of "
          + APP_NAME
          + ".jar."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "3. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_QUESTION_MARK
          + NEW_LINE_CHAR
          + FOLD
          + "or more detailed"
          + NEW_LINE_CHAR
          + FOLD
          + "java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_HELP
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We can read our available commands to use the application."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "4. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_ADMIN
          + SINGLE_SPACE
          + ARG_REVIEW
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We can read about the history of using our "
          + APP_NAME
          + " instance."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "At this point we don't have any history event so we have to create our"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "admin password. Please construct your admin password carefully and do not"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "forget it!"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "5. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_FILE
          + SINGLE_SPACE
          + ARG_ADD
          + " myfile1"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password container file called myfile1 will be created and the"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "password of this file will be prompted. You can choose the same password"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "as admin password but it is much safer to choose a different password."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(File name not included!)"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "What will happen exactly:"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- You have to type your admin password constructed before"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- You have to type your new file password"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- You have to choose the type of the stored passwords in this password"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "container file."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Choose \"n\" in this case."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(Full and valid passwords can be stored in this file.)"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "6. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_KEY
          + SINGLE_SPACE
          + ARG_ADD
          + " myfile1"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "This is it."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We will put our internet bank password into our myfile1 file made before."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- The file password will be prompted"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- The admin password too"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- The key (a name) will be questioned, let it be as \"ibank_pwd\""
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "- The password of this key will be prompted"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "We are done."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "7. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_ADMIN
          + SINGLE_SPACE
          + ARG_REVIEW
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It can be seen that we have initialized our application, have created a new"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "password container file and have added a new password into this file."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "By repeating this command, it can also be seen that the admin review has been called."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "An exact example for the password reading."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "1. Open a command line and navigate to the place of "
          + APP_NAME
          + ".jar"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "2. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_FILE
          + SINGLE_SPACE
          + ARG_LIST
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We can list our file names we want to read a password from."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "3. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_KEY
          + SINGLE_SPACE
          + ARG_LIST
          + " myfile1"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We can list our keys (names of our passwords) added before into myfile1."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password of this file will be prompted."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "4. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_PASSWORD
          + SINGLE_SPACE
          + ARG_SHOW
          + " myfile1 ibank_pwd"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "This is it."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The command above shows the password placed into the myfile1 and belonging to"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "the ibank_pwd key. The password of the file will be prompted of course."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "5. java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_PASSWORD
          + SINGLE_SPACE
          + ARG_COPY
          + " myfile1 ibank_pwd"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "In this case, your password goes to system clipboard only (for a limited time)."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + "Less secure but more efficient usage."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + "java -jar "
          + APP_NAME
          + ".jar"
          + SINGLE_SPACE
          + ARG_INTERACTIVE
          + SINGLE_SPACE
          + ARG_MODE
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We can enter into an interactive mode by typing this command."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "We won't have to type java -jar "
          + APP_NAME
          + ".jar"
          + " and only the command is necessary."
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORDS
          + SINGLE_SPACE
          + ARG_CACHE
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "INSECURE (but for faster use)"
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Typing this in interactive mode the passwords of the password container"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "files and the admin password will be cached in the system memory"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(on the area of JVM). This is a less secure way but the application can"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "be used much faster while you won't have to type the file passwords and"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "the admin password every time. This is useful especially in the beginning"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "when your passwords will go into this "
          + APP_NAME
          + " password container"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "application."
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "All of the cached password will be forgotten when you type this command"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "again. The file and admin passwords will be prompted next time, but still"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "will be cached later."
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The cached admin and file passwords have to be read continuously."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "So you have to work continuously in the application because it will"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "forget your cached passwords after a not too long time and you will have"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "to type these passwords again."
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORDS
          + SINGLE_SPACE
          + ARG_PURGE
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "SECURE "
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "This is also available in interactive mode of "
          + APP_NAME
          + " and this is the"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "default behavior after the interactive mode command. After the execution"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "of "
          + ARG_PASSWORDS
          + SINGLE_SPACE
          + ARG_PURGE
          + " command, the cached passwords of files and admin will"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "be forgotten and you have to type these again and every time when"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "prompted. This does NOT affect your passwords stored in your encrypted files!"
          + NEW_LINE_CHAR
          + FOLD
          + "  "
          + NEW_LINE_CHAR
          + FOLD
          + ARG_EXIT
          + NEW_LINE_CHAR
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "You can quit from the interactive mode.";

  static final String MESSAGE_GOOD_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "THE GOOD PASSWORD IS:"
          + NEW_LINE_CHAR
          + FOLD
          + "+------------------------------------------------------+"
          + NEW_LINE_CHAR
          + FOLD
          + "| - ASCII 33-126 characters are acceptable, no spaces! |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_UC_LETTERS
          + " uppercase letters                     "
          + LETTERS_UCAZ
          + " |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_LC_LETTERS
          + " lowercase letters                     "
          + LETTERS_LCAZ
          + " |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_DIGITS
          + " digits                                "
          + LETTERS09
          + " |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. "
          + APP_GOOD_PASSWORD_MIN_COUNT_OF_SPEC_CHARS
          + " special chars, for example "
          + LETTERS_SPEC_CHARS
          + " |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. _"
          + APP_GOOD_PASSWORD_MIN_LENGTH_OF_GOOD_PASSWORDS
          + "_ and max. _"
          + APP_MAX_LENGTH_OF_PASSWORDS_AND_KEYS_AND_FILE_NAMES
          + "_ characters length password |"
          + NEW_LINE_CHAR
          + FOLD
          + "+------------------------------------------------------+";

  static final String MESSAGE_NOTE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "THE NOTE YOU CAN STORE IS:"
          + NEW_LINE_CHAR
          + FOLD
          + "+------------------------------------------------------+"
          + NEW_LINE_CHAR
          + FOLD
          + "| - printable ASCII 32-126, spaces are allowed         |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - a single line only, no line breaks                 |"
          + NEW_LINE_CHAR
          + FOLD
          + "| - min. _"
          + APP_MIN_LENGTH_OF_NOTE
          + "_ and max. _"
          + APP_MAX_LENGTH_OF_NOTE
          + "_ characters length          |"
          + NEW_LINE_CHAR
          + FOLD
          + "+------------------------------------------------------+";

  static final String MESSAGE_HINTS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + ARG_INTERACTIVE
          + SPACE_CHAR
          + ARG_MODE
          + NEW_LINE_CHAR
          + FOLD2
          + ARG_EXIT
          + NEW_LINE_CHAR
          + FOLD2
          + ARG_PASSWORDS
          + SPACE_CHAR
          + ARG_CACHE
          + NEW_LINE_CHAR
          + FOLD2
          + ARG_PASSWORDS
          + SPACE_CHAR
          + ARG_PURGE
          + NEW_LINE_CHAR
          + FOLD
          + ARG_APPLICATION
          + SPACE_CHAR
          + ARG_DESCRIBE
          + NEW_LINE_CHAR
          + FOLD
          + ARG_APPLICATION
          + SPACE_CHAR
          + ARG_STORY
          + NEW_LINE_CHAR
          + FOLD
          + ARG_WELCOME
          + SPACE_CHAR
          + ARG_SCREEN
          + NEW_LINE_CHAR
          + FOLD
          + ARG_GOOD
          + SPACE_CHAR
          + ARG_PASSWORD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_NOTE
          + NEW_LINE_CHAR
          + FOLD
          + ARG_CLEAR
          + SPACE_CHAR
          + ARG_SCREEN
          + SPACE_CHAR
          + MESSAGE_YOUR_NUM_OF_EMPTY_LINES_TO_PRINT_OUT
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_LIST
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_ADD
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DESCRIBE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DELETEALL
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_LIST
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_ADD
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_CURRENT_KEY_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_NEW_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_DELETEALL
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_MOVE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_CURRENT
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_NEW
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_MOVEALL
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_CURRENT
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_NEW
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_SHOW
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_COPY
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_TYPE
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_REVIEW
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_LIST
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_ADD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_DELETEALL
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_LIST
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCHALL
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_RESTORE
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_RESTOREALL
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + ARG_QUESTION_MARK
          + NEW_LINE_CHAR
          + FOLD
          + ARG_HELP;

  static final String MESSAGE_HELP =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Please type these arguments to use "
          + APP_NAME
          + " correctly:"
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_INTERACTIVE
          + SPACE_CHAR
          + ARG_MODE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Starts the "
          + APP_NAME
          + " in interactive mode."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_EXIT
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(in interactive mode) Exits you from the "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORDS
          + SPACE_CHAR
          + ARG_CACHE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(in interactive mode) Caches the file passwords and admin password you will enter from"
          + " this time."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "                      You have to enter a file or admin password only once."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORDS
          + SPACE_CHAR
          + ARG_PURGE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(in interactive mode) Purges the file passwords and admin password you have entered."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "                      You have to enter a file or admin password every time."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_APPLICATION
          + SPACE_CHAR
          + ARG_DESCRIBE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the information of this application for you."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_APPLICATION
          + SPACE_CHAR
          + ARG_STORY
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the basic concept and the basic usage, please read it carefully."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_WELCOME
          + SPACE_CHAR
          + ARG_SCREEN
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the first run screen."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_GOOD
          + SPACE_CHAR
          + ARG_PASSWORD
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the expectations of a storable good password."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_NOTE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the expectations of a storable note."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_CLEAR
          + SPACE_CHAR
          + ARG_SCREEN
          + SPACE_CHAR
          + MESSAGE_YOUR_NUM_OF_EMPTY_LINES_TO_PRINT_OUT
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Clears your screen by printing several new line characters."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_LIST
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Lists all of your password files."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Searches for files having name according to "
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_ADD
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Creates your new password container file."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "You can specify the name of your file in "
          + MESSAGE_YOUR_FILE_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The key (password) for this password container will be questioned."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "You have to specify the way you will store the passwords."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "(notes or whole passwords)"
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DESCRIBE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the properties of your password container file."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Changes the password of a password container file."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes the file you name in the "
          + MESSAGE_YOUR_FILE_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DELETEALL
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes all the password container files."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_LIST
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Lists the keys in a given password container file in ascending order."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password of the file will be questioned."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Searches for keys in a file according to "
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password of the file also will be questioned."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_ADD
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Adds an ASCII key - password into your password container file."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password of the file will be questioned first"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "then the key and the password belonging to your key."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_CURRENT_KEY_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_NEW_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Changes a key name in one of your password container files."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The password belonging to that key will be untouched."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes a key from your given password container file."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_DELETEALL
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes all of your keys from your given password container file."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_MOVE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_CURRENT
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_NEW
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Moves a key from a password container file into another."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_KEY
          + SPACE_CHAR
          + ARG_MOVEALL
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_CURRENT
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME_NEW
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Moves all of your keys from a password container file into another."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_SHOW
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Shows the password belonging to your key from the file you have requested."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "One password will be shown at a time so you can't list all of them."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_COPY
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Copies the password belonging to your key to the system clipboard."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It is cleared from the clipboard after "
          + APP_CLIPBOARD_CLEAR_SECONDS
          + " seconds, so paste it within that time."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + SPACE_CHAR
          + MESSAGE_YOUR_KEY_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Changes a password in one of your password container files."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It is a password modification belongs to a key and not to password files."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_TYPE
          + SPACE_CHAR
          + ARG_CHANGE
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Changes the type of storable passwords in "
          + MESSAGE_YOUR_FILE_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_REVIEW
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Views the history of files, keys and passwords."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Searches for your expression in the history above."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_ADMIN
          + SPACE_CHAR
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_CHANGE
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Changes your admin password."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_LIST
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Lists your backups of the password container files."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_ADD
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Adds a backup of the current state of your password container files."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_DELETE
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes a backup given as "
          + MESSAGE_YOUR_BACKUP
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_DELETEALL
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Deletes all of your backups of stored passwords."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_LIST
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Lists the files contained by a backup."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCH
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Searches for file names containing the expression."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_FILE
          + SPACE_CHAR
          + ARG_SEARCHALL
          + SPACE_CHAR
          + MESSAGE_YOUR_EXPRESSION_TO_SEARCH
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Searches for file names containing the expression in all of your backups."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_RESTORE
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + SPACE_CHAR
          + MESSAGE_YOUR_FILE_NAME
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Restores just a file from a backup specified as "
          + MESSAGE_YOUR_BACKUP
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Your current password files won't be deleted. The specified file will be restored."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It will be copied into the current workspace or will be overwritten in the current"
          + " workspace."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_BACKUP
          + SPACE_CHAR
          + ARG_RESTOREALL
          + SPACE_CHAR
          + MESSAGE_YOUR_BACKUP
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Restores a backup specified as "
          + MESSAGE_YOUR_BACKUP
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "All of your current password files will be backed up and deleted before "
          + ARG_RESTOREALL
          + "!"
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_QUESTION_MARK
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints the available commands only."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + ARG_HELP
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Prints this page.";

  static final String MESSAGE_ALLOW_FULL_PASSWORDS_ONLY =
      "full passwords only (" + ALLOW_NOTES_NO + ").";
  static final String MESSAGE_ALLOW_NOTES_AND_FULL_PASSWORDS =
      "full passwords or notes (" + ALLOW_NOTES_YES + ").";
  static final String MESSAGE_TYPE_YES_ELSE_ANYTHING = "[type " + YES + " else anything]: ";
  static final String MESSAGE_EXITING =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The "
          + APP_NAME
          + " is exiting with error:"
          + NEW_LINE_CHAR
          + FOLD;
  static final String MESSAGE_YOUR_PASSWORD_IS =
      ""
          + NEW_LINE_CHAR
          + "Your requested password is (showing "
          + APP_PASSWORD_SHOW_SECONDS
          + " seconds, do not press CTRL+C):";
  static final String MESSAGE_YOUR_NOTE_IS =
      ""
          + NEW_LINE_CHAR
          + "Your requested note is:";
  static final String MESSAGE_PASSWORD_HAS_BEEN_COPIED =
      "" + NEW_LINE_CHAR + "The password has been copied to the clipboard.";
  static final String MESSAGE_PASTE_IT_NOW =
      "Paste it now! It will be cleared from the clipboard in "
          + APP_CLIPBOARD_CLEAR_SECONDS
          + " seconds (do not press CTRL+C):";
  static final String MESSAGE_CLIPBOARD_HAS_BEEN_CLEARED = "The clipboard has been cleared.";
  static final String MESSAGE_CLIPBOARD_NOT_AVAILABLE =
      "The system clipboard is not available on this system.";
  static final String MESSAGE_BASE_COMMAND = "\"java -jar " + SPACE_CHAR + APP_NAME + ".jar\"";
  static final String MESSAGE_HELP_COMMAND =
      "\"java -jar " + APP_NAME + ".jar " + ARG_HELP + "\"";
  static final String MESSAGE_WELCOME_SCREEN_COMMAND =
      "\"java -jar " + SPACE_CHAR + APP_NAME + ".jar" + SPACE_CHAR + ARG_WELCOME + SPACE_CHAR + ARG_SCREEN + "\"";
  static final String MESSAGE_GOOD_PASSWORD_COMMAND =
      "\"java -jar " + SPACE_CHAR + APP_NAME + ".jar" + SPACE_CHAR + ARG_GOOD + SPACE_CHAR + ARG_PASSWORD + "\"";
  static final String MESSAGE_NOTE_COMMAND =
      "\"java -jar " + SPACE_CHAR + APP_NAME + ".jar" + SPACE_CHAR + ARG_PASSWORD + SPACE_CHAR + ARG_NOTE + "\"";
  static final String MESSAGE_WELCOME_SCREEN =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Welcome to "
          + APP_NAME
          + "! "
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "This little opensource java project wants to help you"
          + NEW_LINE_CHAR
          + FOLD
          + "storing your passwords or other sensitive key-value data in a secure way! "
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Please use this application on not compromised and not suspicious computers"
          + NEW_LINE_CHAR
          + FOLD
          + "where the operating system"
          + NEW_LINE_CHAR
          + FOLD
          + " - is from trusted and legal source"
          + NEW_LINE_CHAR
          + FOLD
          + " - is up-to-date"
          + NEW_LINE_CHAR
          + FOLD
          + " - never contained viruses and any malicious code"
          + NEW_LINE_CHAR
          + FOLD
          + " - has an active antivirus software and its up-to-date virus definition database"
          + NEW_LINE_CHAR
          + FOLD
          + " - has a properly set up and active firewall software"
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Please follow these instructions! "
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "0. Check your java, min 1.8 is needed! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "\"java -version\" command prints it for you. Also check for the java is the latest on"
          + " the computer."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Make sure the \"java\" command in your classpath points to the correct java"
          + " executable! "
          + NEW_LINE_CHAR
          + FOLD
          + "1. Create a folder! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "The best solution is to create a folder on your removable device! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Make sure your removable device is in your computer in the shortest time possible."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Do not plug it if you won't use "
          + APP_NAME
          + "! "
          + NEW_LINE_CHAR
          + FOLD
          + "2. Make sure to make this folder your personal folder! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "For example on linux: chmod 700, chown your_username:your_group."
          + NEW_LINE_CHAR
          + FOLD
          + "3. Move "
          + APP_NAME
          + ".jar into that folder! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "This folder will be the base of your application instance."
          + NEW_LINE_CHAR
          + FOLD
          + "4. Open a command line and navigate into that folder! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "It is necessary while it is a command line application."
          + NEW_LINE_CHAR
          + FOLD
          + "5. Type "
          + MESSAGE_BASE_COMMAND
          + " to initialize your "
          + APP_NAME
          + " instance! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "That is the time when you will set your admin password."
          + NEW_LINE_CHAR
          + FOLD
          + "6. Type "
          + MESSAGE_HELP_COMMAND
          + " to read about the usage! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "You are now ready to use "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + ".. Periodically make a copy of the whole folder you have created during step 1. into a"
          + " separate removable device! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Having the same attributes as described in step 2."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "If something went wrong you will still have your passwords.";
  static final String MESSAGE_ADMIN_FILE_HAS_BEEN_CREATED =
      "" + NEW_LINE_CHAR + FOLD + "Your admin file has been created successfully.";
  static final String MESSAGE_DESCRIBE_FILE_SIZE = "" + FOLD + "File size (KB) : ";
  static final String MESSAGE_DESCRIBE_FILE_NUM_OF_KEYS = "" + FOLD + "Number of keys : ";
  static final String MESSAGE_DESCRIBE_FILE_PASSWORD_TYPE = "" + FOLD + "Password store : ";
  static final String MESSAGE_KEY_HAS_NOT_VALID_GOOD_PASSWORD =
      "" + FOLD + "The key has no valid good password: ";
  static final String MESSAGE_DO_NOT_FORGET_YOUR_FILE_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "IMPORTANT notice! "
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Please do not forget your password of the file below! "
          + NEW_LINE_CHAR
          + FOLD
          + "If you forget the password of this password container file,"
          + NEW_LINE_CHAR
          + FOLD
          + "  you will not be able to read your passwords stored in it! "
          + NEW_LINE_CHAR
          + FOLD
          + "Keep it in your mind and choose a password you will not forget! ";
  static final String MESSAGE_ALLOW_NOTES =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Do you want to store notes in this password container file?"
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Please type"
          + NEW_LINE_CHAR
          + FOLD
          + "\""
          + ALLOW_NOTES_YES
          + "\": You can store free-form notes - any text, spaces allowed! "
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "For example a note can be a short reminder or a longer message"
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "with spaces, up to " + APP_MAX_LENGTH_OF_NOTE + " characters long."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "These notes are stored exactly as you type them."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "In this case your password will NOT be validated by the standards."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Please type "
          + MESSAGE_NOTE_COMMAND
          + " for more information."
          + NEW_LINE_CHAR
          + FOLD
          + "..or"
          + NEW_LINE_CHAR
          + FOLD
          + "\""
          + ALLOW_NOTES_NO
          + "\": You will be able to store in this file valid passwords only."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "In this case your password will be validated by the standards."
          + NEW_LINE_CHAR
          + FOLD
          + FOLD2
          + "Please type "
          + MESSAGE_GOOD_PASSWORD_COMMAND
          + " for more information."
          + NEW_LINE_CHAR
          + FOLD
          + ": ";
  static final String MESSAGE_THE_PASSWORD_IS_NOT_VALID = "The password is not valid.";
  static final String MESSAGE_GOOD_PASSWORD_IS_NOT_VALID =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_THE_PASSWORD_IS_NOT_VALID
          + NEW_LINE_CHAR
          + MESSAGE_GOOD_PASSWORD;
  static final String MESSAGE_NOTE_IS_NOT_VALID =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_THE_PASSWORD_IS_NOT_VALID
          + NEW_LINE_CHAR
          + MESSAGE_NOTE;
  static final String MESSAGE_NOTE_CONVERTED_TO_ASCII =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Your note contained non-ASCII characters and has been converted to ASCII.";
  static final String MESSAGE_NOTE_TRUNCATED =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Your note was too long and has been truncated to "
          + APP_MAX_LENGTH_OF_NOTE
          + " characters.";
  static final String MESSAGE_ENTER_PASSWORD_VERIFY = "" + FOLD + "Please verify it: ";
  static final String MESSAGE_PASSWORD_VERIFICATION_ERROR =
      "" + NEW_LINE_CHAR + FOLD + "Sorry but the password and its verification are not the same.";
  static final String MESSAGE_DO_NOT_FORGET_YOUR_ADMIN_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The password of the administration tasks will be questioned."
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "Please do not forget your admin password"
          + NEW_LINE_CHAR
          + FOLD
          + "otherwise you won't be able to admin your "
          + APP_NAME
          + " instance! "
          + NEW_LINE_CHAR
          + FOLD
          + NEW_LINE_CHAR
          + FOLD
          + "This admin password is prompted if you execute a modifier task."
          + NEW_LINE_CHAR
          + FOLD
          + "Every modification will be logged. (The read-only queries not.)"
          + NEW_LINE_CHAR
          + FOLD
          + "These log entries will be stored up to "
          + APP_FILE_CONTENT_MAX_LENGTH
          + " bytes long."
          + NEW_LINE_CHAR
          + FOLD
          + "If this size exceeds this limit, the oldest log entries will be dropped.";
  static final String MESSAGE_ERROR_DELETING_OLD_FILES_OR_RENAME_NEW_FILES =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Error has occurred while deleting old files or renaming them back to new files! "
          + NEW_LINE_CHAR
          + FOLD
          + "Please fix it manually:"
          + NEW_LINE_CHAR
          + FOLD
          + "The files have to be deleted ("
          + APP_PD_POSTFIX
          + SEP1
          + APP_SL_POSTFIX
          + " and "
          + APP_IV_POSTFIX
          + ")"
          + NEW_LINE_CHAR
          + FOLD
          + "and the "
          + APP_NW_POSTFIX
          + " files have to be renamed back without "
          + APP_NW_POSTFIX
          + " extension! "
          + NEW_LINE_CHAR
          + FOLD
          + "The filename is: ";
  static final String MESSAGE_SCREEN_HAS_BEEN_CLEARED1 =
      NEW_LINE_CHAR + FOLD + "Your screen has been cleared as ";
  static final String MESSAGE_SCREEN_HAS_BEEN_CLEARED2 = " empty lines have been printed out.";
  static final String MESSAGE_NO_ARGUMENTS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "You haven't specified any arguments."
          + NEW_LINE_CHAR
          + FOLD
          + "hint: type "
          + MESSAGE_HELP_COMMAND;
  static final String MESSAGE_FILE_HAS_BEEN_DELETED_SL =
      "" + FOLD + "Sl file has also been deleted.";
  static final String MESSAGE_FILE_HAS_BEEN_DELETED_IV =
      "" + FOLD + "Iv file has also been deleted.";
  static final String MESSAGE_FILE_HAS_NOT_BEEN_DELETED_SL =
      "" + FOLD + "Sl file may be still there, please remove it manually! ";
  static final String MESSAGE_FILE_HAS_NOT_BEEN_DELETED_IV =
      "" + FOLD + "Iv file may be still there, please remove it manually! ";
  static final String MESSAGE_ERROR_DELETING_NEW_PW_FILE =
      "" + FOLD + "Error while deleting newly created " + APP_PD_POSTFIX + " file! ";
  static final String MESSAGE_ERROR_DELETING_NEW_SL_FILE =
      "" + FOLD + "Error while deleting newly created " + APP_SL_POSTFIX + " file! ";
  static final String MESSAGE_ERROR_DELETING_NEW_IV_FILE =
      "" + FOLD + "Error while deleting newly created " + APP_IV_POSTFIX + " file! ";
  static final String MESSAGE_MISSING_PW_OR_SL_OR_IV_FILE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Sorry but you have no original "
          + APP_PD_POSTFIX
          + " file or "
          + APP_SL_POSTFIX
          + " file or "
          + APP_IV_POSTFIX
          + " file for ";
  static final String MESSAGE_MISSING_AN_OR_SL_OR_IV_FILE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Sorry but you have no original "
          + APP_AN_POSTFIX
          + " file or "
          + APP_SL_POSTFIX
          + " file or "
          + APP_IV_POSTFIX
          + " file for ";
  static final String MESSAGE_MISSING_NEW_PW_OR_SL_OR_IV_FILE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Sorry but one or more new file is missing after the saving operation"
          + NEW_LINE_CHAR
          + FOLD
          + "( "
          + APP_PD_POSTFIX
          + " file or "
          + APP_SL_POSTFIX
          + " file or "
          + APP_IV_POSTFIX
          + " ), your changes will be rolled back! ";
  static final String MESSAGE_MISSING_NEW_AN_OR_SL_OR_IV_FILE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Sorry but one or more new file is missing after the saving operation"
          + NEW_LINE_CHAR
          + FOLD
          + "( "
          + APP_AN_POSTFIX
          + " file or "
          + APP_SL_POSTFIX
          + " file or "
          + APP_IV_POSTFIX
          + " ), your changes will be rolled back! ";
  static final String MESSAGE_SURE_CHANGE_TYPE_OF_PASSWORS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to change the type of passwords in this file?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE_DELETE_ALL_FILES =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to delete all of your password container files?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE_DELETE_KEYS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to delete ALL of your keys in the file?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE_MOVE_KEYS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to move ALL of your keys in the file?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE_CHANGE_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to change this password?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE2 = "\"?" + NEW_LINE_CHAR + FOLD + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_SURE_CHANGE_ADMIN_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to change the admin password?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_CONTENT_IS_NOT_DECRYPTED =
      NEW_LINE_CHAR + FOLD + "The content is not decrypted for password type: ";
  static final String MESSAGE_IS_FOLDER_SAFE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Is the folder of this "
          + APP_NAME
          + " safe enough?"
          + NEW_LINE_CHAR
          + FOLD
          + "(like described in "
          + MESSAGE_WELCOME_SCREEN_COMMAND
          + ")"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_WOULD_YOU_LIKE_TO_HAVE_A_GENERATED_GOOD_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Would you like to have a generated good password?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_WOULD_YOU_LIKE_TO_READ_YOUR_GENERATED_GOOD_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Would you like to read your generated good password now?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_WELCOME_TO_INTERACTIVE_MODE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Welcome to interactive mode of "
          + APP_NAME
          + "."
          + NEW_LINE_CHAR
          + FOLD
          + "Type \""
          + ARG_EXIT
          + "\" to leave, \""
          + ARG_QUESTION_MARK
          + "\" or \""
          + ARG_HELP
          + "\" for more!"
          + NEW_LINE_CHAR
          + FOLD
          + "Type \""
          + ARG_PASSWORDS
          + " "
          + ARG_CACHE
          + "\" to work easier with your pw files! "
          + NEW_LINE_CHAR;
  static final String MESSAGE_PASSWORDS_CACHE_ENABLED =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "OK, your file and admin passwords will be cached if you work continuously.";
  static final String MESSAGE_PASSWORDS_CACHE_DISABLED =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "OK, your file and admin passwords will NOT be cached."
          + NEW_LINE_CHAR
          + FOLD
          + "Yeah, your passwords have disappeared from system memory! ";
  static final String MESSAGE_FILES_COUNT_MORE = " password files have been found.";
  static final String MESSAGE_KEYS_COUNT_FOUND = " keys have been found in your file.";
  static final String MESSAGE_HIT_HAS_BEEN_FOUND = " hit has been found for ";
  static final String MESSAGE_HITS_HAVE_BEEN_FOUND = " hits have been found for ";
  static final String MESSAGE_NO_HITS_HAVE_BEEN_FOUND = "No hits have been found for ";
  static final String MESSAGE_AVAILABLE_FILES_COUNT = "" + FOLD + "You can create more files: ";
  static final String MESSAGE_AVAILABLE_KEYS_COUNT =
      "" + FOLD + "You can create more keys in file: ";
  static final String MESSAGE_KEY_HAS_BEEN_MOVED =
      "" + FOLD + "The key has been moved successfully: ";
  static final String MESSAGE_KEY_HAS_BEEN_MOVED_WITH_FILE_SAVING =
      "" + FOLD + "The key has been moved successfully (with file saving): ";
  static final String MESSAGE_KEY_HAS_BEEN_ADDED =
      "" + NEW_LINE_CHAR + FOLD + "Your new key has been added successfully.";
  static final String MESSAGE_FILE_HAS_BEEN_CREATED =
      "" + FOLD + "Your file has been created successfully.";
  static final String MESSAGE_TOO_MANY_KEYS_IN_FILE_NEW =
      ""
          + FOLD
          + "You cannot have more than "
          + APP_MAX_NUM_OF_KEYS_PER_FILE
          + " keys in the file you wanted to move into.";
  static final String MESSAGE_KEY_FOUND_IN_NEW =
      "" + FOLD + "Your key is found in the second file (move into): ";
  static final String MESSAGE_KEY_IS_NOT_FOUND_IN_CURRENT =
      "" + FOLD + "Your key is not found in the first file (move from): ";
  static final String MESSAGE_THE_PASSWORD_TYPE_HAS_ALREADY_SET_TO_THIS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The password type of this file has already been set to this value.";
  static final String MESSAGE_CHANGE_PASSWORD_AT_LEAST3_DIGITS =
      "" + NEW_LINE_CHAR + FOLD + "Change your password by at least 3 characters! ";
  static final String MESSAGE_FILES_HAVE_TO_BE_DIFFERENT =
      "" + NEW_LINE_CHAR + FOLD + "The names of the two files have to be different.";
  static final String MESSAGE_NEW_KEY_NAME_HAVE_TO_BE_DIFFERENT =
      "" + NEW_LINE_CHAR + FOLD + "The old and the new key name have to be different.";
  static final String MESSAGE_KEYS_HAS_BEEN_HANDLED =
      "" + NEW_LINE_CHAR + FOLD + "All of the keys have been handled.";
  static final String MESSAGE_DESCRIBE_FILE_LAST_MODIFIED =
      "" + NEW_LINE_CHAR + FOLD + "Last modified  : ";
  static final String MESSAGE_TYPE_OF_STORABLE_PASSWORDS_HAS_BEEN_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "The type of storable passwords has been changed.";
  static final String MESSAGE_FILES_COUNT_ONE =
      "" + NEW_LINE_CHAR + FOLD + "1 password file has been found.";
  static final String MESSAGE_FILES_COUNT_EMPTY =
      "" + NEW_LINE_CHAR + FOLD + "No password files have been found.";
  static final String MESSAGE_FILE_DOES_NOT_EXIST =
      "" + NEW_LINE_CHAR + FOLD + "The file does not exist: ";
  static final String MESSAGE_FILE_IS_NOT_FILE =
      "" + NEW_LINE_CHAR + FOLD + "The file is not a file: ";
  static final String MESSAGE_FILE_HAS_BEEN_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "Your file has been deleted successfully.";
  static final String MESSAGE_FILE_HAS_NOT_BEEN_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "Your file has not been deleted!";
  static final String MESSAGE_FILE_WONT_BE_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "Your password file is still there.";
  static final String MESSAGE_PASSWORD_FROM_FILE =
      "" + NEW_LINE_CHAR + FOLD + "The file password you want to move from - ";
  static final String MESSAGE_PASSWORD_INTO_FILE =
      "" + NEW_LINE_CHAR + FOLD + "The file password you want to move into - ";
  static final String MESSAGE_FILE_PASSWORD_WONT_BE_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "The password of your password container file is the same.";
  static final String MESSAGE_FILE_PASSWORD_HAS_BEEN_CHANGED =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The password of your password container file has been changed successfully.";
  static final String MESSAGE_PASSWORD_WONT_BE_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "OK, your password has not been changed.";
  static final String MESSAGE_PASSWORD_HAS_BEEN_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "Your password has been changed successfully.";
  static final String MESSAGE_KEY_HAS_BEEN_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "Your key has been changed to new name.";
  static final String MESSAGE_WRONG_PARAMETERS =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "You have used wrong parameters! "
          + NEW_LINE_CHAR
          + FOLD
          + "(and ASCII 32-126 characters are acceptable.)";
  static final String MESSAGE_SURE_DELETE_FILE =
      "" + NEW_LINE_CHAR + FOLD + "Are you sure you want to delete password file \"";
  static final String MESSAGE_SURE_CHANGE_FILE_PASSWORD =
      "" + NEW_LINE_CHAR + FOLD + "Are you sure you want to change the password of file \"";
  static final String MESSAGE_NEW_KEY_ALREADY_EXISTS =
      "" + NEW_LINE_CHAR + FOLD + "The new key you have specified already exists in the file.";
  static final String MESSAGE_KEY_IS_NOT_FOUND =
      "" + NEW_LINE_CHAR + FOLD + "Your key is not found in this file.";
  static final String MESSAGE_SURE_DELETE_KEY =
      "" + NEW_LINE_CHAR + FOLD + "Are you sure you want to delete the key \"";
  static final String MESSAGE_SURE_MOVE_KEY =
      "" + NEW_LINE_CHAR + FOLD + "Are you sure you want to move the key \"";
  static final String MESSAGE_SURE_CHANGE_KEY =
      "" + NEW_LINE_CHAR + FOLD + "Are you sure you want to change the key \"";
  static final String MESSAGE_KEYS_ARE_STILL_THERE =
      "" + NEW_LINE_CHAR + FOLD + "Don't panic, your keys are still there.";
  static final String MESSAGE_KEYS_HAS_BEEN_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "All of your keys have been deleted (if there were any).";
  static final String MESSAGE_SCREEN_HAS_BEEN_CLEARED_BUT =
      "" + NEW_LINE_CHAR + FOLD + "This screen has been cleared, but..";
  static final String MESSAGE_CLOSE_THIS_WINDOW =
      "" + NEW_LINE_CHAR + FOLD + "Do not forget to close this window! ";
  static final String MESSAGE_NOBODY_IS_AROUND =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "MAKE SURE nobody is looking at your screen!"
          + NEW_LINE_CHAR
          + FOLD
          + "Is your screen safe?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_ALL_FILES_ARE_STILL_THERE =
      "" + NEW_LINE_CHAR + FOLD + "All of your password files are still there.";
  static final String MESSAGE_TOO_MANY_FILES =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "You cannot have more than "
          + APP_MAX_NUM_OF_FILES
          + " password files! ";
  static final String MESSAGE_TOO_MANY_KEYS_IN_FILE =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "You cannot have more than "
          + APP_MAX_NUM_OF_KEYS_PER_FILE
          + " keys per file.";
  static final String MESSAGE_FILE_CONTENT_HAS_NOT_BEEN_FOUND =
      "" + NEW_LINE_CHAR + FOLD + "The content of the file has not been found: ";
  static final String MESSAGE_NAME_IS_NOT_VALID =
      "" + NEW_LINE_CHAR + FOLD + "The name is not valid.";
  static final String MESSAGE_TYPE_OF_PASSWORDS_WONT_BE_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "The type of storable passwords won't be changed in this file.";
  static final String MESSAGE_FROM_FILE_EMPTY =
      "" + NEW_LINE_CHAR + FOLD + "The file you wanted to move your keys from is empty! ";
  static final String MESSAGE_FILE_ALREADY_EXISTS =
      "" + NEW_LINE_CHAR + FOLD + "This file name is already in use! ";
  static final String MESSAGE_FILE_HAS_BEEN_SAVED =
      "" + NEW_LINE_CHAR + FOLD + "File has been saved: ";
  static final String MESSAGE_ENTER_PASSWORD_FOR_KEY =
      "" + NEW_LINE_CHAR + FOLD + "Enter your key password: ";
  static final String MESSAGE_ENTER_NOTE =
      "" + NEW_LINE_CHAR + FOLD + "Enter your note: ";
  static final String MESSAGE_ENTER_PASSWORD_FOR_FILE =
      "" + NEW_LINE_CHAR + FOLD + "Enter your file password: ";
  static final String MESSAGE_ENTER_PASSWORD_FOR_ADMIN =
      "" + NEW_LINE_CHAR + FOLD + "Enter your admin password: ";
  static final String MESSAGE_ENTER_KEY = "" + NEW_LINE_CHAR + FOLD + "Enter your key: ";
  static final String MESSAGE_INCORRECT_FILE_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The password of this file container you have entered is incorrect: ";
  static final String MESSAGE_USING_CACHED_FILE_PASSWORD =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "Opened with a cached file password: ";
  static final String MESSAGE_KEY_HAS_BEEN_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "Your key has been deleted successfully.";
  static final String MESSAGE_KEY_IS_STILL_THERE =
      "" + NEW_LINE_CHAR + FOLD + "Your key is still there.";
  static final String MESSAGE_KEY_WONT_BE_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "Your key name is still the same.";
  static final String MESSAGE_ADMIN_PASSWORD_HAS_BEEN_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "The admin password has been changed successfully.";
  static final String MESSAGE_ADMIN_PASSWORD_WONT_BE_CHANGED =
      "" + NEW_LINE_CHAR + FOLD + "The admin password is the same.";
  static final String MESSAGE_ALL_FILES_HAVE_BEEN_DELETED =
      "" + NEW_LINE_CHAR + FOLD + "All of the password container files have been deleted.";
  static final String MESSAGE_KEY_COUNT_HAS_BEEN_FOUND =
      "" + NEW_LINE_CHAR + FOLD + "1 key has been found in your file.";
  static final String MESSAGE_NO_KEYS_HAVE_BEEN_FOUND =
      "" + NEW_LINE_CHAR + FOLD + "No keys have been found in your file.";
  static final String MESSAGE_INCOMPATIBLE_FILES =
      ""
          + NEW_LINE_CHAR
          + FOLD
          + "The type of the stored passwords does not match in the two files you have specified."
          + NEW_LINE_CHAR
          + FOLD
          + "Please look at it by "
          + ARG_FILE
          + SPACE_CHAR
          + ARG_DESCRIBE
          + " and "
          + ARG_PASSWORD
          + SPACE_CHAR
          + ARG_TYPE
          + SPACE_CHAR
          + ARG_CHANGE
          + " commands! ";
  static final String MESSAGE_FILE_DOES_NOT_CONTAIN_ANY_KEY =
      "" + NEW_LINE_CHAR + FOLD + "It seems your file does not contain any keys.";
  static final String MESSAGE_SURE_MAKE_BACKUP =
      NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to make a backup of your current state of password files?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_BACKUP_WONT_BE_MADE =
      NEW_LINE_CHAR + FOLD + "Ok, backup will be not made.";
  static final String MESSAGE_YOUR_BACKUP_IS = NEW_LINE_CHAR + FOLD + "Your backup is in folder: ";
  static final String MESSAGE_ENTER_BACKUP_DESCRIPTION =
      NEW_LINE_CHAR
          + FOLD
          + "Type your description of the backup!"
          + NEW_LINE_CHAR
          + FOLD
          + "Use ASCII 32-126 characters and max length "
          + APP_MAX_LENGTH_OF_BACKUP_DESCRIPTION
          + ": ";
  static final String MESSAGE_BACKUP_HAS_BEEN_FINISHED_SUCCESSFULLY =
      NEW_LINE_CHAR + FOLD + "Your backup has been finished successfully.";
  static final String MESSAGE_NO_BACKUPS_HAVE_BEEN_FOUND =
      NEW_LINE_CHAR + FOLD + "No backups have been found.";
  static final String MESSAGE_ONE_BACKUP_HAS_BEEN_FOUND =
      NEW_LINE_CHAR + FOLD + "One backup has been found.";
  static final String MESSAGE_BACKUPS_HAVE_BEEN_FOUND = " backups have been found.";
  static final String MESSAGE_THE_BACKUP_CREATION_HAS_NOT_BEEN_FINISHED_SUCCESSFULLY =
      NEW_LINE_CHAR
          + FOLD
          + " The backup creation has not been finished successfully!"
          + NEW_LINE_CHAR
          + FOLD
          + "Please check the filesystem and repeat this operation.";
  static final String MESSAGE_TOO_MANY_BACKUPS_ARE_THERE =
      NEW_LINE_CHAR
          + FOLD
          + "Too many backups are there."
          + NEW_LINE_CHAR
          + FOLD
          + "Please remove the not needed ones."
          + NEW_LINE_CHAR
          + FOLD
          + "The allowed number of backups is maximum: ";
  static final String MESSAGE_THE_COUNT_OF_AVAILABLE_BACKUPS_IS =
      FOLD + "The count of available backups is: ";
  static final String MESSAGE_BACKUP_HAS_BEEN_DELETED_SUCCESSFULLY =
      NEW_LINE_CHAR + FOLD + "Your backup has been deleted successfully.";
  static final String MESSAGE_BACKUP_HAS_NOT_BEEN_DELETED_SUCCESSFULLY =
      NEW_LINE_CHAR + FOLD + "Your backup has not been deleted successfully: ";
  static final String MESSAGE_ERROR_WHILE_DELETING_FILE =
      NEW_LINE_CHAR + FOLD + "Error while deleting file: ";
  static final String MESSAGE_ERROR_WHILE_DELETING_FOLDER =
      NEW_LINE_CHAR + FOLD + "Error while deleting folder: ";
  static final String MESSAGE_SURE_DELETE_BACKUP1 =
      NEW_LINE_CHAR + FOLD + "Are you sure you want to delete your backup \"";
  static final String MESSAGE_SURE_DELETE_BACKUP2 =
      "\"?" + NEW_LINE_CHAR + FOLD + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_BACKUP_WONT_BE_DELETED =
      NEW_LINE_CHAR + FOLD + "OK, the backup won't be deleted.";
  static final String MESSAGE_YOUR_BACKED_UP_FILE_HAS_NOT_BEEN_FOUND =
      NEW_LINE_CHAR + FOLD + "Your backed up file has not been found!";
  static final String MESSAGE_ALL_BACKUPS_HAVE_BEEN_HANDELED =
      NEW_LINE_CHAR + FOLD + "All of the backups have been handled.";
  static final String MESSAGE_SURE_DELETE_BACKUPS =
      NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to delete all of your backups?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_BACKUPS_WONT_BE_DELETED =
      NEW_LINE_CHAR + FOLD + "Ok, your backups will be untouched.";
  static final String MESSAGE_SURE_BRING_BACKED_UP_FILE_AND_OVERWRITE_CURRENT_FILE =
      NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to bring the backed up file and overwrite your current file?"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_FILE_WONT_BE_OVERWRITTEN_BY_BACKED_UP_FILE =
      NEW_LINE_CHAR + FOLD + "Your file won't be overwritten by backed up file.";
  static final String MESSAGE_YOUR_FILE_HAS_BEEN_RESTORED_SUCCESSFULLY =
      NEW_LINE_CHAR + FOLD + "Your file has been restored successfully.";
  static final String MESSAGE_UNABLE_TO_CREATE_NW_FILES =
      NEW_LINE_CHAR + FOLD + "Unable to create " + APP_NW_POSTFIX + " files: ";
  static final String MESSAGE_SURE_RESTORE_FILE1 =
      NEW_LINE_CHAR + FOLD + "Are you sure you want to restore file \"";
  static final String MESSAGE_SURE_RESTORE_FILE2 = "\" from backup \"";
  static final String MESSAGE_SURE_RESTORE_FILE3 =
      "\"?" + NEW_LINE_CHAR + FOLD + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_FILE_WONT_BE_RESTORED =
      NEW_LINE_CHAR + FOLD + "Ok, your file won't be restored.";
  static final String MESSAGE_FOLDER_IS_FILE = NEW_LINE_CHAR + FOLD + "The folder is a file: ";
  static final String MESSAGE_FOLDER_DOES_NOT_EXIST =
      NEW_LINE_CHAR + FOLD + "The folder doesn't exist: ";
  static final String MESSAGE_SURE_RESTORE_FILES =
      NEW_LINE_CHAR
          + FOLD
          + "Are you sure you want to restore all of your files from backup?"
          + NEW_LINE_CHAR
          + FOLD
          + "(note: your current files will be backed up automatically if you type \"yes\")"
          + NEW_LINE_CHAR
          + FOLD
          + MESSAGE_TYPE_YES_ELSE_ANYTHING;
  static final String MESSAGE_FILES_WONT_BE_RESTORED =
      NEW_LINE_CHAR + FOLD + "Ok, your files won't be restored from backup.";
  static final String MESSAGE_ALL_BACKED_UP_FILES_HAVE_BEEN_HANDELED =
      NEW_LINE_CHAR + FOLD + "All of your backed up files have been handled.";
  static final String MESSAGE_AUTOMATED_BACKUP_BEFORE_RESTORING =
      "Automated backup before restoring.";
  static final String MESSAGE_UNABLE_TO_DELETE_FILE =
      NEW_LINE_CHAR + FOLD + "Unable to delete file: ";
  static final String MESSAGE_OK = "" + NEW_LINE_CHAR + FOLD + "Ok.";
  static final String MESSAGE_BYE = "" + NEW_LINE_CHAR + FOLD + "Bye!";
}
