/*
** MyPwStock application.
**
** Description:    : This tiny application stores passwords
**                   or any key - value sensitive data in encrypted format.
**                   Handles 42 commands and this is not an accident.
**                   Nor that it is contained only by one single class.
**
** Published       : 02.01.2017
**
** Current version : 1.2
**
** Developed by    : Jozsef Kiss
**                   KissCode Systems Kft
**                   <http://www.prdare.com>
**
** Changelog       : 1.0 - 02.01.2017
**                   Initial release.
**                   1.1 - 04.05.2017
**                   The password show displays random spaces. (not to copy..)
**                   Smaller improvements.
**                   1.2 - 08.19.2017
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
package com . kisscodesystems . MyPwStock ;
import java . io . BufferedReader ;
import java . io . Console ;
import java . io . File ;
import java . io . FileInputStream ;
import java . io . FileNotFoundException ;
import java . io . FileOutputStream ;
import java . io . IOException ;
import java . io . InputStreamReader ;
import java . io . ObjectInputStream ;
import java . io . ObjectOutputStream ;
import java . security . AlgorithmParameters ;
import java . security . InvalidAlgorithmParameterException ;
import java . security . InvalidKeyException ;
import java . security . NoSuchAlgorithmException ;
import java . security . SecureRandom ;
import java . security . spec . InvalidKeySpecException ;
import java . security . spec . InvalidParameterSpecException ;
import java . text . SimpleDateFormat ;
import java . util . ArrayList ;
import java . util . Collections ;
import java . util . Date ;
import java . util . HashMap ;
import javax . crypto . BadPaddingException ;
import javax . crypto . Cipher ;
import javax . crypto . IllegalBlockSizeException ;
import javax . crypto . NoSuchPaddingException ;
import javax . crypto . SecretKey ;
import javax . crypto . SecretKeyFactory ;
import javax . crypto . spec . IvParameterSpec ;
import javax . crypto . spec . PBEKeySpec ;
import javax . crypto . spec . SecretKeySpec ;
/*
** This is the only class.
*/
public final class MyPwStockMain
{
/*
** Constants.
*/
/*
** Some misc char, String and byte constants.
*/
  private static final byte nullByte = '\0' ;
  private static final char newLineChar = '\n' ;
  private static final char spaceChar = ' ' ;
  private static final String doubleSpace = "" + spaceChar + spaceChar ;
  private static final String singleSpace = "" + spaceChar ;
/*
** Characters stored in the admin and password files!
** ____________________________________________________
** A decrypted password container file looks like this:
** (It is not allowed to store space char in this file!)
** ----------------------------------------------------
** _characters_of_filesHeader_string_\n
** allowPasswordPartsYes|allowPasswordPartsNo\n
** key0\n
** password0\n
** key1\n
** password1\n
** ...
** ____________________________________________________
** The decrypted admin file looks like this:
** (It is allowed to store space characters!)
** ----------------------------------------------------
** _characters_of_adminHeader_string_\n
** initialization history entry\n
** history entry0\n
** history entry1\n
** ...
** ____________________________________________________
*/
// This will be the header of a password container file.
  private static final String filesHeader = "-p-a-s-s-w-o-r-d-s-" + newLineChar ;
// This will be the header of the admin file.
  private static final String adminHeader = "-a-d-m-i-n-h-i-s-t-" + newLineChar ;
// These are the possible values of allowing password parts to be stored in a file or not.
  private static final char allowPasswordPartsYes = 'y' ;
  private static final char allowPasswordPartsNo = 'n' ;
/*
** The types of the passwords.
*/
  private static final String passwordTypeFile1 = "file1" ;
  private static final String passwordTypeFile2 = "file2" ;
  private static final String passwordTypeKey = "key" ;
  private static final String passwordTypeAdmin = "admin" ;
/*
** These constants are for the proper working of this application!
** These can be printed out! (messageApplicationDescribe)
*/
  private static final String appName = "MyPwStock" ;
  private static final String appVersion = "1.2" ;
  private static final int appMaxNumOfFiles = 7 ;
  private static final int appMaxLengthOfPasswordsAndKeysAndFileNames = 70 ;
  private static final int appMaxNumOfKeysPerFile = 700 ;
  private static final int appMaxLengthOfGeneratedPasswords = 14 ;
  private static final int appMaxLengthToLog = 4 * appMaxLengthOfPasswordsAndKeysAndFileNames ;
  private static final int appFileContentMaxLength = appMaxNumOfKeysPerFile * 2 * ( appMaxLengthOfPasswordsAndKeysAndFileNames + 1 ) + filesHeader . length ( ) + adminHeader . length ( ) + 1 + 1 ;
  private static final String appPasswordDir = "pd" ;
  private static final String appAdminDir = "an" ;
  private static final String appBackupDir = "bp" ;
  private static final String appPdPostfix = ".pd" ;
  private static final String appIvPostfix = ".iv" ;
  private static final String appSlPostfix = ".sl" ;
  private static final String appNwPostfix = ".nw" ;
  private static final String appAnPostfix = ".an" ;
  private static final String appAdminFileName = "admin" ;
  private static final String appBackupDescriptionFileName = "description" ;
  private static final int appMinLengthOfKeysAndFileNames = 1 ;
  private static final int appGoodPasswordMinCountOfUCLetters = 2 ;
  private static final int appGoodPasswordMinCountOfLCLetters = 2 ;
  private static final int appGoodPasswordMinCountOfDigits = 2 ;
  private static final int appGoodPasswordMinCountOfSpecChars = 1 ;
  private static final int appGoodPasswordMinLengthOfGoodPasswords = 7 ;
  private static final int appMinLengthOfPasswordPart = 1 ;
  private static final int appSaltLength = 64 ;
  private static final int appPbeKeySpecIterations = 65536 ;
  private static final int appPbeKeySpecKeyLength = 128 ;
  private static final String appSecretKeyFactoryInstance = "PBKDF2WithHmacSHA512" ;
  private static final String appSecretKeySpecAlgorythm = "AES" ;
  private static final String appCipherInstance = "AES/CBC/PKCS5Padding" ;
  private static final String appDateFormat = "MM/dd/yyyy HH:mm:ss" ;
  private static final String appBackupNameFormat = "yyyy.MM.dd-HHmmss" ;
  private static final int appNumOfEmptyLinesToClearTheScreen = 10000 ;
  private static final int appPasswordShowSeconds = 20 ;
  private static final int appMaxNotReadCachedPasswordSeconds = 300 ;
  private static final int appMaxNotReadInputsSeconds = 60 ;
  private static final int appMaxLengthOfBackupDescription = 70 ;
  private static final int appMaxNumOfBackups = 70 ;
/*
** Foldings.
**  For formatting the messages in the front of the user.
*/
  private static final String fold = "" + spaceChar + spaceChar ;
  private static final String fold2 = "" + spaceChar + spaceChar + spaceChar + spaceChar + spaceChar ;
/*
** Separators.
*/
  private static final String sep1 = "," + spaceChar ;
  private static final String sep2 = spaceChar + "->" + spaceChar ;
  private static final String sep3 = spaceChar + ":" + spaceChar ;
  private static final String sep9 = spaceChar + "|" + spaceChar ;
/*
** Others.
*/
// The "yes" answer from the user.
  private static final String yes = "yes" ;
// The separator used by the current system.
  private static final String SEP = File . separator ;
// When showing the passwords, a "status bar" can be seen.
  private static final String passwordStatusMargin = "_" ;
  private static final String passwordStatusStatus = "-" ;
// In interactive mode this is the prompt waiting for the user's input.
  private static final String prompt = appName + "> " ;
// The types of the letters of the allowed passwords.
  private static final String lettersUCAZ = "[A-Z]" ;
  private static final String lettersLCAZ = "[a-z]" ;
  private static final String letters09 = "[0-9]" ;
  private static final String lettersSpecChars = "[.?!,;:-+_*@=<>]" ;
// For printing dates.
  private static final SimpleDateFormat simpleDateFormat = new SimpleDateFormat ( appDateFormat ) ;
// For naming backups (the name of the backup folders will be this kind of formatted.)
  private static final SimpleDateFormat backupDateFormat = new SimpleDateFormat ( appBackupNameFormat ) ;
// This is the only console object.
  private static final Console console = System . console ( ) ;
/*
** The valid arguments of using this application.
** This commands can be handled by this application.
*/
  private static final String argApplication = "application" ;
  private static final String argQuestionMark = "?" ;
  private static final String argHelp = "help" ;
  private static final String argFile = "file" ;
  private static final String argList = "list" ;
  private static final String argDescribe = "describe" ;
  private static final String argDelete = "delete" ;
  private static final String argDeleteall = "deleteall" ;
  private static final String argKey = "key" ;
  private static final String argAdd = "add" ;
  private static final String argGood = "good" ;
  private static final String argPassword = "password" ;
  private static final String argPart = "part" ;
  private static final String argWelcome = "welcome" ;
  private static final String argScreen = "screen" ;
  private static final String argShow = "show" ;
  private static final String argChange = "change" ;
  private static final String argMove = "move" ;
  private static final String argMoveall = "moveall" ;
  private static final String argAdmin = "admin" ;
  private static final String argReview = "review" ;
  private static final String argSearch = "search" ;
  private static final String argInteractive = "interactive" ;
  private static final String argMode = "mode" ;
  private static final String argExit = "exit" ;
  private static final String argPasswords = "passwords" ;
  private static final String argCache = "cache" ;
  private static final String argPurge = "purge" ;
  private static final String argType = "type" ;
  private static final String argStory = "story" ;
  private static final String argClear = "clear" ;
  private static final String argBackup = "backup" ;
  private static final String argRestore = "restore" ;
  private static final String argRestoreall = "restoreall" ;
  private static final String argSearchall = "searchall" ;
/*
** Special messages to the user or into the log.
*/
// Messages of writing the history of the application.
  private static final String messageTheHistoryOfApplication = "" + newLineChar + "The history of this " + appName + " instance." + newLineChar ;
  private static final String messageLogApplicationInstanceInitialize = "Application instance initialize." ;
  private static final String messageLogAdminPasswordChange = "Admin password change." ;
  private static final String messageLogAdminReview = "Admin review." ;
  private static final String messageLogAdminSearch = "Admin search: " ;
  private static final String messageLogKeyMove = "Key move (from file" + sep1 + "to file" + sep1 + "key): " ;
  private static final String messageLogPasswordChange = "Key password change (file" + sep1 + "key" + sep2 + "new password): " ;
  private static final String messageLogKeyChange = "Key change (file" + sep1 + "old key" + sep2 + "new key): " ;
  private static final String messageLogKeyDelete = "Key delete (file" + sep1 + "key): " ;
  private static final String messageLogKeysDelete = "Keys delete (file): " ;
  private static final String messageLogFileAdd = "File add (file" + sep2 + "password): " ;
  private static final String messageLogFileDelete = "File delete (file): " ;
  private static final String messageLogFilesDelete = "Files delete." ;
  private static final String messageLogFilePasswordChange = "File password change (file" + sep2 + "new password): " ;
  private static final String messageLogKeyAdd = "Key add (file" + sep1 + "key" + sep2 + "password): " ;
  private static final String messageLogPasswordTypeChange = "Password type change (file" + sep2 + "new password type ): " ;
  private static final String messageLogBackupMake = "Backup make (name" + sep9 + "description): " ;
  private static final String messageLogBackupDelete = "Backup delete (name" + sep9 + "success): " ;
  private static final String messageLogRestoreFile = "File restore (backup" + sep3 + "file): " ;
// Hints and help used messages.
  private static final String messageYourFileName = "<your_file_name>" ;
  private static final String messageYourKeyName = "<your_key_name>" ;
  private static final String messageYourFileNameCurrent = "<your_current_file_name>" ;
  private static final String messageYourFileNameNew = "<your_new_file_name>" ;
  private static final String messageYourCurrentKeyName = "<your_current_key_name>" ;
  private static final String messageYourNewKeyName = "<your_new_key_name>" ;
  private static final String messageYourExpressionToSearch = "<your_expression_to_search>" ;
  private static final String messageYourNumOfEmptyLinesToPrintOut = "<your_number_of_empty_lines_to_print_out>" ;
  private static final String messageYourBackup = "<your_backup>" ;
// This goes onto the console when user wants to the application be described.
  private static final String messageApplicationDescribe = "" + newLineChar + fold + appName + " information." + newLineChar + fold + newLineChar + fold + "Current version: " + appVersion + newLineChar + fold + newLineChar + fold + "File specific information." + newLineChar + fold + fold2 + "Maximum number of password container files      : " + appMaxNumOfFiles + newLineChar + fold + fold2 + "Maximum length of passwords and keys            : " + appMaxLengthOfPasswordsAndKeysAndFileNames + newLineChar + fold + fold2 + "Maximum number of passwords per file            : " + appMaxNumOfKeysPerFile + newLineChar + fold + fold2 + "Maximum length of generated passwords           : " + appMaxLengthOfGeneratedPasswords + newLineChar + fold + fold2 + "Maximum length of log entries                   : " + appMaxLengthToLog + newLineChar + fold + fold2 + "Maximum length of the content of a file (bytes) : " + appFileContentMaxLength + newLineChar + fold + fold2 + "Directory name of the file containers           : " + appPasswordDir + newLineChar + fold + fold2 + "Directory name of the admin tasks               : " + appAdminDir + newLineChar + fold + fold2 + "Directory name of the backups                   : " + appBackupDir + newLineChar + fold + fold2 + "Postfix of password files                       : " + appPdPostfix + newLineChar + fold + fold2 + "Postfix of initialization vector files          : " + appIvPostfix + newLineChar + fold + fold2 + "Postfix of salt files                           : " + appSlPostfix + newLineChar + fold + fold2 + "Postfix of newly created files of above         : " + appNwPostfix + newLineChar + fold + fold2 + "Postfix of admin file                           : " + appAnPostfix + newLineChar + fold + fold2 + "Name of admin file                              : " + appAdminFileName + newLineChar + fold + fold2 + "Name of backup description file                 : " + appBackupDescriptionFileName + newLineChar + fold + fold2 + "Minimum length of keys and file names           : " + appMinLengthOfKeysAndFileNames + newLineChar + fold + newLineChar + fold + "Storable password specific information." + newLineChar + fold + " - fully stored good password:" + newLineChar + fold + fold2 + "Minimum count of uppercase letters              : " + appGoodPasswordMinCountOfUCLetters + newLineChar + fold + fold2 + "Minimum count of lowercase letters              : " + appGoodPasswordMinCountOfLCLetters + newLineChar + fold + fold2 + "Minimum count of digits                         : " + appGoodPasswordMinCountOfDigits + newLineChar + fold + fold2 + "Minimum count of special chars                  : " + appGoodPasswordMinCountOfSpecChars + newLineChar + fold + fold2 + "Minimum length of passwords                     : " + appGoodPasswordMinLengthOfGoodPasswords + newLineChar + fold + " - password part only:" + newLineChar + fold + fold2 + "Minimum length of a password part               : " + appMinLengthOfPasswordPart + newLineChar + fold + newLineChar + fold + "Encrypt/decrypt information." + newLineChar + fold + fold2 + "Salt length                                     : " + appSaltLength + newLineChar + fold + fold2 + "Pbe key spec iterations                         : " + appPbeKeySpecIterations + newLineChar + fold + fold2 + "Pbe key spec key length                         : " + appPbeKeySpecKeyLength + newLineChar + fold + fold2 + "Secret key factory instance                     : " + appSecretKeyFactoryInstance + newLineChar + fold + fold2 + "Secret key spec algorithm                       : " + appSecretKeySpecAlgorythm + newLineChar + fold + fold2 + "Cipher instance                                 : " + appCipherInstance + newLineChar + fold + newLineChar + fold + "Other information." + newLineChar + fold + fold2 + "The format of the displayed dates               : " + appDateFormat + newLineChar + fold + fold2 + "The format of the name of the backups           : " + appBackupNameFormat + newLineChar + fold + fold2 + "Number of empty lines to clear the screen       : " + appNumOfEmptyLinesToClearTheScreen + newLineChar + fold + fold2 + "Seconds to show the password                    : " + appPasswordShowSeconds + newLineChar + fold + fold2 + "Max seconds to not read any cached password     : " + appMaxNotReadCachedPasswordSeconds + newLineChar + fold + fold2 + "Max seconds to enter any input                  : " + appMaxNotReadInputsSeconds + newLineChar + fold + fold2 + "Max length of backup description                : " + appMaxLengthOfBackupDescription + newLineChar + fold + fold2 + "Max number of backups to create                 : " + appMaxNumOfBackups ;
// This is the message of the application story.
  private static final String messageApplicationStory = newLineChar + fold + "The application story." + newLineChar + newLineChar + "The situation." + newLineChar + newLineChar + fold + "The most efficient way to identify a person in e-world is still the password." + newLineChar + fold + "(Year: 2017)" + newLineChar + fold + "Based on the fact that we cannot see into others head." + newLineChar + fold + "For example, if someone has thought a number, we cannot know that number." + newLineChar + fold + "It is known only by who has thought it." + newLineChar + newLineChar + "The problem." + newLineChar + newLineChar + fold + "If I thought a couple of numbers yesterday, it may be very hard for me to" + newLineChar + fold + "remember now each." + newLineChar + newLineChar + fold + "A person can have many good and different passwords in an ideal case." + newLineChar + fold + "(Good password is long enough and contains many kind of characters" + newLineChar + fold + " -> strong enough and hard to guess password is good password.)" + newLineChar + newLineChar + fold + "But. We are humans and the password is just a password, right?" + newLineChar + fold + "This is not the most important thing in our life." + newLineChar + fold + "Hard to guess password usually means hard to remember password too." + newLineChar + fold + "There are people who can memorize their passwords hardly." + newLineChar + fold + "(A good and monthly changed password can be forgotten easily" + newLineChar + fold + "not using it a couple of weeks, believe me.)" + newLineChar + newLineChar + fold + "To remember a password I can write it to a postit or save on a computer" + newLineChar + fold + "in a text file. The basic idea that the password should be known only by the" + newLineChar + fold + "person who has constructed it is breached in this case. Because it can be read" + newLineChar + fold + "anyone who has access to my postit or to my file." + newLineChar + fold + "So we should avoid these methods to store our passwords! These are the part" + newLineChar + fold + "of our most sensitive data so we have to take care about our passwords to be" + newLineChar + fold + "known only by us avoid the unauthorized operations on our behalf in the" + newLineChar + fold + "electronic world." + newLineChar + newLineChar + fold + "The problem is with the plain text stored passwords is that it can be read" + newLineChar + fold + "sitting in the front of the computer or stolen on the network." + newLineChar + fold + "The problem is with the postit stored password is that it can be read by" + newLineChar + fold + "everyone who walk around my desk." + newLineChar + newLineChar + fold + "The simplest way is to save this sensitive data into encrypted files while" + newLineChar + fold + "there are several good and known algorithms and its implementations!" + newLineChar + newLineChar + "A solution for this problem above." + newLineChar + newLineChar + fold + "You can defend your real passwords using " + appName + " application even one" + newLineChar + fold + "password!" + newLineChar + fold + "You now have to memorize just 1 password to know the other good and hard to" + newLineChar + fold + "guess (and hard to memorize) passwords." + newLineChar + newLineChar + fold + "This application has been developed in java technology and can be used in" + newLineChar + fold + "command line in every operating systems that contain (min 1.8) java installed." + newLineChar + newLineChar + fold + "The AES encryption is used 128 bit length of encryption key default but 192" + newLineChar + fold + "and 256 key length are also available by downloading the" + newLineChar + fold + "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy" + newLineChar + fold + "from Oracle. But, the 128 length will be enough for a couple of years." + newLineChar + newLineChar + fold + "The most important goals we have achieved:" + newLineChar + fold + "- there are no passwords written to disk in plain text format" + newLineChar + fold + "- there are unencrypted passwords in the system memory only in mutable objects" + newLineChar + fold + "- there are unencrypted passwords in the system memory while they are needed" + newLineChar + fold + "  (it is possible to use " + appName + " in an unsecure way to speed up the manual" + newLineChar + fold + "  password handling job: it can cache the admin and file passwords to not have" + newLineChar + fold + "  to type these every time, this is for the user's exact command)" + newLineChar + fold + "- the file and password operations are fully logged." + newLineChar + newLineChar + "The types of the passwords in " + appName + "." + newLineChar + newLineChar + fold + "There are 3 kind of password in this application." + newLineChar + newLineChar + fold + "Admin password:" + newLineChar + fold + fold2 + "This is the password to access the previous modifications and to manage" + newLineChar + fold + fold2 + "our file container files." + newLineChar + newLineChar + fold + "File password:" + newLineChar + fold + fold2 + "This files or password container files are to store our user passwords" + newLineChar + fold + fold2 + "named as key passwords." + newLineChar + fold + fold2 + "These files are defended by password." + newLineChar + fold + fold2 + "Every file can be set by the same file password and these passwords can" + newLineChar + fold + fold2 + "be the same as the admin password. So it is really possible to handle the" + newLineChar + fold + fold2 + "application using just one password." + newLineChar + fold + fold2 + "But, the secure way is to construct the file passwords and the admin" + newLineChar + fold + fold2 + "passwords to different strings different at least 3 characters and no" + newLineChar + fold + fold2 + "file names in these." + newLineChar + newLineChar + fold + "Password:" + newLineChar + fold + fold2 + "These are our passwords or key passwords or user passwords we want to" + newLineChar + fold + fold2 + "store in a secure and unreadable way. These passwords will go into the" + newLineChar + fold + fold2 + "file containers for future use. (For example you can log in into your" + newLineChar + fold + fold2 + "internet banking application because you will know your strong but not" + newLineChar + fold + fold2 + "recently used password.)" + newLineChar + fold + fold2 + "It is possible to have a generated good password by " + appName + "." + newLineChar + fold + fold2 + "Just type " + yes + " if it will be questioned." + newLineChar + fold + fold2 + "It is not applicable to your file and admin passwords. These passwords" + newLineChar + fold + fold2 + "have to be created by you because you have to memorize them!" + newLineChar + newLineChar + "Password storing in " + appName + "." + newLineChar + newLineChar + fold + "Password storing has been implemented in this application by key - value pair." + newLineChar + fold + "We have to name the password (this will be the key) and this name will" + newLineChar + fold + "identify this password for reading or handling in the future." + newLineChar + newLineChar + "An exact example for the password storing." + newLineChar + newLineChar + fold + "ATTENTION!" + newLineChar + fold + "If you forget your file password then the passwords contained by that file can" + newLineChar + fold + "handled as unreadable. If you forget your admin password then further" + newLineChar + fold + "modification of your password container files cannot be done and you cannot" + newLineChar + fold + "read the history of your " + appName + " instance." + newLineChar + fold + "We cannot give you any solution for these cases." + newLineChar + fold + "(This is one of our main goals: nobody can help you in case of forgotten" + newLineChar + fold + "file or admin passwords. The only solution is in the user's head as the" + newLineChar + fold + "correct admin and file passwords. Or delete everything to start over.)" + newLineChar + newLineChar + fold + "1. java " + appName + singleSpace + argWelcome + singleSpace + argScreen + newLineChar + fold + fold2 + "Read and do this." + newLineChar + fold + fold2 + "Please copy the " + appName + ".class into a safe place according to this" + newLineChar + fold + fold2 + "information." + newLineChar + newLineChar + fold + "2. Open a command line and navigate into the new place of " + appName + ".class." + newLineChar + newLineChar + fold + "3. java " + appName + singleSpace + argQuestionMark + newLineChar + fold + "or more detailed" + newLineChar + fold + "java " + appName + singleSpace + argHelp + newLineChar + fold + fold2 + "We can read our available commands to use the application." + newLineChar + newLineChar + fold + "4. java " + appName + singleSpace + argAdmin + singleSpace + argReview + newLineChar + fold + fold2 + "We can read about the history of using our " + appName + " instance." + newLineChar + fold + fold2 + "At this point we don't have any history event so we have to create our" + newLineChar + fold + fold2 + "admin password. Please construct your admin password carefully and do not" + newLineChar + fold + fold2 + "forget it!" + newLineChar + newLineChar + fold + "5. java " + appName + singleSpace + argFile + singleSpace + argAdd + " myfile1" + newLineChar + fold + fold2 + "The password container file called myfile1 will be created and the" + newLineChar + fold + fold2 + "password of this file will be prompted. You can choose the same password" + newLineChar + fold + fold2 + "as admin password but it is much safer to choose a different password." + newLineChar + fold + fold2 + "(File name doesn't included!)" + newLineChar + fold + fold2 + "What will happen exactly:" + newLineChar + fold + fold2 + "- You have to type your admin password constructed before" + newLineChar + fold + fold2 + "- You have to type you new file password" + newLineChar + fold + fold2 + "- You have to choose the type of the stored passwords in this password" + newLineChar + fold + fold2 + "container file." + newLineChar + fold + fold2 + "Choose \"n\" in this case." + newLineChar + fold + fold2 + "(Full and valid passwords can be stored in this file.)" + newLineChar + newLineChar + fold + "6. java " + appName + singleSpace + argKey + singleSpace + argAdd + " myfile1" + newLineChar + fold + fold2 + "This is it." + newLineChar + fold + fold2 + "We will put our internet bank password into our myfile1 file made before." + newLineChar + fold + fold2 + "- The file password will be prompted" + newLineChar + fold + fold2 + "- The admin password too" + newLineChar + fold + fold2 + "- The key (a name) will be questioned, let it be as \"ibank_pwd\"" + newLineChar + fold + fold2 + "- The password of this key will be prompted" + newLineChar + newLineChar + fold + "We are done." + newLineChar + newLineChar + fold + "7. java " + appName + singleSpace + argAdmin + singleSpace + argReview + newLineChar + fold + fold2 + "It can be seen that we have initialized our application, have created a new" + newLineChar + fold + fold2 + "password container file and have added a new password into this file." + newLineChar + fold + fold2 + "By repeat this command, it also can be seen that the admin review has called." + newLineChar + newLineChar + "An exact example for the password reading." + newLineChar + newLineChar + fold + "1. Open a command line and navigate to the place of " + appName + ".class." + newLineChar + newLineChar + fold + "2. java " + appName + singleSpace + argFile + singleSpace + argList + newLineChar + fold + fold2 + "We can list our file names we want to read a password from." + newLineChar + newLineChar + fold + "3. java " + appName + singleSpace + argKey + singleSpace + argList + " myfile1" + newLineChar + fold + fold2 + "We can list our keys (names of our passwords) added before into myfile1." + newLineChar + fold + fold2 + "The password of this file will be prompted." + newLineChar + newLineChar + fold + "4. java " + appName + singleSpace + argPassword + singleSpace + argShow + " myfile1 ibank_pwd" + newLineChar + fold + fold2 + "This is it." + newLineChar + fold + fold2 + "The command above shows the password placed into the myfile1 and belongs to" + newLineChar + fold + fold2 + "the ibank_pwd key. The password of the file will be prompted of course." + newLineChar + newLineChar + "Less secure but more efficient usage." + newLineChar + newLineChar + fold + "java " + appName + singleSpace + argInteractive + singleSpace + argMode + newLineChar + newLineChar + fold + fold2 + "We can enter into an interactive mode by typing this command." + newLineChar + fold + fold2 + "We won't have to type java " + appName + " and only the command is necessary." + newLineChar + newLineChar + fold + argPasswords + singleSpace + argCache + newLineChar + newLineChar + fold + fold2 + "INSECURE (but for faster use)" + newLineChar + newLineChar + fold + fold2 + "Typing this in interactive mode the passwords of the password container" + newLineChar + fold + fold2 + "files and the admin password will be cached in the system memory" + newLineChar + fold + fold2 + "(on the area of JVM). This is a less secure way but the application can" + newLineChar + fold + fold2 + "be used much faster while you won't have to type the file passwords and" + newLineChar + fold + fold2 + "the admin password every time. This is useful especially in the beginning" + newLineChar + fold + fold2 + "when your passwords will go into this " + appName + " password container" + newLineChar + fold + fold2 + "application." + newLineChar + fold + "  " + newLineChar + fold + fold2 + "All of the cached password will be forgotten when you type this command" + newLineChar + fold + fold2 + "again. The file and admin passwords will be prompted next time, but still" + newLineChar + fold + fold2 + "will be cached later." + newLineChar + fold + "  " + newLineChar + fold + fold2 + "The cached admin and file passwords have to be read continuously." + newLineChar + fold + fold2 + "So you have to work continuously in the application because it will" + newLineChar + fold + fold2 + "forget your cached passwords after a not too long time and you will have" + newLineChar + fold + fold2 + "to type these passwords again." + newLineChar + fold + "  " + newLineChar + fold + argPasswords + singleSpace + argPurge + newLineChar + fold + "  " + newLineChar + fold + fold2 + "SECURE " + newLineChar + fold + "  " + newLineChar + fold + fold2 + "This is also available in interactive mode of " + appName + " and this is the" + newLineChar + fold + fold2 + "default behavior after the interactive mode command. After the execution" + newLineChar + fold + fold2 + "of " + argPasswords + singleSpace + argPurge + " command, the cached passwords of files and admin will" + newLineChar + fold + fold2 + "be forgotten and you have to type these again and every time when" + newLineChar + fold + fold2 + "prompted." + newLineChar + fold + "  " + newLineChar + fold + argExit + newLineChar + newLineChar + fold + fold2 + "You can quit from the interactive mode." ;
// This is the message of good password.
  private static final String messageGoodPassword = "" + newLineChar + fold + "THE GOOD PASSWORD IS:" + newLineChar + fold + "+------------------------------------------------------+" + newLineChar + fold + "| - ASCII 33-126 characters are acceptable, no spaces! |" + newLineChar + fold + "| - min. " + appGoodPasswordMinCountOfUCLetters + " uppercase letters                     " + lettersUCAZ + " |" + newLineChar + fold + "| - min. " + appGoodPasswordMinCountOfLCLetters + " lowercase letters                     " + lettersLCAZ + " |" + newLineChar + fold + "| - min. " + appGoodPasswordMinCountOfDigits + " digits                                " + letters09 + " |" + newLineChar + fold + "| - min. " + appGoodPasswordMinCountOfSpecChars + " special chars, for example " + lettersSpecChars + " |" + newLineChar + fold + "| - min. _" + appGoodPasswordMinLengthOfGoodPasswords + "_ and max. _" + appMaxLengthOfPasswordsAndKeysAndFileNames + "_ characters length password! |" + newLineChar + fold + "+------------------------------------------------------+" ;
// This is the message of good passwords.
  private static final String messagePasswordPart = "" + newLineChar + fold + "THE PASSWORD PART YOU CAN STORE IS:" + newLineChar + fold + "+------------------------------------------------------+" + newLineChar + fold + "| - ASCII 33-126 characters are acceptable, no spaces! |" + newLineChar + fold + "| - min. _" + appMinLengthOfPasswordPart + "_ and max. _" + appMaxLengthOfPasswordsAndKeysAndFileNames + "_ characters length password! |" + newLineChar + fold + "+------------------------------------------------------+" ;
// This goes onto the console when user types argQuestionMark.
  private static final String messageHints = "" + newLineChar + fold + argInteractive + spaceChar + argMode + newLineChar + fold2 + argExit + newLineChar + fold2 + argPasswords + spaceChar + argCache + newLineChar + fold2 + argPasswords + spaceChar + argPurge + newLineChar + fold + argApplication + spaceChar + argDescribe + newLineChar + fold + argApplication + spaceChar + argStory + newLineChar + fold + argWelcome + spaceChar + argScreen + newLineChar + fold + argGood + spaceChar + argPassword + newLineChar + fold + argPassword + spaceChar + argPart + newLineChar + fold + argClear + spaceChar + argScreen + spaceChar + messageYourNumOfEmptyLinesToPrintOut + newLineChar + fold + argFile + spaceChar + argList + newLineChar + fold + argFile + spaceChar + argSearch + spaceChar + messageYourExpressionToSearch + newLineChar + fold + argFile + spaceChar + argAdd + spaceChar + messageYourFileName + newLineChar + fold + argFile + spaceChar + argDescribe + spaceChar + messageYourFileName + newLineChar + fold + argFile + spaceChar + argPassword + spaceChar + argChange + spaceChar + messageYourFileName + newLineChar + fold + argFile + spaceChar + argDelete + spaceChar + messageYourFileName + newLineChar + fold + argFile + spaceChar + argDeleteall + newLineChar + fold + argKey + spaceChar + argList + spaceChar + messageYourFileName + newLineChar + fold + argKey + spaceChar + argSearch + spaceChar + messageYourFileName + spaceChar + messageYourExpressionToSearch + newLineChar + fold + argKey + spaceChar + argAdd + spaceChar + messageYourFileName + newLineChar + fold + argKey + spaceChar + argChange + spaceChar + messageYourFileName + spaceChar + messageYourCurrentKeyName + spaceChar + messageYourNewKeyName + newLineChar + fold + argKey + spaceChar + argDelete + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + argKey + spaceChar + argDeleteall + spaceChar + messageYourFileName + newLineChar + fold + argKey + spaceChar + argMove + spaceChar + messageYourFileNameCurrent + spaceChar + messageYourFileNameNew + spaceChar + messageYourKeyName + newLineChar + fold + argKey + spaceChar + argMoveall + spaceChar + messageYourFileNameCurrent + spaceChar + messageYourFileNameNew + newLineChar + fold + argPassword + spaceChar + argShow + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + argPassword + spaceChar + argChange + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + argPassword + spaceChar + argType + spaceChar + argChange + spaceChar + messageYourFileName + newLineChar + fold + argAdmin + spaceChar + argReview + newLineChar + fold + argAdmin + spaceChar + argSearch + spaceChar + messageYourExpressionToSearch + newLineChar + fold + argAdmin + spaceChar + argPassword + spaceChar + argChange + newLineChar + fold + argBackup + spaceChar + argList + newLineChar + fold + argBackup + spaceChar + argAdd + newLineChar + fold + argBackup + spaceChar + argDelete + spaceChar + messageYourBackup + newLineChar + fold + argBackup + spaceChar + argDeleteall + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argList + spaceChar + messageYourBackup + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argSearch + spaceChar + messageYourBackup + spaceChar + messageYourExpressionToSearch + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argSearchall + spaceChar + messageYourExpressionToSearch + newLineChar + fold + argBackup + spaceChar + argRestore + spaceChar + messageYourBackup + spaceChar + messageYourFileName + newLineChar + fold + argBackup + spaceChar + argRestoreall + spaceChar + messageYourBackup + newLineChar + fold + argQuestionMark + newLineChar + fold + argHelp ;
// And this goes when user types argHelp.
  private static final String messageHelp = "" + newLineChar + fold + "Please type these arguments to use " + appName + " correctly:" + newLineChar + fold + newLineChar + fold + argInteractive + spaceChar + argMode + newLineChar + fold + fold2 + "Starts the " + appName + " in interactive mode." + newLineChar + fold + newLineChar + fold + argExit + newLineChar + fold + fold2 + "(in interactive mode) Exits you from the " + appName + "." + newLineChar + fold + newLineChar + fold + argPasswords + spaceChar + argCache + newLineChar + fold + fold2 + "(in interactive mode) Caches the file passwords and admin password you will enter from this time." + newLineChar + fold + fold2 + "                      You have to enter a file or admin password only once." + newLineChar + fold + newLineChar + fold + argPasswords + spaceChar + argPurge + newLineChar + fold + fold2 + "(in interactive mode) Purges the file passwords and admin password you have entered." + newLineChar + fold + fold2 + "                      You have to enter a file or admin password every time." + newLineChar + fold + newLineChar + fold + argApplication + spaceChar + argDescribe + newLineChar + fold + fold2 + "Prints the information of this application for you." + newLineChar + fold + newLineChar + fold + argApplication + spaceChar + argStory + newLineChar + fold + fold2 + "Prints the basic concept and the basic usage, please read it carefully." + newLineChar + fold + newLineChar + fold + argWelcome + spaceChar + argScreen + newLineChar + fold + fold2 + "Prints the first run screen." + newLineChar + fold + newLineChar + fold + argGood + spaceChar + argPassword + newLineChar + fold + fold2 + "Prints the expectations of a storable good password." + newLineChar + fold + newLineChar + fold + argPassword + spaceChar + argPart + newLineChar + fold + fold2 + "Prints the expectations of a storable password part." + newLineChar + fold + newLineChar + fold + argClear + spaceChar + argScreen + spaceChar + messageYourNumOfEmptyLinesToPrintOut + newLineChar + fold + fold2 + "Clears your screen by printing several new line characters." + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argList + newLineChar + fold + fold2 + "Lists all of your password files." + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argSearch + spaceChar + messageYourExpressionToSearch + newLineChar + fold + fold2 + "Searches for files having name according to " + messageYourExpressionToSearch + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argAdd + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Creates your new password container file." + newLineChar + fold + fold2 + "You can specify the name of your file in " + messageYourFileName + "." + newLineChar + fold + fold2 + "The key (password) for this password container will be questioned." + newLineChar + fold + fold2 + "You have to specify the way you will store the passwords." + newLineChar + fold + fold2 + "(password parts or whole passwords)" + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argDescribe + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Prints the properties of your password container file." + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argPassword + spaceChar + argChange + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Changes the password of a password container file." + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argDelete + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Deletes the file you name in the " + messageYourFileName + "." + newLineChar + fold + newLineChar + fold + argFile + spaceChar + argDeleteall + newLineChar + fold + fold2 + "Deletes all the password container files." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argList + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Lists the keys in a given password container file in ascending order." + newLineChar + fold + fold2 + "The password of the file will be questioned." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argSearch + spaceChar + messageYourFileName + spaceChar + messageYourExpressionToSearch + newLineChar + fold + fold2 + "Searches for keys in a file according to " + messageYourExpressionToSearch + newLineChar + fold + fold2 + "The password of the file also will be questioned." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argAdd + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Adds an ASCII key - password into your password container file." + newLineChar + fold + fold2 + "The password of the file will be questioned first" + newLineChar + fold + fold2 + "then the key and the password belongs to your key." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argChange + spaceChar + messageYourFileName + spaceChar + messageYourCurrentKeyName + spaceChar + messageYourNewKeyName + newLineChar + fold + fold2 + "Changes a key name in one of your password container files." + newLineChar + fold + fold2 + "The password belongs to that key will be untouched." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argDelete + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + fold2 + "Deletes a key from your given password container file." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argDeleteall + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Deletes all of your keys from your given password container file." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argMove + spaceChar + messageYourFileNameCurrent + spaceChar + messageYourFileNameNew + spaceChar + messageYourKeyName + newLineChar + fold + fold2 + "Moves a key from a password container file into another." + newLineChar + fold + newLineChar + fold + argKey + spaceChar + argMoveall + spaceChar + messageYourFileNameCurrent + spaceChar + messageYourFileNameNew + newLineChar + fold + fold2 + "Moves all of your keys from a password container file into another." + newLineChar + fold + newLineChar + fold + argPassword + spaceChar + argShow + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + fold2 + "Shows the password belongs to your key from the file you have requested." + newLineChar + fold + fold2 + "One password will be shown at a time so you can't list all of them." + newLineChar + fold + newLineChar + fold + argPassword + spaceChar + argChange + spaceChar + messageYourFileName + spaceChar + messageYourKeyName + newLineChar + fold + fold2 + "Changes a password in one of your password container files." + newLineChar + fold + fold2 + "It is a password modification belongs to a key and not to password files." + newLineChar + fold + newLineChar + fold + argPassword + spaceChar + argType + spaceChar + argChange + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Changes the type of storable passwords in " + messageYourFileName + "." + newLineChar + fold + newLineChar + fold + argAdmin + spaceChar + argReview + newLineChar + fold + fold2 + "Views the history of files, keys and passwords." + newLineChar + fold + newLineChar + fold + argAdmin + spaceChar + argSearch + spaceChar + messageYourExpressionToSearch + newLineChar + fold + fold2 + "Searches for your expression in the history above." + newLineChar + fold + newLineChar + fold + argAdmin + spaceChar + argPassword + spaceChar + argChange + newLineChar + fold + fold2 + "Changes your admin password." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argList + newLineChar + fold + fold2 + "Lists your backups of the password container files." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argAdd + newLineChar + fold + fold2 + "Adds a backup of the current state of your password container files." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argDelete + spaceChar + messageYourBackup + newLineChar + fold + fold2 + "Deletes a backup given as " + messageYourBackup + "." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argDeleteall + newLineChar + fold + fold2 + "Deletes all of your backups of stored passwords." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argList + spaceChar + messageYourBackup + newLineChar + fold + fold2 + "Lists the files contained by a backup." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argSearch + spaceChar + messageYourBackup + spaceChar + messageYourExpressionToSearch + newLineChar + fold + fold2 + "Searches for file names contains the expression." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argFile + spaceChar + argSearchall + spaceChar + messageYourExpressionToSearch + newLineChar + fold + fold2 + "Searches for file names contains the expression in all of your backups." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argRestore + spaceChar + messageYourBackup + spaceChar + messageYourFileName + newLineChar + fold + fold2 + "Restores just a file from a backup specified as " + messageYourBackup + "." + newLineChar + fold + fold2 + "Your current password files won't be deleted. The specified file will be restored." + newLineChar + fold + fold2 + "It will be copied into the current workspace or will be overwritten in the current workspace." + newLineChar + fold + newLineChar + fold + argBackup + spaceChar + argRestoreall + spaceChar + messageYourBackup + newLineChar + fold + fold2 + "Restores a backup specified as " + messageYourBackup + "." + newLineChar + fold + fold2 + "All of your current password files will be backed up and deleted before " + argRestoreall + "!" + newLineChar + fold + newLineChar + fold + argQuestionMark + newLineChar + fold + fold2 + "Prints the available commands only." + newLineChar + fold + newLineChar + fold + argHelp + newLineChar + fold + fold2 + "Prints this page." ;
/*
** General messages to the user.
*/
  private static final String messageAllowFullPasswordsOnly = "full passwords only (" + allowPasswordPartsNo + ")." ;
  private static final String messageAllowPasswordPartsAndFullPasswords = "full passwords or password parts (" + allowPasswordPartsYes + ")." ;
  private static final String messageTypeYesElseAnything = "[type " + yes + " else anything]: " ;
  private static final String messageExiting = "" + newLineChar + fold + "The " + appName + " is exiting with error:" + newLineChar + fold ;
  private static final String messageYourPasswordIs = "" + newLineChar + "Your requested password is (showing " + appPasswordShowSeconds + " seconds, do not press CTRL+C):" ;
  private static final String messageBaseCommand = "\"java" + spaceChar + appName + "\"" ;
  private static final String messageHelpCommand = "\"java" + spaceChar + appName + spaceChar + argHelp + "\"" ;
  private static final String messageWelcomeScreenCommand = "\"java" + spaceChar + appName + spaceChar + argWelcome + spaceChar + argScreen + "\"" ;
  private static final String messageGoodPasswordCommand = "\"java" + spaceChar + appName + spaceChar + argGood + spaceChar + argPassword + "\"" ;
  private static final String messagePasswordPartCommand = "\"java" + spaceChar + appName + spaceChar + argPassword + spaceChar + argPart + "\"" ;
  private static final String messageWelcomeScreen = "" + newLineChar + fold + "Welcome to " + appName + "! " + newLineChar + fold + newLineChar + fold + "This little opensource java project wants to help you" + newLineChar + fold + "storing your passwords or other sensitive key-value data in a secure way! " + newLineChar + fold + newLineChar + fold + "Please use this application on not compromised and not suspicious computers" + newLineChar + fold + "where the operating system" + newLineChar + fold + " - is from trusted and legal source" + newLineChar + fold + " - is up-to-date" + newLineChar + fold + " - never contained viruses and any malicious code" + newLineChar + fold + " - has an active antivirus software and its up-to-date virus definition database" + newLineChar + fold + " - has a properly set up and active firewall software" + newLineChar + fold + newLineChar + fold + "Please follow these instructions! " + newLineChar + fold + newLineChar + fold + "0. Check your java, min 1.8 is needed! " + newLineChar + fold + fold2 + "\"java -version\" command prints it for you. Also check for the java is the latest on the computer." + newLineChar + fold + fold2 + "Make sure in your classpath to the \"java\" command points into the correct java executable! " + newLineChar + fold + "1. Create a folder! " + newLineChar + fold + fold2 + "The best solution is to create a folder on your removable device! " + newLineChar + fold + fold2 + "Make sure your removable device is in your computer in the shortest time possible." + newLineChar + fold + fold2 + "Do not plug it if you won't use " + appName + "! " + newLineChar + fold + "2. Make sure to make this folder your personal folder! " + newLineChar + fold + fold2 + "For example on linux: chmod 700, chown your_username, chgrp your_group." + newLineChar + fold + "3. Move " + appName + ".class into that folder! " + newLineChar + fold + fold2 + "This folder will be the base of your application instance." + newLineChar + fold + "4. Open a command line and navigate into that folder! " + newLineChar + fold + fold2 + "It is necessary while it is a command line application." + newLineChar + fold + "5. Type " + messageBaseCommand + " to initialize your " + appName + " instance! " + newLineChar + fold + fold2 + "That is the time when you will set your admin password." + newLineChar + fold + "6. Type " + messageHelpCommand + " to read about the usage! " + newLineChar + fold + fold2 + "You are now ready to use " + appName + "." + newLineChar + fold + ".. Periodically make a copy of the whole folder you have created during step 1. into a separate removable device! " + newLineChar + fold + fold2 + "Having the same attributes as described in step 2." + newLineChar + fold + fold2 + "If something went wrong you will still have your passwords." ;
  private static final String messageAdminFileHasBeenCreated = "" + newLineChar + fold + "Your admin file has been created successfully." ;
  private static final String messageDescribeFileSize = "" + fold + "File size (KB) : " ;
  private static final String messageDescribeFileNumOfKeys = "" + fold + "Number of keys : " ;
  private static final String messageDescribeFilePasswordType = "" + fold + "Password store : " ;
  private static final String messageKeyHasNotValidGoodPassword = "" + fold + "The key has not valid good password: " ;
  private static final String messageDoNotForgetYourFilePassword = "" + newLineChar + fold + "IMPORTANT notice! " + newLineChar + fold + newLineChar + fold + "Please do not forget your password of the file below! " + newLineChar + fold + "If you forget the password of this password container file," + newLineChar + fold + "  you will not be able to read your passwords stored in it! " + newLineChar + fold + "Keep it in your mind and choose a password you will not forget! " ;
  private static final String messageAllowPasswordParts = "" + newLineChar + fold + "Do you want to store password parts in this password container file?" + newLineChar + fold + newLineChar + fold + "Please type" + newLineChar + fold + "\"" + allowPasswordPartsYes + "\": You can store just a piece of the password or whole passwords! " + newLineChar + fold + fold2 + "For example you choose for your password \"WTb7u.-84\"" + newLineChar + fold + fold2 + "you can store the password part \"84\"" + newLineChar + fold + fold2 + "and the other parts of this password can be never written anywhere." + newLineChar + fold + fold2 + "In this case your password will NOT be validated by the standards." + newLineChar + fold + fold2 + "Please type " + messagePasswordPartCommand + " for more information." + newLineChar + fold + "..or" + newLineChar + fold + "\"" + allowPasswordPartsNo + "\": You will be able to store in this file valid passwords only." + newLineChar + fold + fold2 + "In this case your password will be validated by the standards." + newLineChar + fold + fold2 + "Please type " + messageGoodPasswordCommand + " for more information." + newLineChar + fold + ": " ;
  private static final String messageThePasswordIsNotValid = "The password is not valid." ;
  private static final String messageGoodPasswordIsNotValid = "" + newLineChar + fold + messageThePasswordIsNotValid + newLineChar + messageGoodPassword ;
  private static final String messagePasswordPartIsNotValid = "" + newLineChar + fold + messageThePasswordIsNotValid + newLineChar + messagePasswordPart ;
  private static final String messageEnterPasswordVerify = "" + fold + "Please verify it: " ;
  private static final String messagePasswordVerificationError = "" + newLineChar + fold + "Sorry but the password and its verification are not the same." ;
  private static final String messageDoNotForgetYourAdminPassword = "" + newLineChar + fold + "The password of the administration tasks will be questioned." + newLineChar + fold + newLineChar + fold + "Please do not forget your admin password" + newLineChar + fold + "otherwise you won't be able to admin your " + appName + " instance! " + newLineChar + fold + newLineChar + fold + "This admin password is prompted if you execute a modifier task." + newLineChar + fold + "Every modification will be logged. (The read-only queries not.)" + newLineChar + fold + "This logging entries will be stored up to " + appFileContentMaxLength + " bytes long." + newLineChar + fold + "If this size exceeds this limit, the oldest log entries will be dropped." ;
  private static final String messageErrorDeletingOldFilesOrRenameNewFiles = "" + newLineChar + fold + "Error has occurred while deleting old files or rename back to new files! " + newLineChar + fold + "Please fix it manually:" + newLineChar + fold + "The files has to be deleted (" + appPdPostfix + sep1 + appSlPostfix + " and " + appIvPostfix + ")" + newLineChar + fold + "and the " + appNwPostfix + " files have to be renamed back without " + appNwPostfix + " extension! " + newLineChar + fold + "The filename is: " ;
  private static final String messageScreenHasBeenCleared1 = newLineChar + fold + "Your Screen has been cleared as " ;
  private static final String messageScreenHasBeenCleared2 = " empty lines have been printed out." ;
  private static final String messageNoArguments = "" + newLineChar + fold + "You haven't specified any arguments." + newLineChar + fold + "hint: type " + messageHelpCommand ;
  private static final String messageFileHasBeenDeletedSl = "" + fold + "Sl file has also been deleted." ;
  private static final String messageFileHasBeenDeletedIv = "" + fold + "Iv file has also been deleted." ;
  private static final String messageFileHasNotBeenDeletedSl = "" + fold + "Sl file may be still there, please remove it manually! " ;
  private static final String messageFileHasNotBeenDeletedIv = "" + fold + "Iv file may be still there, please remove it manually! " ;
  private static final String messageErrorDeletingNewPwFile = "" + fold + "Error while deleting newly created " + appPdPostfix + " file! " ;
  private static final String messageErrorDeletingNewSlFile = "" + fold + "Error while deleting newly created " + appSlPostfix + " file! " ;
  private static final String messageErrorDeletingNewIvFile = "" + fold + "Error while deleting newly created " + appIvPostfix + " file! " ;
  private static final String messageMissingPwOrSlOrIvFile = "" + newLineChar + fold + "Sorry but you have no original " + appPdPostfix + " file or " + appSlPostfix + " file or " + appIvPostfix + " file for " ;
  private static final String messageMissingAnOrSlOrIvFile = "" + newLineChar + fold + "Sorry but you have no original " + appAnPostfix + " file or " + appSlPostfix + " file or " + appIvPostfix + " file for " ;
  private static final String messageMissingNewPwOrSlOrIvFile = "" + newLineChar + fold + "Sorry but one or more new file is missing after the saving operation" + newLineChar + fold + "( " + appPdPostfix + " file or " + appSlPostfix + " file or " + appIvPostfix + " ), your changes will be rolled back! " ;
  private static final String messageMissingNewAnOrSlOrIvFile = "" + newLineChar + fold + "Sorry but one or more new file is missing after the saving operation" + newLineChar + fold + "( " + appAnPostfix + " file or " + appSlPostfix + " file or " + appIvPostfix + " ), your changes will be rolled back! " ;
  private static final String messageSureChangeTypeOfPasswors = "" + newLineChar + fold + "Are you sure want to change the type of passwords in this file?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSureDeleteAllFiles = "" + newLineChar + fold + "Are you sure delete all of your password container files?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSureDeleteKeys = "" + newLineChar + fold + "Are you sure delete ALL of your keys in the file?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSureMoveKeys = "" + newLineChar + fold + "Are you sure move ALL of your keys in the file?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSureChangePassword = "" + newLineChar + fold + "Are you sure want to change this password?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSure2 = "\"?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageSureChangeAdminPassword = "" + newLineChar + fold + "Are you sure change the admin password?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageContentIsNotDecrypted = newLineChar + fold + "The content is not decrypted for password type: " ;
  private static final String messageIsFolderSafe = "" + newLineChar + fold + "Is the folder of this " + appName + ".class safe enough?" + newLineChar + fold + "(like described in " + messageWelcomeScreenCommand + ")" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageWouldYouLikeToHaveAGeneratedGoodPassword = "" + newLineChar + fold + "Would you like to have a generated good password?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageWouldYouLikeToReadYourGeneratedGoodPassword = "" + newLineChar + fold + "Would you like to read your generated good password now?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageWelcomeToInteractiveMode = "" + newLineChar + fold + "Welcome to interactive mode of " + appName + "." + newLineChar + fold + "Type \"" + argExit + "\" to leave! " + newLineChar ;
  private static final String messagePasswordsCacheEnabled = "" + newLineChar + fold + "OK, your file and admin passwords will be cached if you work continuously." + newLineChar + fold + "It is not a secure way because your passwords will stay in the system memory." ;
  private static final String messagePasswordsCacheDisabled = "" + newLineChar + fold + "OK, your file and admin passwords will NOT be cached." + newLineChar + fold + "Yeah, your passwords have been disappeared from system memory! " ;
  private static final String messageFilesCountMore = " password files have been found." ;
  private static final String messageKeysCountFound = " keys have been found in your file." ;
  private static final String messageHitHasBeenFound = " hit has been found for " ;
  private static final String messageHitsHaveBeenFound = " hits have been found for " ;
  private static final String messageNoHitsHaveBeenFound = "No hits have been found for " ;
  private static final String messageAvailableFilesCount = "" + fold + "You can create more files: " ;
  private static final String messageAvailableKeysCount = "" + fold + "You can create more keys in file: " ;
  private static final String messageKeyHasBeenMoved = "" + fold + "The key has been moved successfully: " ;
  private static final String messageKeyHasBeenMovedWithFileSaving = "" + fold + "The key has been moved successfully (with file saving): " ;
  private static final String messageKeyHasBeenAdded = "" + newLineChar + fold + "Your new key has been added successfully." ;
  private static final String messageFileHasBeenCreated = "" + fold + "Your file has been created successfully." ;
  private static final String messageTooManyKeysInFileNew = "" + fold + "You cannot have more than " + appMaxNumOfKeysPerFile + " keys in the file you have wanted to move into." ;
  private static final String messageKeyFoundInNew = "" + fold + "Your key is found in the second file (move into): " ;
  private static final String messageKeyIsNotFoundInCurrent = "" + fold + "Your key is not found in the first file (move from): " ;
  private static final String messageThePasswordTypeHasAlreadySetToThis = "" + newLineChar + fold + "The password type of this file has already set to this value." ;
  private static final String messageChangePasswordAtLeast3Digits = "" + newLineChar + fold + "Change your password at least 3 characters! " ;
  private static final String messageFilesHaveToBeDifferent = "" + newLineChar + fold + "The names of the two files have to be different." ;
  private static final String messageNewKeyNameHaveToBeDifferent = "" + newLineChar + fold + "The old and the new key name have to be different." ;
  private static final String messageKeysHasBeenHandled = "" + newLineChar + fold + "All of the keys has been handled." ;
  private static final String messageDescribeFileLastModified = "" + newLineChar + fold + "Last modified  : " ;
  private static final String messageTypeOfStorablePasswordsHasBeenChanged = "" + newLineChar + fold + "The type of storable passwords has been changed." ;
  private static final String messageFilesCountOne = "" + newLineChar + fold + "1 password file has been found." ;
  private static final String messageFilesCountEmpty = "" + newLineChar + fold + "No password files have been found." ;
  private static final String messageFileDoesNotExist = "" + newLineChar + fold + "The file does not exist: " ;
  private static final String messageFileIsNotFile = "" + newLineChar + fold + "The file is not a file: " ;
  private static final String messageFileHasBeenDeleted = "" + newLineChar + fold + "Your file has been deleted successfully." ;
  private static final String messageFileHasNotBeenDeleted = "" + newLineChar + fold + "Your file has not been deleted!" ;
  private static final String messageFileWontBeDeleted = "" + newLineChar + fold + "Your password file is still there." ;
  private static final String messagePasswordFromFile = "" + newLineChar + fold + "The file password you want to move from - " ;
  private static final String messagePasswordIntoFile = "" + newLineChar + fold + "The file password you want to move into - " ;
  private static final String messageFilePasswordWontBeChanged = "" + newLineChar + fold + "The password of your password container file is the same." ;
  private static final String messageFilePasswordHasBeenChanged = "" + newLineChar + fold + "The password of your password container file has been changed successfully." ;
  private static final String messagePasswordWontBeChanged = "" + newLineChar + fold + "OK, your password has not been changed." ;
  private static final String messagePasswordHasBeenChanged = "" + newLineChar + fold + "Your password has been changed successfully." ;
  private static final String messageKeyHasBeenChanged = "" + newLineChar + fold + "Your key has been changed to new name." ;
  private static final String messageWrongParameters = "" + newLineChar + fold + "You have used wrong parameters! " + newLineChar + fold + "(and ASCII 32-126 characters are acceptable.)" ;
  private static final String messageSureDeleteFile = "" + newLineChar + fold + "Are you sure delete password file \"" ;
  private static final String messageSureChangeFilePassword = "" + newLineChar + fold + "Are you sure change the password of file \"" ;
  private static final String messageNewKeyAlreadyExists = "" + newLineChar + fold + "The new key you have specified already exists in the file." ;
  private static final String messageKeyIsNotFound = "" + newLineChar + fold + "Your key is not found in this file." ;
  private static final String messageSureDeleteKey = "" + newLineChar + fold + "Are you sure delete the key \"" ;
  private static final String messageSureMoveKey = "" + newLineChar + fold + "Are you sure move the key \"" ;
  private static final String messageSureChangeKey = "" + newLineChar + fold + "Are you sure change the key \"" ;
  private static final String messageKeysAreStillThere = "" + newLineChar + fold + "Don't panic, your keys are still there." ;
  private static final String messageKeysHasBeenDeleted = "" + newLineChar + fold + "All of your keys has been deleted (if there were any)." ;
  private static final String messageScreenHasBeenClearedBut = "" + newLineChar + fold + "This screen has been cleared, but.." ;
  private static final String messageCloseThisWindow = "" + newLineChar + fold + "Do not forget to close this window! " ;
  private static final String messageNobodyIsAround = "" + newLineChar + fold + "MAKE SURE nobody is looking at your screen!" + newLineChar + fold + "Is your screen safe?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageAllFilesAreStillThere = "" + newLineChar + fold + "All of your password files are still there." ;
  private static final String messageTooManyFiles = "" + newLineChar + fold + "You cannot have more than " + appMaxNumOfFiles + " password files! " ;
  private static final String messageTooManyKeysInFile = "" + newLineChar + fold + "You cannot have more than " + appMaxNumOfKeysPerFile + " keys per file." ;
  private static final String messageFileContentHasNotBeenFound = "" + newLineChar + fold + "The content of the file has not been found: " ;
  private static final String messageNameIsNotValid = "" + newLineChar + fold + "The name is not valid." ;
  private static final String messageTypeOfPasswordsWontBeChanged = "" + newLineChar + fold + "The type of storable passwords won't be changed in this file." ;
  private static final String messageFromFileEmpty = "" + newLineChar + fold + "The file is empty you have wanted to move your keys from! " ;
  private static final String messageFileAlreadyExists = "" + newLineChar + fold + "This file name is already in use! " ;
  private static final String messageFileHasBeenSaved = "" + newLineChar + fold + "File has been saved: " ;
  private static final String messageEnterPasswordForKey = "" + newLineChar + fold + "Enter your key password: " ;
  private static final String messageEnterPasswordForFile = "" + newLineChar + fold + "Enter your file password: " ;
  private static final String messageEnterPasswordForAdmin = "" + newLineChar + fold + "Enter your admin password: " ;
  private static final String messageEnterKey = "" + newLineChar + fold + "Enter your key: " ;
  private static final String messageIncorrectFilePassword = "" + newLineChar + fold + "The password of this file container you have entered is incorrect: " ;
  private static final String messageKeyHasBeenDeleted = "" + newLineChar + fold + "Your key has been deleted successfully." ;
  private static final String messageKeyIsStillThere = "" + newLineChar + fold + "Your key is still there." ;
  private static final String messageKeyWontBeChanged = "" + newLineChar + fold + "Your key name is still the same." ;
  private static final String messageAdminPasswordHasBeenChanged = "" + newLineChar + fold + "The admin password has been changed successfully." ;
  private static final String messageAdminPasswordWontBeChanged = "" + newLineChar + fold + "The admin password is the same." ;
  private static final String messageAllFilesHaveBeenDeleted = "" + newLineChar + fold + "All of the password container files have been deleted." ;
  private static final String messageKeyCountHasBeenFound = "" + newLineChar + fold + "1 key has been found in your file." ;
  private static final String messageNoKeysHaveBeenFound = "" + newLineChar + fold + "No keys have been found in your file." ;
  private static final String messageIncompatibleFiles = "" + newLineChar + fold + "The type of the stored passwords do not match in the two files you have specified." + newLineChar + fold + "Please look at it by " + argFile + spaceChar + argDescribe + " and " + argPassword + spaceChar + argType + spaceChar + argChange + " commands! " ;
  private static final String messageFileDoesNotContainAnyKey = "" + newLineChar + fold + "It seems to your file does not contain any keys." ;
  private static final String messageSureMakeBackup = newLineChar + fold + "Are you sure want to make a backup of your current state of password files?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageBackupWontBeMade = newLineChar + fold + "Ok, backup will be not made." ;
  private static final String messageYourBackupIs = newLineChar + fold + "Your backup is in folder: " ;
  private static final String messageEnterBackupDescription = newLineChar + fold + "Type your description of the backup!" + newLineChar + fold + "Use ASCII 32-126 characters and max length " + appMaxLengthOfBackupDescription + ": " ;
  private static final String messageBackupHasBeenFinishedSuccessfully = newLineChar + fold + "Your backup has been finished successfully." ;
  private static final String messageNoBackupsHaveBeenFound = newLineChar + fold + "No backups have been found." ;
  private static final String messageOneBackupHasBeenFound = newLineChar + fold + "One backup has been found." ;
  private static final String messageBackupsHaveBeenFound = " backups have been found." ;
  private static final String messageTheBackupCreationHasNotBeenFinishedSuccessfully = newLineChar + fold + " The backup creation has not been finished successfully!" + newLineChar + fold + "Please check the filesystem and repeat this operation." ;
  private static final String messageTooManyBackupsAreThere = newLineChar + fold + "Too many backups are there." + newLineChar + fold + "Please remove the not needed ones." + newLineChar + fold + "The allowed number of backups is maximum: " ;
  private static final String messageTheCountOfAvailableBackupsIs = fold + "The count of available backups is: " ;
  private static final String messageBackupHasBeenDeletedSuccessfully = newLineChar + fold + "Your backup has been deleted successfully." ;
  private static final String messageBackupHasNotBeenDeletedSuccessfully = newLineChar + fold + "Your backup has not been deleted successfully: " ;
  private static final String messageErrorWhileDeletingFile = newLineChar + fold + "Error while deleting file: " ;
  private static final String messageErrorWhileDeletingFolder = newLineChar + fold + "Error while deleting folder: " ;
  private static final String messageSureDeleteBackup1 = newLineChar + fold + "Are you sure want to delete your backup \"" ;
  private static final String messageSureDeleteBackup2 = "\"?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageBackupWontBeDeleted = newLineChar + fold + "OK, the backup won't be deleted." ;
  private static final String messageYourBackedUpFileHasNotBeenFound = newLineChar + fold + "Your backed up file has not been found!" ;
  private static final String messageAllBackupsHaveBeenHandeled = newLineChar + fold + "All of the backups have been handled." ;
  private static final String messageSureDeleteBackups = newLineChar + fold + "Are you sure delete all of your backups?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageBackupsWontBeDeleted = newLineChar + fold + "Ok, your backups will be untouched." ;
  private static final String messageSureBringBackedUpFileAndOverwriteCurrentFile = newLineChar + fold + "Are you sure want to bring backed up file and overwrite your current file?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageFileWontBeOverwrittenByBackedUpFile = newLineChar + fold + "Your file won't be overwritten by backed up file." ;
  private static final String messageYourFileHasBeenRestoredSuccessfully = newLineChar + fold + "Your file has been restored successfully." ;
  private static final String messageUnableToCreateNwFiles = newLineChar + fold + "Unable to create " + appNwPostfix + " files: " ;
  private static final String messageSureRestoreFile1 = newLineChar + fold + "Are you sure want to restore file \"" ;
  private static final String messageSureRestoreFile2 = "\" from backup \"" ;
  private static final String messageSureRestoreFile3 = "\"?" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageFileWontBeRestored = newLineChar + fold + "Ok, your file won't be restored." ;
  private static final String messageFolderIsFile = newLineChar + fold + "The folder is a file: " ;
  private static final String messageFolderDoesNotExist = newLineChar + fold + "The folder doesn't exist: " ;
  private static final String messageSureRestoreFiles = newLineChar + fold + "Are you sure restore all of your files from backup?" + newLineChar + fold + "(note: your current files will be backed up automatically if you type \"yes\")" + newLineChar + fold + messageTypeYesElseAnything ;
  private static final String messageFilesWontBeRestored = newLineChar + fold + "Ok, your files won't be restored from backup." ;
  private static final String messageAllBackedUpFilesHaveBeenHandeled = newLineChar + fold + "All of your backed up files have been handled." ;
  private static final String messageAutomatedBackupBeforeRestoring = "Automated backup before restoring." ;
  private static final String messageUnableToDeleteFile = newLineChar + fold + "Unable to delete file: " ;
  private static final String messageOk = "" + newLineChar + fold + "Ok." ;
  private static final String messageBye = "" + newLineChar + fold + "Bye!" ;
/*
** Variables.
*/
/*
** This folder objects will be used.
*/
  private static File passwordDirFolder = null ;
  private static File adminDirFolder = null ;
  private static File backupDirFolder = null ;
/*
** These objects are existing to store the contents and passwords of file system objects!
*/
// When a password is read from the console.
  private static char [ ] passwordFromInputOriginal = new char [ 0 ] ;
// This is used when the password above has to be verified.
  private static char [ ] passwordFromInputVerified = new char [ 0 ] ;
// This is the object that stores the password for File1.
// (This type of password file is used usually.)
  private static char [ ] passwordForFile1 = new char [ 0 ] ;
// This is the object that stores the password for File2.
// (File2 is used when keys will be moved from a file to a file, this is the type of "to file")
  private static char [ ] passwordForFile2 = new char [ 0 ] ;
// This will store the password to be stored in a file in encrypted format.
  private static char [ ] passwordForKey = new char [ 0 ] ;
// This is the decrypted (readable) formatted content of the File1.
// (Original: this is the working char array.)
  private static char [ ] fileContent1Orig = new char [ 0 ] ;
// This is the decrypted (readable) formatted content of the File1.
// (Trimmed: this is the char array we will save.)
  private static char [ ] fileContent1Trim = new char [ 0 ] ;
// For File2.
  private static char [ ] fileContent2Orig = new char [ 0 ] ;
  private static char [ ] fileContent2Trim = new char [ 0 ] ;
// These are the keys used in this application.
// (key: the name of the password we want to store in encrypted format.)
  private static String key1 = "" ;
  private static String key2 = "" ;
// These are the characters of which kind of passwords we allow to be stored into a file.
  private static char allowPasswordPartsFile1 = spaceChar ;
  private static char allowPasswordPartsFile2 = spaceChar ;
// Byte arrays to store the salts and the initialization vectors of File1 and File2.
  private static byte [ ] sl1 = new byte [ 0 ] ;
  private static byte [ ] iv1 = new byte [ 0 ] ;
  private static byte [ ] sl2 = new byte [ 0 ] ;
  private static byte [ ] iv2 = new byte [ 0 ] ;
// This is the current admin password object.
  private static char [ ] passwordForAdmin = new char [ 0 ] ;
// These are the admin contents. Orig: working, Trim: to be saved char arrays.
  private static char [ ] fileContentAdminOrig = new char [ 0 ] ;
  private static char [ ] fileContentAdminTrim = new char [ 0 ] ;
// Byte arrays to store the salt and initialization vector for the admin content..
  private static byte [ ] slAdmin = new byte [ 0 ] ;
  private static byte [ ] ivAdmin = new byte [ 0 ] ;
/*
** Objects for password caching!
*/
// This variable is to set the caching of admin and files passwords to enabled or disabled.
  private static boolean toCachePasswords = false ;
// These will be the cached file passwords!
  private static HashMap < String , char [ ] > cachedFilePasswords = new HashMap < String , char [ ] > ( ) ;
// This will be the cached admin password!
  private static char [ ] cachedAdminPassword = new char [ 0 ] ;
// This is a date object: if too long time elapsed after
// last password caching or reading then the cached passwords will be forgotten.
  private static Date lastReadOrCacheCachablePassword = new Date ( ) ;
/*
** This method will route the process to the correct method to be executed.
*/
  private static final void letsWork ( String [ ] args )
  {
// The args object (comes from the main method or from interactive mode)
// will be checked and the execution will be headed for the correct
// executeCommand... method.
    if ( args != null )
    {
      if ( args . length == 0 )
      {
        outprintln ( messageNoArguments ) ;
      }
      else if ( args . length == 1 )
      {
        if ( argQuestionMark . equals ( args [ 0 ] . toLowerCase ( ) ) )
        {
          executeCommandHints ( ) ;
        }
        else if ( argHelp . equals ( args [ 0 ] . toLowerCase ( ) ) )
        {
          executeCommandHelp ( ) ;
        }
        else
        {
          usageWrongParameters ( ) ;
        }
      }
      else if ( args . length == 2 )
      {
        if ( argInteractive . equals ( args [ 0 ] . toLowerCase ( ) ) && argMode . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandInteractiveMode ( ) ;
        }
        else if ( argApplication . equals ( args [ 0 ] . toLowerCase ( ) ) && argDescribe . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandApplicationDescribe ( ) ;
        }
        else if ( argApplication . equals ( args [ 0 ] . toLowerCase ( ) ) && argStory . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandApplicationStory ( ) ;
        }
        else if ( argWelcome . equals ( args [ 0 ] . toLowerCase ( ) ) && argScreen . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandWelcomeScreen ( ) ;
        }
        else if ( argGood . equals ( args [ 0 ] . toLowerCase ( ) ) && argPassword . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandGoodPassword ( ) ;
        }
        else if ( argPassword . equals ( args [ 0 ] . toLowerCase ( ) ) && argPart . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandPasswordPart ( ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argList . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileList ( ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argDeleteall . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileDeleteall ( ) ;
        }
        else if ( argAdmin . equals ( args [ 0 ] . toLowerCase ( ) ) && argReview . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandAdminReview ( ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argAdd . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupAdd ( ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argList . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupList ( ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argDeleteall . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupDeleteall ( ) ;
        }
        else
        {
          usageWrongParameters ( ) ;
        }
      }
      else if ( args . length == 3 )
      {
        if ( argClear . equals ( args [ 0 ] . toLowerCase ( ) ) && argScreen . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandClearScreen ( args [ 2 ] ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argSearch . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileSearch ( args [ 2 ] ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argAdd . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileAdd ( args [ 2 ] ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argDescribe . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileDescribe ( args [ 2 ] ) ;
        }
        else if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argDelete . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandFileDelete ( args [ 2 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argList . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyList ( args [ 2 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argAdd . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyAdd ( args [ 2 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argDeleteall . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyDeleteall ( args [ 2 ] ) ;
        }
        else if ( argAdmin . equals ( args [ 0 ] . toLowerCase ( ) ) && argSearch . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandAdminSearch ( args [ 2 ] ) ;
        }
        else if ( argAdmin . equals ( args [ 0 ] . toLowerCase ( ) ) && argPassword . equals ( args [ 1 ] . toLowerCase ( ) ) && argChange . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandAdminPasswordChange ( ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argDelete . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupDelete ( args [ 2 ] ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argRestoreall . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupRestoreall ( args [ 2 ] ) ;
        }
        else
        {
          usageWrongParameters ( ) ;
        }
      }
      else if ( args . length == 4 )
      {
        if ( argFile . equals ( args [ 0 ] . toLowerCase ( ) ) && argPassword . equals ( args [ 1 ] . toLowerCase ( ) ) && argChange . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandFilePasswordChange ( args [ 3 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argSearch . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeySearch ( args [ 2 ] , args [ 3 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argDelete . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyDelete ( args [ 2 ] , args [ 3 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argMoveall . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyMoveall ( args [ 2 ] , args [ 3 ] ) ;
        }
        else if ( argPassword . equals ( args [ 0 ] . toLowerCase ( ) ) && argShow . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandPasswordShow ( args [ 2 ] , args [ 3 ] ) ;
        }
        else if ( argPassword . equals ( args [ 0 ] . toLowerCase ( ) ) && argChange . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandPasswordChange ( args [ 2 ] , args [ 3 ] ) ;
        }
        else if ( argPassword . equals ( args [ 0 ] . toLowerCase ( ) ) && argType . equals ( args [ 1 ] . toLowerCase ( ) ) && argChange . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandPasswordTypeChange ( args [ 3 ] ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argFile . equals ( args [ 1 ] . toLowerCase ( ) ) && argList . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupFileList ( args [ 3 ] ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argFile . equals ( args [ 1 ] . toLowerCase ( ) ) && argSearchall . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupFileSearchall ( args [ 3 ] ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argRestore . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupRestore ( args [ 2 ] , args [ 3 ] ) ;
        }
        else
        {
          usageWrongParameters ( ) ;
        }
      }
      else if ( args . length == 5 )
      {
        if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argChange . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyChange ( args [ 2 ] , args [ 3 ] , args [ 4 ] ) ;
        }
        else if ( argKey . equals ( args [ 0 ] . toLowerCase ( ) ) && argMove . equals ( args [ 1 ] . toLowerCase ( ) ) )
        {
          executeCommandKeyMove ( args [ 2 ] , args [ 3 ] , args [ 4 ] ) ;
        }
        else if ( argBackup . equals ( args [ 0 ] . toLowerCase ( ) ) && argFile . equals ( args [ 1 ] . toLowerCase ( ) ) && argSearch . equals ( args [ 2 ] . toLowerCase ( ) ) )
        {
          executeCommandBackupFileSearch ( args [ 3 ] , args [ 4 ] ) ;
        }
        else
        {
          usageWrongParameters ( ) ;
        }
      }
      else
      {
        usageWrongParameters ( ) ;
      }
    }
    else
    {
      systemexit ( "Error - args is null, letsWork" ) ;
    }
  }
/*
** These methods are to execute the specific commands.
*/
/*
** This enters the user to the interactive mode.
*/
  private static final void executeCommandInteractiveMode ( )
  {
// A welcome message to the user (how to quit).
    outprintln ( messageWelcomeToInteractiveMode ) ;
// This string is for storing the command coming from the user's console.
    String requestString = null ;
// This is the correct args object of the above.
    String [ ] requestParams = null ;
// The interactive mode means that it waits for the user's interaction continuously.
// So an endless loop is required.
    while ( true )
    {
// These are always the first steps:
// clearing the used character and byte arrays to keep the memory safe clean!
      clearCharArrays ( ) ;
      clearByteArrays ( ) ;
// Waiting for the user's input.
      requestString = readiline ( prompt ) ;
// If we have this, we have to validate it. ASCII and not too long input is allowed.
      if ( isASCII ( requestString ) )
      {
// Removing the double spaces.
        while ( requestString . contains ( doubleSpace ) )
        {
          requestString = requestString . replace ( doubleSpace , singleSpace ) ;
        }
// Creating the "args" object.
        requestParams = requestString . split ( singleSpace ) ;
// If this is set then we should clear the cached password if the last
// read date is too long before.
        if ( toCachePasswords )
        {
          cachedPasswordsClearIfOld ( ) ;
        }
// At first we are looking for the interactive mode specific input.
        if ( argExit . equals ( requestString . toLowerCase ( ) ) )
        {
// Exit has typed, we break the while ( true ) loop.
          break ;
        }
        else if ( ( argPasswords + spaceChar + argCache ) . equals ( requestString . toLowerCase ( ) ) )
        {
// Cache password, so we have to do the necessary things:
// Purge of the cached admin and file passwords (but still caching when user types it again),
// toCachePasswords = true and a message.
          toCachePasswords = true ;
          cachedPasswordsIni ( ) ;
          outprintln ( messagePasswordsCacheEnabled ) ;
        }
        else if ( ( argPasswords + spaceChar + argPurge ) . equals ( requestString . toLowerCase ( ) ) )
        {
// Purge password, so we have to do the necessary things:
// Purge of the cached admin and file passwords (and won't cache these any more!)
// toCachePasswords = false and a message.
          toCachePasswords = false ;
          cachedPasswordsIni ( ) ;
          outprintln ( messagePasswordsCacheDisabled ) ;
        }
        else
        {
// Now we can work as being in the main method.
// If the args is fine then give it to the letsWork method.
          if ( isGoodArgsObject ( requestParams ) )
          {
            letsWork ( requestParams ) ;
          }
        }
      }
      else
      {
// If the format of the given input is not good then this message goes to the user.
        usageWrongParameters ( ) ;
      }
// An empty line to be nice.
      outprintln ( "" ) ;
// Again: clearing the used char and byte arrays.
      clearCharArrays ( ) ;
      clearByteArrays ( ) ;
    }
// These have to be zero at this point.
    requestString = null ;
    requestParams = null ;
// And a bye message will be printed to the user.
    outprintln ( messageBye ) ;
  }
/*
** Describes the application as prints the app... variables.
** (description : value in the compiled application.)
*/
  private static final void executeCommandApplicationDescribe ( )
  {
    outprintln ( messageApplicationDescribe ) ;
  }
/*
** Prints the basic contept and considerations of this application.
** (It is not stored in a separate document.)
*/
  private static final void executeCommandApplicationStory ( )
  {
    outprintln ( messageApplicationStory ) ;
  }
/*
** Prints the welcome screen again to the user.
*/
  private static final void executeCommandWelcomeScreen ( )
  {
    outprintln ( messageWelcomeScreen ) ;
  }
/*
** Displays the expectations of the valid and good password to store.
*/
  private static final void executeCommandGoodPassword ( )
  {
    outprintln ( messageGoodPassword ) ;
  }
/*
** Displays the expectations of the storable password parts.
*/
  private static final void executeCommandPasswordPart ( )
  {
    outprintln ( messagePasswordPart ) ;
  }
/*
** Clears the screen!
** This is necessary especially after displaying
** sensitive data such as stored password or admin content.
*/
  private static final void executeCommandClearScreen ( String numOfEmptyLinesToPrintOut )
  {
    int num = Integer . parseInt ( numOfEmptyLinesToPrintOut ) ;
    if ( num > 1 )
    {
      clearScreen ( num ) ;
      outprintln ( messageScreenHasBeenCleared1 + num + messageScreenHasBeenCleared2 ) ;
    }
  }
/*
** Lists the user's password files.
** Only the filename will be listed and the extension is not.
*/
  private static final void executeCommandFileList ( )
  {
    fileListOrSearch ( "" , passwordDirFolder , false ) ;
  }
/*
** Searches for files having the name that matches to toSearch.
** Only the filename will be listed and the extension is not.
*/
  private static final void executeCommandFileSearch ( String toSearch )
  {
    fileListOrSearch ( toSearch , passwordDirFolder , false ) ;
  }
/*
** Adds a password container file.
*/
  private static final void executeCommandFileAdd ( String fileName )
  {
// This has to be valid.
    if ( isValidKeyOrFileName ( fileName , true ) )
    {
// This object will be listed to determine if it is an already existing file.
      File [ ] passwordFiles = passwordDirFolder . listFiles ( ) ;
      if ( passwordFiles != null )
      {
// Not existing by default.
        boolean exists = false ;
// This has to be set to 0 by default.
        int counter = 0 ;
// Looping on the object.
        for ( File passwordFile : passwordFiles )
        {
          if ( passwordFile != null )
          {
            if ( passwordFile . getName ( ) != null )
            {
              if ( passwordFile . isFile ( ) && passwordFile . getName ( ) . endsWith ( appPdPostfix ) )
              {
// We have got a newer one.
                counter ++ ;
                if ( passwordFile . getName ( ) . equals ( fileName + appPdPostfix ) )
                {
// Existing file we have.
                  exists = true ;
                }
              }
            }
            else
            {
              systemexit ( "Error - passwordFile . getName ( ) is null, executeCommandFileAdd" ) ;
            }
          }
          else
          {
            systemexit ( "Error - passwordFile is null, executeCommandFileAdd" ) ;
          }
        }
        if ( counter >= appMaxNumOfFiles )
        {
// Printing to the user that the number of password files has exceeded the limit.
          outprintln ( messageTooManyFiles ) ;
        }
        else if ( exists )
        {
// Printing to the user that the file already exists.
          outprintln ( messageFileAlreadyExists ) ;
        }
        else
        {
// We can create the new file. The admin file is needed.
          if ( isExistingAdminFile ( appAdminFileName , true ) )
          {
// And its valid password.
            readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And the decrypted content of the admin file.
            if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
            {
// Message to the user of the new password!
              outprintln ( messageDoNotForgetYourFilePassword ) ;
// Reading this password of the new file.
              readPassword ( passwordTypeFile1 , true , fileName ) ;
// Creating the content of the new file.
// (1: clearing because we don't know where has been used this char array.)
// (2: creating a new object with that exact size.)
// (3: clearing again to have space characters in this array.)
// (This is the proper way to keep the system memory clear.)
              clearCharArray ( fileContent1Orig ) ;
              fileContent1Orig = new char [ appFileContentMaxLength ] ;
              clearCharArray ( fileContent1Orig ) ;
// Let it be 0.
              counter = 0 ;
// Creating the beginning of the content with filesHeader string.
              for ( int i = 0 ; i < filesHeader . length ( ) ; i ++ )
              {
                fileContent1Orig [ i ] = filesHeader . charAt ( i ) ;
                counter ++ ;
              }
// This is also needed.
// We have to know what kind of password will be stored in this file.
// Password part or whole password.
              readAllowPasswordPartsFile1 ( ) ;
// We can add this information into the content of the file.
              fileContent1Orig [ counter ] = allowPasswordPartsFile1 ;
// A newLineChar is needed to terminate the header information.
              counter ++ ;
              fileContent1Orig [ counter ] = newLineChar ;
// This has been finished, now let's log this event.
// The password of the file will be logged but not stored in string,
// this will be appended into the end of the toLog.
              char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
              clearCharArray ( contentToLog ) ;
              String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogFileAdd + fileName + sep2 ;
              counter = 0 ;
              for ( int i = 0 ; i < Math . min ( contentToLog0 . length ( ) , appMaxLengthToLog ) ; i ++ )
              {
                contentToLog [ i ] = contentToLog0 . charAt ( i ) ;
                counter ++ ;
              }
              for ( int i = contentToLog0 . length ( ) ; i < Math . min ( contentToLog0 . length ( ) + passwordForFile1 . length , appMaxLengthToLog ) ; i ++ )
              {
                contentToLog [ i ] = passwordForFile1 [ i - contentToLog0 . length ( ) ] ;
                counter ++ ;
              }
              contentToLog [ counter ] = newLineChar ;
              doLog ( contentToLog ) ;
              clearCharArray ( contentToLog ) ;
              contentToLog = null ;
              contentToLog0 = null ;
// Trying to save the password file (this is empty, contains only the header.)
              if ( saveFile ( fileName , passwordTypeFile1 ) )
              {
// Trying to save the admin content. (This is because of saving the this last history entry.)
                if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                {
// If we are here then we are successful and a message can go tho the user.
                  outprintln ( messageFileHasBeenCreated ) ;
                }
              }
            }
          }
        }
// These are not used.
        exists = false ;
        counter = 0 ;
      }
      else
      {
        systemexit ( "Error - passwordFiles is null, executeCommandFileAdd" ) ;
      }
// This is not used.
      passwordFiles = null ;
    }
  }
/*
** Describes a file as printing information from the file.
** The file password is required to get this information.
*/
  private static final void executeCommandFileDescribe ( String fileName )
  {
// An existing password file is needed.
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// Reading its password.
      readPassword ( passwordTypeFile1 , false , fileName ) ;
// Decrypting its content to see what's inside.
      if ( getFileContent ( fileName , passwordTypeFile1 ) )
      {
// This is the file object!
        File file = new File ( appPasswordDir + SEP + fileName + appPdPostfix ) ;
        if ( file != null )
        {
// Printing these out.
          outprintln ( messageDescribeFileLastModified + simpleDateFormat . format ( file . lastModified ( ) ) ) ;
          outprintln ( messageDescribeFileSize + Math . round ( file . length ( ) / 1024 ) ) ;
          outprintln ( messageDescribeFileNumOfKeys + getNumOfKeysInContent ( passwordTypeFile1 ) ) ;
          outprintln ( messageDescribeFilePasswordType + ( allowPasswordPartsFile1 == allowPasswordPartsYes ? messageAllowPasswordPartsAndFullPasswords : messageAllowFullPasswordsOnly ) ) ;
        }
        else
        {
          systemexit ( "Error - file is null, executeCommandFileDescribe" ) ;
        }
// This is not used any more.
        file = null ;
      }
    }
  }
/*
** Changing the password of a password container file.
** This is simple: just decrypt the content of the file, ask for a new password
** and simply save the content. (The new password will be used during the encryption.)
*/
  private static final void executeCommandFilePasswordChange ( String fileName )
  {
// An existing file is needed.
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// If it exists then a verification is required from the user.
      if ( readYesElseAnything ( messageSureChangeFilePassword + fileName + messageSure2 , messageFilePasswordWontBeChanged ) )
      {
// The password will be questioned.
        readPassword ( passwordTypeFile1 , false , fileName ) ;
// And the content of the file will be decrypted.
        if ( getFileContent ( fileName , passwordTypeFile1 ) )
        {
// Admin file also needed.
          if ( isExistingAdminFile ( appAdminFileName , true ) )
          {
// The password too to decrypt it.
            readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// Let's see the content of it.
            if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
            {
// A message to the user!
              outprintln ( messageDoNotForgetYourFilePassword ) ;
// Reading the new file password.
              readPassword ( passwordTypeFile1 , true , fileName ) ;
// Let's log this event! The password won't be stored in string.
// This will be appended to the end of the toLog character array.
              char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
              clearCharArray ( contentToLog ) ;
              String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogFilePasswordChange + fileName + sep2 ;
              int counter = 0 ;
              for ( int i = 0 ; i < Math . min ( contentToLog0 . length ( ) , appMaxLengthToLog ) ; i ++ )
              {
                contentToLog [ i ] = contentToLog0 . charAt ( i ) ;
                counter ++ ;
              }
              for ( int i = contentToLog0 . length ( ) ; i < Math . min ( contentToLog0 . length ( ) + passwordForFile1 . length , appMaxLengthToLog ) ; i ++ )
              {
                contentToLog [ i ] = passwordForFile1 [ i - contentToLog0 . length ( ) ] ;
                counter ++ ;
              }
              contentToLog [ counter ] = newLineChar ;
              doLog ( contentToLog ) ;
              clearCharArray ( contentToLog ) ;
              contentToLog = null ;
              contentToLog0 = null ;
// Re-saving the content of the password file (using the new password.)
              if ( saveFile ( fileName , passwordTypeFile1 ) )
              {
// Saving the admin content containing the log entry we have created about the password changing.
                if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                {
// Successfully changed password and logged event!
                  outprintln ( messageFilePasswordHasBeenChanged ) ;
                }
              }
// This is 0 now.
              counter = 0 ;
            }
          }
        }
      }
    }
  }
/*
** Deletes a password file.
*/
  private static final void executeCommandFileDelete ( String fileName )
  {
// The filename must be existing.
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// A confirmation from the user.
      if ( readYesElseAnything ( messageSureDeleteFile + fileName + messageSure2 , messageFileWontBeDeleted ) )
      {
// Existing admin file is needed.
        if ( isExistingAdminFile ( appAdminFileName , true ) )
        {
// The password of the admin content will be prompted.
          readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And the admin content will be decrypted if this password is correct.
          if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
          {
// This is the file object we want to delete.
            File file = new File ( appPasswordDir + SEP + fileName + appPdPostfix ) ;
            if ( file != null )
            {
// Deleting the .pd file first.
              if ( file . delete ( ) )
              {
// Logging this event if the above has happened.
                char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                clearCharArray ( contentToLog ) ;
                String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogFileDelete + fileName + newLineChar ;
                prepareToLog ( contentToLog , contentToLog0 ) ;
                doLog ( contentToLog ) ;
                clearCharArray ( contentToLog ) ;
                contentToLog = null ;
                contentToLog0 = null ;
// Saving the admin content now!
                if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                {
// Ant a message can go to the user, but there are some work to do.
                  outprintln ( messageFileHasBeenDeleted ) ;
// We have to delete the .sl file.
                  File slFile = new File ( appPasswordDir + SEP + fileName + appSlPostfix ) ;
                  if ( slFile . delete ( ) )
                  {
                    outprintln ( messageFileHasBeenDeletedSl ) ;
                  }
                  else
                  {
                    outprintln ( messageFileHasNotBeenDeletedSl ) ;
                  }
// And we have to delete the .iv file as well.
                  File ivFile = new File ( appPasswordDir + SEP + fileName + appIvPostfix ) ;
                  if ( ivFile . delete ( ) )
                  {
                    outprintln ( messageFileHasBeenDeletedIv ) ;
                  }
                  else
                  {
                    outprintln ( messageFileHasNotBeenDeletedIv ) ;
                  }
// Purging the cached password of this file if there is.
                  if ( toCachePasswords )
                  {
                    purgeCachedFilePassword ( fileName ) ;
                  }
// These are releasable.
                  slFile = null ;
                  ivFile = null ;
                }
              }
              else
              {
// If the main .pd file has not been deleted successfully
// then the user gets this message and the event will be not logged.
                outprintln ( messageFileHasNotBeenDeleted ) ;
              }
            }
            else
            {
              systemexit ( "Error - file is null, executeCommandFileDelete" ) ;
            }
// This should be null now.
            file = null ;
          }
        }
      }
    }
  }
/*
** Deletes all of the password container files.
*/
  private static final void executeCommandFileDeleteall ( )
  {
// A validation from the user..
    if ( readYesElseAnything ( messageSureDeleteAllFiles , messageAllFilesAreStillThere ) )
    {
// The existing admin file is needed.
      if ( isExistingAdminFile ( appAdminFileName , true ) )
      {
// Reading its password.
        readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And decrypting its content using the given admin password.
        if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
        {
// Trying to delete all password files.
          if ( deleteAllPasswordContainerFiles ( ) )
          {
// And trying to save the admin content (because of logging.)
            if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
            {
// If we are here then the operation is successfully finished!
              outprintln ( messageAllFilesHaveBeenDeleted ) ;
            }
          }
        }
      }
    }
  }
/*
** Lists all of the keys stored in the file.
*/
  private static final void executeCommandKeyList ( String fileName )
  {
// This is a listing so we add an empty string to the keyListOrSearch.
    keyListOrSearch ( fileName , "" ) ;
  }
/*
** Searches a string in the keys and displays them into the console.
** So this is a filtered listing.
*/
  private static final void executeCommandKeySearch ( String fileName , String toSearch )
  {
// This is a searching so we adding a string to search to the keyListOrSearch.
    keyListOrSearch ( fileName , toSearch ) ;
  }
/*
** Adds a key into a password container file.
** The new key will be appended to the end of the file content.
*/
  private static final void executeCommandKeyAdd ( String fileName )
  {
// The existing files are needed!
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// The password of this file too.
      readPassword ( passwordTypeFile1 , false , fileName ) ;
// We are trying to decrypt its content.
      if ( getFileContent ( fileName , passwordTypeFile1 ) )
      {
// The number of already stored keys is now got.
// We are fine if we can add at least one key into this file.
        if ( getNumOfKeysInContent ( passwordTypeFile1 ) < appMaxNumOfKeysPerFile )
        {
// Getting the index to append the new characters of key\npassword\n.
          int currIndex = getFirstSpaceCharIndexBefore ( fileContent1Orig ) + 1 ;
          if ( filesHeader != null )
          {
// This has to be a nearly good value..
            if ( currIndex >= filesHeader . length ( ) + 1 + 1 )
            {
// Getting the key from the user.
              readKeyFile1 ( ) ;
// This given key has to be not existing!
              if ( getKeyPos ( passwordTypeFile1 , key1 ) == - 1 )
              {
// The admin files are needed.
                if ( isExistingAdminFile ( appAdminFileName , true ) )
                {
// Let's read the user's admin password.
                  readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// Let's decrypt the admin content using this password given before.
                  if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                  {
// We can have a generated password generated by this application.
// If this remains false then the user has to type the password.
                    boolean generated = false ;
                    if ( yes != null )
                    {
// If the user types yes then a generated good password is on the way.
                      if ( yes . equals ( readline ( messageWouldYouLikeToHaveAGeneratedGoodPassword , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
                      {
// Has to be cleared!
                        clearCharArray ( passwordForKey ) ;
                        passwordForKey = null ;
// This can now point into a good generated password!
                        passwordForKey = getGeneratedGoodPassword ( ) ;
// So this is a generated password.
                        generated = true ;
                      }
                      else
                      {
// The user has typed not "yes" so the password has to be read from the console.
                        readPassword ( passwordTypeKey , true , "" ) ;
// So this is not a generated password.
                        generated = false ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - yes is null (1), executeCommandKeyAdd" ) ;
                    }
                    if ( passwordForKey == null )
                    {
                      systemexit ( "Error, passwordForKey is null, executeCommandKeyAdd" ) ;
                    }
                    else if ( passwordForKey . length == 0 )
                    {
                      systemexit ( "Error, passwordForKey is empty, executeCommandKeyAdd" ) ;
                    }
                    if ( key1 != null )
                    {
// Let's add the key first.
                      for ( int i = 0 + currIndex ; i < key1 . length ( ) + currIndex ; i ++ )
                      {
                        fileContent1Orig [ i ] = key1 . charAt ( i - currIndex ) ;
                      }
// The new line character is the next separating the key from the password.
                      currIndex = currIndex + key1 . length ( ) ;
                      fileContent1Orig [ currIndex ] = newLineChar ;
// Increase this to continue.
                      currIndex ++ ;
// Now we can start the inserting of the password.
                      for ( int i = 0 + currIndex ; i < passwordForKey . length + currIndex ; i ++ )
                      {
                        fileContent1Orig [ i ] = passwordForKey [ i - currIndex ] ;
                      }
// The ending new line char is needed.
                      currIndex = currIndex + passwordForKey . length ;
                      fileContent1Orig [ currIndex ] = newLineChar ;
// If it has been generated, we can show it to the user if requested.
                      if ( generated )
                      {
                        if ( yes != null )
                        {
                          if ( yes . equals ( readline ( messageWouldYouLikeToReadYourGeneratedGoodPassword , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
                          {
// A password show will be performed if we are here.
                            passwordShowFile1 ( key1 ) ;
                          }
                        }
                        else
                        {
                          systemexit ( "Error - yes is null (2), executeCommandKeyAdd" ) ;
                        }
                      }
// The operation has been finished so we can log this event.
                      char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                      clearCharArray ( contentToLog ) ;
                      String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogKeyAdd + fileName + sep1 + key1 + sep2 ;
                      int counter = 0 ;
                      for ( int i = 0 ; i < Math . min ( contentToLog0 . length ( ) , appMaxLengthToLog ) ; i ++ )
                      {
                        contentToLog [ i ] = contentToLog0 . charAt ( i ) ;
                        counter ++ ;
                      }
                      for ( int i = contentToLog0 . length ( ) ; i < Math . min ( contentToLog0 . length ( ) + passwordForKey . length , appMaxLengthToLog ) ; i ++ )
                      {
                        contentToLog [ i ] = passwordForKey [ i - contentToLog0 . length ( ) ] ;
                        counter ++ ;
                      }
                      contentToLog [ counter ] = newLineChar ;
                      doLog ( contentToLog ) ;
                      clearCharArray ( contentToLog ) ;
                      contentToLog = null ;
                      contentToLog0 = null ;
// The final step is to save all of this.
                      if ( saveFile ( fileName , passwordTypeFile1 ) )
                      {
                        if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                        {
// Successful, message to the user.
                          outprintln ( messageKeyHasBeenAdded ) ;
                        }
                      }
                    }
                    else
                    {
                      systemexit ( "Error - key1 is null, executeCommandKeyAdd" ) ;
                    }
// This can be set to false.
                    generated = false ;
                  }
                }
              }
              else
              {
// Existing key cannot be inserted!
                outprintln ( messageNewKeyAlreadyExists ) ;
              }
            }
            else
            {
              systemexit ( "Error - currIndex is negative, executeCommandKeyAdd" ) ;
            }
          }
          else
          {
            systemexit ( "Error - filesHeader is null, executeCommandKeyAdd" ) ;
          }
// This can be set to zero.
          currIndex = 0 ;
        }
        else
        {
// We cannot append a new key because this file is full.
          outprintln ( messageTooManyKeysInFile ) ;
        }
      }
    }
  }
/*
** Changes a key in a file. The password belong to this key will be untouched.
*/
  private static final void executeCommandKeyChange ( String fileName , String currentKeyName , String newKeyName )
  {
// These key names have to be valid.
    if ( isValidKeyOrFileName ( currentKeyName , true ) && isValidKeyOrFileName ( newKeyName , true ) )
    {
// The key names have to be different!
      if ( ! currentKeyName . equals ( newKeyName ) )
      {
// And this file has to be existing.
        if ( isExistingPasswordFile ( fileName , true ) )
        {
// Let's read the file password.
          readPassword ( passwordTypeFile1 , false , fileName ) ;
// We have to have the decrypted content of the file!
          if ( getFileContent ( fileName , passwordTypeFile1 ) )
          {
// The indexes of the current key position and the new key position.
            int currentKeyPos = getKeyPos ( passwordTypeFile1 , currentKeyName ) ;
            int newKeyPos = getKeyPos ( passwordTypeFile1 , newKeyName ) ;
// The current name has to be existing and the new key name has to be not existing!
            if ( currentKeyPos == - 1 )
            {
              outprintln ( messageKeyIsNotFound ) ;
            }
            else if ( newKeyPos != - 1 )
            {
              outprintln ( messageNewKeyAlreadyExists ) ;
            }
            else
            {
// A confirmation is needed by the user.
              if ( readYesElseAnything ( messageSureChangeKey + currentKeyName + messageSure2 , messageKeyWontBeChanged ) )
              {
// The admin file is needed.
                if ( isExistingAdminFile ( appAdminFileName , true ) )
                {
// And its valid password.
                  readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And its decrypted content.
                  if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                  {
// Now the changing can be started. Setting the two parameter of the shiftFileContent.
                    int toMoveFromPos = currentKeyPos + currentKeyName . length ( ) ;
                    int toMoveDiff = newKeyName . length ( ) - currentKeyName . length ( ) ;
// Let's move it if we should.
                    if ( toMoveDiff != 0 )
                    {
                      shiftFileContent ( passwordTypeFile1 , toMoveFromPos , toMoveDiff ) ;
                    }
// Now the space of the new key is ready. Fill this space by the chars of the new key.
// (Remember, the password will be still the same!)
                    for ( int i = 0 ; i < newKeyName . length ( ) ; i ++ )
                    {
                      fileContent1Orig [ i + currentKeyPos ] = newKeyName . charAt ( i ) ;
                    }
// Let's log this key changing event.
                    char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                    clearCharArray ( contentToLog ) ;
                    String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogKeyChange + fileName + sep1 + currentKeyName + sep2 + newKeyName + newLineChar ;
                    prepareToLog ( contentToLog , contentToLog0 ) ;
                    doLog ( contentToLog ) ;
                    clearCharArray ( contentToLog ) ;
                    contentToLog = null ;
                    contentToLog0 = null ;
// We are ready for the final saving.
                    if ( saveFile ( fileName , passwordTypeFile1 ) )
                    {
                      if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                      {
// The key changing operation has been successfully finished.
                        outprintln ( messageKeyHasBeenChanged ) ;
                      }
                    }
// These two can be set to zero.
                    toMoveFromPos = 0 ;
                    toMoveDiff = 0 ;
                  }
                }
              }
            }
// These two too.
            newKeyPos = 0 ;
            currentKeyPos = 0 ;
          }
        }
      }
      else
      {
// Message because the user because of the same key names.
        outprintln ( messageNewKeyNameHaveToBeDifferent ) ;
      }
    }
  }
/*
** Deletes a key from a file.
*/
  private static final void executeCommandKeyDelete ( String fileName , String key )
  {
// Valid key is needed.
    if ( isValidKeyOrFileName ( key , true ) )
    {
// And an existing password file too.
      if ( isExistingPasswordFile ( fileName , true ) )
      {
// Reading its password.
        readPassword ( passwordTypeFile1 , false , fileName ) ;
// We can move on if we have the successfully decrypted content of this file.
        if ( getFileContent ( fileName , passwordTypeFile1 ) )
        {
// The position of the key is requested in the file.
          int keyPos = getKeyPos ( passwordTypeFile1 , key ) ;
// This should be -1 otherwise the key doesn't exist.
          if ( keyPos != - 1 )
          {
// The user has to confirm the key deleting.
            if ( readYesElseAnything ( messageSureDeleteKey + key + messageSure2 , messageKeyIsStillThere ) )
            {
// The admin files are needed.
              if ( isExistingAdminFile ( appAdminFileName , true ) )
              {
// Now let's ask for the user to type the admin password.
                readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// The successfully decrypted admin content is needed.
                if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                {
// We can delete the key now.
                  char [ ] deletedContent = keyDelete ( passwordTypeFile1 , key , keyPos , fileName ) ;
                  if ( deletedContent != null )
                  {
                    if ( deletedContent . length > 0 )
                    {
// Saving this operation.
                      if ( saveFile ( fileName , passwordTypeFile1 ) )
                      {
                        if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                        {
// This is a successfully key deleting, let's tell to the user.
                          outprintln ( messageKeyHasBeenDeleted ) ;
                        }
                      }
                    }
                    else
                    {
                      systemexit ( "Error - deletedContent is empty, executeCommandKeyDelete" ) ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - deletedContent is null, executeCommandKeyDelete" ) ;
                  }
// This should be cleared as it contains sensitive data!
                  clearCharArray ( deletedContent ) ;
                  deletedContent = null ;
                }
              }
            }
          }
          else
          {
// The key pos was -1 before so the key is not found in the decrypted content.
            outprintln ( messageKeyIsNotFound ) ;
          }
// This can be set to 0.
          keyPos = 0 ;
        }
      }
    }
  }
/*
** Delete all of the stored keys in a password container file.
** We don't care about how many passwords are there in the file.
*/
  private static final void executeCommandKeyDeleteall ( String fileName )
  {
// Existing password file is the condition to moving on
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// Reading its password.
      readPassword ( passwordTypeFile1 , false , fileName ) ;
// Only if we have decrypted successfully the content of the password file
      if ( getFileContent ( fileName , passwordTypeFile1 ) )
      {
// A confirmation is needed from the user.
        if ( readYesElseAnything ( messageSureDeleteKeys , messageKeysAreStillThere ) )
        {
// The admin file will be searched for.
          if ( isExistingAdminFile ( appAdminFileName , true ) )
          {
// The password of the admin content will be prompted.
            readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// Have we got the decrypted admin content?
            if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
            {
              if ( filesHeader != null )
              {
// This is the index of the character which is before the last space.
                int lastNonSpaceCharIndexOrig = getFirstSpaceCharIndexBefore ( fileContent1Orig ) ;
// Only if we have any characters to delete.
                if ( lastNonSpaceCharIndexOrig > filesHeader . length ( ) - 1 + 1 + 1 )
                {
// The characters of header line and the stored password type have to be not deleted!
                  for ( int i = filesHeader . length ( ) + 1 + 1 ; i <= lastNonSpaceCharIndexOrig ; i ++ )
                  {
                    fileContent1Orig [ i ] = spaceChar ;
                  }
// Let's log this event.
                  char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                  clearCharArray ( contentToLog ) ;
                  String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogKeysDelete + fileName + newLineChar ;
                  prepareToLog ( contentToLog , contentToLog0 ) ;
                  doLog ( contentToLog ) ;
                  clearCharArray ( contentToLog ) ;
                  contentToLog = null ;
                  contentToLog0 = null ;
// Let's save this modification.
                  if ( saveFile ( fileName , passwordTypeFile1 ) )
                  {
                    if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                    {
// If we are here then the key deleting and the saving operations have been successful.
                      outprintln ( messageKeysHasBeenDeleted ) ;
                    }
                  }
// This is not usable from now.
                  lastNonSpaceCharIndexOrig = 0 ;
                }
                else
                {
                  outprintln ( messageFileDoesNotContainAnyKey ) ;
                }
              }
              else
              {
                systemexit ( "Error - filesHeader is null, executeCommandKeyDeleteall" ) ;
              }
            }
          }
        }
      }
    }
  }
/*
** Moves a key from a file into another.
*/
  private static final void executeCommandKeyMove ( String currentFileName , String newFileName , String key )
  {
// A valid key is needed.
    if ( isValidKeyOrFileName ( key , true ) )
    {
// The current file must be existing.
      if ( isExistingPasswordFile ( currentFileName , true ) )
      {
// And the new file too.
        if ( isExistingPasswordFile ( newFileName , true ) )
        {
// The current and the new files have to be different!
          if ( ! currentFileName . equals ( newFileName ) )
          {
// Read the passwords of the two files.
            outprintln ( messagePasswordFromFile + currentFileName ) ;
            readPassword ( passwordTypeFile1 , false , currentFileName ) ;
            outprintln ( messagePasswordIntoFile + newFileName ) ;
            readPassword ( passwordTypeFile2 , false , newFileName ) ;
// The content of the first file has to be decrypted.
            if ( getFileContent ( currentFileName , passwordTypeFile1 ) )
            {
// The content of the second file too.
              if ( getFileContent ( newFileName , passwordTypeFile2 ) )
              {
// The files have to be compatible!
                if ( allowPasswordPartsFile1 == allowPasswordPartsFile2 )
                {
// A confirmation is needed from the user.
                  if ( readYesElseAnything ( messageSureMoveKey + key + messageSure2 , messageKeyIsStillThere ) )
                  {
// The admin file has to be existing!
                    if ( isExistingAdminFile ( appAdminFileName , true ) )
                    {
// Reading the password to the admin content.
                      readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// The content of admin file has to be decrypted successfully.
                      if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                      {
// If we are here then we can move now the given key.
// (The keyMove method will be called as to save the operation.)
                        keyMove ( currentFileName , newFileName , key , true ) ;
                      }
                    }
                  }
                }
                else
                {
// The type of the storable password have to be the same!
                  outprintln ( messageIncompatibleFiles ) ;
                }
              }
            }
          }
          else
          {
// The two files have to be different!
            outprintln ( messageFilesHaveToBeDifferent ) ;
          }
        }
      }
    }
  }
/*
** Moves all of the keys possible to move contained by a file into another.
*/
  private static final void executeCommandKeyMoveall ( String currentFileName , String newFileName )
  {
// The current file must be existing.
    if ( isExistingPasswordFile ( currentFileName , true ) )
    {
// The new file must be existing.
      if ( isExistingPasswordFile ( newFileName , true ) )
      {
// The current and the new file must be different! Else message to the user!
        if ( ! currentFileName . equals ( newFileName ) )
        {
// Reading the password of the current file.
          outprintln ( messagePasswordFromFile + currentFileName ) ;
          readPassword ( passwordTypeFile1 , false , currentFileName ) ;
// The content has to be successfully decrypted!
          if ( getFileContent ( currentFileName , passwordTypeFile1 ) )
          {
// The current file has to contain at least one key. Else message to the user!
            if ( getNumOfKeysInContent ( passwordTypeFile1 ) > 0 )
            {
// Then the password of the new file will be requested
              outprintln ( messagePasswordIntoFile + newFileName ) ;
              readPassword ( passwordTypeFile2 , false , newFileName ) ;
// It has to be successfully decrypted too.
              if ( getFileContent ( newFileName , passwordTypeFile2 ) )
              {
// The type of the storable passwords has to be the same in the two files.
// Else the user gets a message.
                if ( allowPasswordPartsFile1 == allowPasswordPartsFile2 )
                {
// A confirmation is needed from the user.
                  if ( readYesElseAnything ( messageSureMoveKeys , messageKeysAreStillThere ) )
                  {
// The admin file will be searched for.
                    if ( isExistingAdminFile ( appAdminFileName , true ) )
                    {
// And the password will be read if it is found.
                      readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// The admin content has to be successfully decrypted!
                      if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                      {
// We are ready to move the keys from a file into the new file.
// This is the keys contained by the file we want to move from.
                        ArrayList < String > keys = getSortedKeyList ( passwordTypeFile1 , "" ) ;
                        if ( keys != null )
                        {
// This is just for the first empty line printing now.
                          int counter = 0 ;
// Looping on the list of keys.
                          for ( String aKey : keys )
                          {
// Empty line will be printed if this is the first case.
                            if ( counter == 0 )
                            {
                              outprintln ( "" ) ;
                            }
// Trying to move the current key.
                            keyMove ( currentFileName , newFileName , aKey , false ) ;
// This has to be incremented.
                            counter ++ ;
                          }
// The loop is over so we have to save the modifications.
// (The keyMove method has been called as not to save the operation.)
                          if ( saveFile ( newFileName , passwordTypeFile2 ) && saveFile ( currentFileName , passwordTypeFile1 ) )
                          {
                            if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                            {
// If we are here then the operation has been successful so a message will be shown on the console.
                              outprintln ( messageKeysHasBeenHandled ) ;
                            }
                          }
// This should be cleared.
                          keys . clear ( ) ;
                        }
                        else
                        {
                          systemexit ( "Error - keys is null, executeCommandKeyMoveall" ) ;
                        }
// This can be point to nowhere.
                        keys = null ;
                      }
                    }
                  }
                }
                else
                {
// The types of the storable passwords don't equal in the two files.
                  outprintln ( messageIncompatibleFiles ) ;
                }
              }
            }
            else
            {
// We have wanted to move from an empty file.
              outprintln ( messageFromFileEmpty ) ;
            }
          }
        }
        else
        {
// Moving is possible into a different file!
          outprintln ( messageFilesHaveToBeDifferent ) ;
        }
      }
    }
  }
/*
** Shows the password of a key stored in a password container file.
*/
  private static final void executeCommandPasswordShow ( String fileName , String key )
  {
// Valid key is needed
    if ( isValidKeyOrFileName ( key , true ) )
    {
// And an existing password container file too.
      if ( isExistingPasswordFile ( fileName , true ) )
      {
// Reading its password.
        readPassword ( passwordTypeFile1 , false , fileName ) ;
// And trying to decrypt its content.
        if ( getFileContent ( fileName , passwordTypeFile1 ) )
        {
// If we are here then we can continue to show the password.
          passwordShowFile1 ( key ) ;
        }
      }
    }
  }
/*
** Changes the password of a key stored in a password container file.
*/
  private static final void executeCommandPasswordChange ( String fileName , String key )
  {
// The key has to be valid.
    if ( isValidKeyOrFileName ( key , true ) )
    {
// The file has to be existing.
      if ( isExistingPasswordFile ( fileName , true ) )
      {
// Reading the password of the password container file.
        readPassword ( passwordTypeFile1 , false , fileName ) ;
// Trying to get the decrypted content of the file.
        if ( getFileContent ( fileName , passwordTypeFile1 ) )
        {
// This is the position of the key.
          int keyPos = getKeyPos ( passwordTypeFile1 , key ) ;
// And it has to be greater than -1 because it means that the key does not exist in this file.
          if ( keyPos != - 1 )
          {
// The user has to confirm the wish to modify the password.
            if ( readYesElseAnything ( messageSureChangePassword , messagePasswordWontBeChanged ) )
            {
// Now we are looking for the admin file.
              if ( isExistingAdminFile ( appAdminFileName , true ) )
              {
// If it is existing then its admin password is needed.
                readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// We have the admin password so we trying to decrypt it.
                if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                {
// If we are here then everything are ready to do the password changing.
                  outprintln ( messageChangePasswordAtLeast3Digits ) ;
// It is possible to generate a good password by this application.
                  boolean generated = false ;
// The user wants it or not.
                  if ( yes . equals ( readline ( messageWouldYouLikeToHaveAGeneratedGoodPassword , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
                  {
// Let it be cleared, important!
                    clearCharArray ( passwordForKey ) ;
                    passwordForKey = null ;
// The char array of the key password is to be replaced by a new password generated by this application.
                    passwordForKey = getGeneratedGoodPassword ( ) ;
// Yes, we have a generated password now.
                    generated = true ;
                  }
                  else
                  {
// Reading the password from the user, from the console.
                    readPassword ( passwordTypeKey , true , "" ) ;
// We have a password not generated by the application
                    generated = false ;
                  }
// This is the position of the password. This is after the key and a newLineChar.
                  int passwordPos = keyPos + key . length ( ) + 1 ;
// We are searching for the next key position.
// Between passwordPos and nextKeyPos is the actual password we want to change.
                  int nextKeyPos = - 1 ;
// Searching for the position of the next key. This after the next newLineChar.
// (The above also works when this is the last key.)
                  for ( int i = passwordPos ; i < fileContent1Orig . length ; i ++ )
                  {
                    if ( fileContent1Orig [ i ] == newLineChar )
                    {
                      nextKeyPos = i + 1 ;
                      break ;
                    }
                  }
// Here we have the exact location of the password in the content.
// Now we are going to shift the content from this pos. (the very next newLineChar after the password.)
                  int toMoveFromPos = nextKeyPos - 1 ;
// This number is the difference: the shifting will be happened to this difference.
                  int toMoveDiff = passwordForKey . length - ( nextKeyPos - passwordPos - 1 ) ;
// Shifting only if this is not zero.
// Otherwise we will replace the characters of the currently stored password
// to the chars of the newly typed password.
                  if ( toMoveDiff != 0 )
                  {
                    shiftFileContent ( passwordTypeFile1 , toMoveFromPos , toMoveDiff ) ;
                  }
// And now we have the space to write the new password into.
                  for ( int i = 0 ; i < passwordForKey . length ; i ++ )
                  {
                    fileContent1Orig [ i + passwordPos ] = passwordForKey [ i ] ;
                  }
// This is here because the new password has to be written into the content first.
// If this has been a newly generated password then now we can show it to the user.
                  if ( generated )
                  {
// Of course the "yes" is expected.
                    if ( yes . equals ( readline ( messageWouldYouLikeToReadYourGeneratedGoodPassword , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
                    {
// Showing the password to the user. like it would be a password show.
                      passwordShowFile1 ( key ) ;
                    }
                  }
// Let's log this password change event!
                  char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                  clearCharArray ( contentToLog ) ;
                  String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogPasswordChange + fileName + sep1 + key + sep2 ;
                  int counter = 0 ;
                  for ( int i = 0 ; i < Math . min ( contentToLog0 . length ( ) , appMaxLengthToLog ) ; i ++ )
                  {
                    contentToLog [ i ] = contentToLog0 . charAt ( i ) ;
                    counter ++ ;
                  }
                  for ( int i = contentToLog0 . length ( ) ; i < Math . min ( contentToLog0 . length ( ) + passwordForKey . length , appMaxLengthToLog ) ; i ++ )
                  {
                    contentToLog [ i ] = passwordForKey [ i - contentToLog0 . length ( ) ] ;
                    counter ++ ;
                  }
                  contentToLog [ counter ] = newLineChar ;
                  doLog ( contentToLog ) ;
                  clearCharArray ( contentToLog ) ;
                  contentToLog = null ;
                  contentToLog0 = null ;
// Finally this is the saving operation to complete the password changing.
                  if ( saveFile ( fileName , passwordTypeFile1 ) )
                  {
                    if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                    {
// The contents of the file and of the admin have been saved so we can write it to the user.
                      outprintln ( messagePasswordHasBeenChanged ) ;
                    }
                  }
// These are no longer used.
                  generated = false ;
                  toMoveFromPos = 0 ;
                  toMoveDiff = 0 ;
                  passwordPos = 0 ;
                  nextKeyPos = 0 ;
                }
              }
            }
          }
          else
          {
// This is the case of not found key, let's print it to the user.
            outprintln ( messageKeyIsNotFound ) ;
          }
// This will be no longer used.
          keyPos = 0 ;
        }
      }
    }
  }
/*
** Changes the type of the storable passwords in a file.
** This can be one of the two types:
** - it is allowed to store password parts in a file. (y)
** - or not. (n)
*/
  private static final void executeCommandPasswordTypeChange ( String fileName )
  {
// The file will be searched for at first.
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// Then its password is needed.
      readPassword ( passwordTypeFile1 , false , fileName ) ;
// If the content of the file is decrypted successfully..
      if ( getFileContent ( fileName , passwordTypeFile1 ) )
      {
// In this char we will store the current value of this attribute.
// (named it old because later this will be the old value.)
        char allowPasswordPartsFile1Old = allowPasswordPartsFile1 ;
// Now we are going to read this new value.
        readAllowPasswordPartsFile1 ( ) ;
// A new value is expected.. else the user will be notified.
        if ( allowPasswordPartsFile1Old != allowPasswordPartsFile1 )
        {
// We will count the passwords that will be incorrect in case of password type changing.
// For example: password parts store attribute in a file: y
// and there is a password in this: "uk8"
// This is possible since when in the case of allow password parts it is possible to store
// strings as passwords that may be not valid by good password validation.
// If this attribute will be changed to n then some passwords may be not valid because
// in case of y the passwords have to be valid as good passwords.
// This is zero by default.
          int counter = 0 ;
// So, if this file has at least one password and the direction of this changing is "y" -> "n"
          if ( getNumOfKeysInContent ( passwordTypeFile1 ) > 0 && allowPasswordPartsFile1 == allowPasswordPartsNo )
          {
// What are the keys in this file?
            ArrayList < String > keys = getSortedKeyList ( passwordTypeFile1 , "" ) ;
            if ( keys != null )
            {
// This is a temporary reference pointing to the current password.
              char [ ] aPassword = null ;
// Let's loop on this list.
              for ( String aKey : keys )
              {
                if ( aKey != null )
                {
// This will be the current password.
                  aPassword = getKeyPasswordFile1 ( aKey ) ;
                  if ( aPassword != null )
                  {
// We will validate this password!
                    if ( ! isValidGoodPassword ( aPassword , false ) )
                    {
// For formatting..
                      if ( counter == 0 )
                      {
                        outprintln ( "" ) ;
                      }
// This key of this password will be not valid
// if we change the types of the stored passwords to "n"
// So we are going to print this key to the user.
                      outprintln ( messageKeyHasNotValidGoodPassword + aKey ) ;
// Plus one wrong password in case of "n"
                      counter ++ ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - aPassword is null, executeCommandPasswordTypeChange" ) ;
                  }
// This have to be cleared!
                  clearCharArray ( aPassword ) ;
                  aPassword = null ;
                }
                else
                {
                  systemexit ( "Error - aKey is null, executeCommandPasswordTypeChange" ) ;
                }
              }
// The keys are no longer necessary.
              keys . clear ( ) ;
            }
            else
            {
              systemexit ( "Error - keys is null, executeCommandPasswordTypeChange" ) ;
            }
// We will drop it.
            keys = null ;
          }
// The counter has to be zero to continue.
          if ( counter == 0 )
          {
// This is a final confirmation from the user.
            if ( readYesElseAnything ( messageSureChangeTypeOfPasswors , "" + newLineChar + messageTypeOfPasswordsWontBeChanged ) )
            {
// The admin files are needed.
              if ( isExistingAdminFile ( appAdminFileName , true ) )
              {
// Passwords will be asked.
                readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// The content of the admin file will be decrypted.
                if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                {
// This is the modification.
// Change the character of the original content to the new char.
                  fileContent1Orig [ filesHeader . length ( ) ] = allowPasswordPartsFile1 ;
// Let's log this event.
                  char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                  clearCharArray ( contentToLog ) ;
                  String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogPasswordTypeChange + fileName + sep2 + allowPasswordPartsFile1 + newLineChar ;
                  prepareToLog ( contentToLog , contentToLog0 ) ;
                  doLog ( contentToLog ) ;
                  clearCharArray ( contentToLog ) ;
                  contentToLog = null ;
                  contentToLog0 = null ;
// Now we have to save the file and the admin content.
// (file: because of modification, admin: because of logging.)
                  if ( saveFile ( fileName , passwordTypeFile1 ) )
                  {
                    if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                    {
// If we are here, all changes have been made successfully,
// message is on the way to the user.
                      outprintln ( messageTypeOfStorablePasswordsHasBeenChanged ) ;
                    }
                  }
                }
              }
            }
          }
          else
          {
// The counter is not zero, so just a final message goes to the user.
            outprintln ( messageTypeOfPasswordsWontBeChanged ) ;
          }
// This will be not used.
          counter = 0 ;
        }
        else
        {
// A message to the user: a new value has to be typed!
          outprintln ( messageThePasswordTypeHasAlreadySetToThis ) ;
        }
// This is newer gonna be used.
        allowPasswordPartsFile1Old = spaceChar ;
      }
    }
  }
/*
** Admin search: the toSearch string will be searched for  in the lines of content admin.
** Only the matched lines will be printed onto the console.
*/
  private static final void executeCommandAdminSearch ( String toSearch )
  {
    adminReviewOrSearch ( toSearch ) ;
  }
/*
** Admin review: all of the admin content will be shown in case of the correct admin password.
*/
  private static final void executeCommandAdminReview ( )
  {
    adminReviewOrSearch ( "" ) ;
  }
/*
** It changes the admin password.
** Changing this means only to decrypt the admin content using the current admin password
** and then to ask a new admin password and to save (to encrypt) the content with the
** new admin password.
*/
  private static final void executeCommandAdminPasswordChange ( )
  {
// Existing admin files are needed.
    if ( isExistingAdminFile ( appAdminFileName , true ) )
    {
// Then a confirmation is needed. (User has to type: yes.)
      if ( readYesElseAnything ( messageSureChangeAdminPassword , messageAdminPasswordWontBeChanged ) )
      {
// The current admin password will be questioned.
        readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
        if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
        {
// Message again: don't forget the password.
          outprintln ( messageDoNotForgetYourAdminPassword ) ;
// User has to type the new admin password.
          readPassword ( passwordTypeAdmin , true , appAdminFileName ) ;
// Log this event: the admin password has been changed.
// (The admin password doesn't go to the log.)
          char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
          clearCharArray ( contentToLog ) ;
          String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogAdminPasswordChange + newLineChar ;
          prepareToLog ( contentToLog , contentToLog0 ) ;
          doLog ( contentToLog ) ;
          clearCharArray ( contentToLog ) ;
          contentToLog = null ;
          contentToLog0 = null ;
// Save the admin content and this is done. (With the new password at this point.)
          if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
          {
            outprintln ( messageAdminPasswordHasBeenChanged ) ;
          }
        }
      }
    }
  }
/*
** Lists the backups made before of password container files.
*/
  private static final void executeCommandBackupList ( )
  {
    backupListOrFileSearch ( "" ) ;
  }
/*
** Creates a backup of the current state of all of password container files.
*/
  private static final void executeCommandBackupAdd ( )
  {
// Existing admin files are needed.
    if ( isExistingAdminFile ( appAdminFileName , true ) )
    {
// Then a confirmation is needed. (User has to type: yes.)
      if ( readYesElseAnything ( messageSureMakeBackup , messageBackupWontBeMade ) )
      {
// The current admin password will be questioned.
        readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
        if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
        {
// Reading the short description of the backup
          String description = readBackupDescription ( ) ;
// Doing the backup
          if ( addBackup ( description ) )
          {
// Saving the admin content.
            if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
            {
// This operation has been finished successfully, message is going to the user!
              outprintln ( messageBackupHasBeenFinishedSuccessfully ) ;
            }
          }
// This can be null.
          description = null ;
        }
      }
    }
  }
/*
** Deletes a backup made before.
*/
  private static final void executeCommandBackupDelete ( String backupName )
  {
// valid name is required!
    if ( isValidKeyOrFileName ( backupName , true ) )
    {
// Existing backup is needed.
      if ( isExistingFolder ( appBackupDir + SEP + backupName , true ) )
      {
// Existing admin files are needed.
        if ( isExistingAdminFile ( appAdminFileName , true ) )
        {
// Then a confirmation is needed. (User has to type: yes.)
          if ( readYesElseAnything ( messageSureDeleteBackup1 + backupName + messageSureDeleteBackup2 , messageBackupWontBeDeleted ) )
          {
// The current admin password will be questioned.
            readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
            if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
            {
// Trying to delete the backup
              if ( deleteBackup ( backupName ) )
              {
// Trying to save the admin content
                if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                {
// This operation has been finished successfully, message is going to the user!
                  outprintln ( messageBackupHasBeenDeletedSuccessfully ) ;
                }
              }
            }
          }
        }
      }
    }
  }
/*
** Deletes all of the backups have ever made.
*/
  private static final void executeCommandBackupDeleteall ( )
  {
// We need a not null backupDirFolder!
    if ( backupDirFolder != null )
    {
// We need an existing backupDirFolder!
      if ( backupDirFolder . exists ( ) )
      {
// This object will be looped.
        File [ ] backupFolders = backupDirFolder . listFiles ( ) ;
        if ( backupFolders != null )
        {
// .. if there is something in this.
          if ( backupFolders . length > 0 )
          {
// Existing admin files are needed.
            if ( isExistingAdminFile ( appAdminFileName , true ) )
            {
// Then a confirmation is needed. (User has to type: yes.)
              if ( readYesElseAnything ( messageSureDeleteBackups , messageBackupsWontBeDeleted ) )
              {
// The current admin password will be questioned.
                readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
                if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
                {
                  for ( File backupFolder : backupFolders )
                  {
                    if ( backupFolder != null )
                    {
                      if ( ! deleteBackup ( backupFolder . getName ( ) ) )
                      {
                        systemexit ( "Error - deleteBackup is false!, executeCommandBackupDeleteall" ) ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - backupFolder is null, executeCommandBackupDeleteall" ) ;
                    }
                  }
                  if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                  {
// This operation has been finished successfully, message is going to the user!
                    outprintln ( messageAllBackupsHaveBeenHandeled ) ;
                  }
                }
              }
            }
          }
          else
          {
            outprintln ( messageNoBackupsHaveBeenFound ) ;
          }
        }
        else
        {
          systemexit ( "Error - backupFolders is null, executeCommandBackupDeleteall" ) ;
        }
        backupFolders = null ;
      }
      else
      {
        systemexit ( "Error - backupDirFolder is not existing, executeCommandBackupDeleteall" ) ;
      }
    }
    else
    {
      systemexit ( "Error - backupDirFolder is null, executeCommandBackupDeleteall" ) ;
    }
  }
/*
** Lists the files in a backup.
*/
  private static final void executeCommandBackupFileList ( String backupName )
  {
    if ( isValidKeyOrFileName ( backupName , true ) )
    {
// This folder is to be listed.
      if ( isExistingFolder ( appBackupDir + SEP + backupName , true ) )
      {
// Let's list this folder.
        fileListOrSearch ( "" , new File ( appBackupDir + SEP + backupName ) , true ) ;
      }
    }
  }
/*
** Lists the files in a backup filtered by .
*/
  private static final void executeCommandBackupFileSearch ( String backupName , String toSearch )
  {
    if ( isValidKeyOrFileName ( backupName , true ) )
    {
// This folder is to be listed.
      if ( isExistingFolder ( appBackupDir + SEP + backupName , true ) )
      {
// Let's list this folder.
        fileListOrSearch ( toSearch , new File ( appBackupDir + SEP + backupName ) , true ) ;
      }
    }
  }
/*
** Searches for filenames containing the toSearch in all of the backup files.
*/
  private static final void executeCommandBackupFileSearchall ( String toSearch )
  {
    backupListOrFileSearch ( toSearch ) ;
  }
/*
** Restores a password container file from a given backup.
*/
  private static final void executeCommandBackupRestore ( String backupName , String fileName )
  {
// This have to be valid!
    if ( isValidKeyOrFileName ( backupName , true ) )
    {
// This have to be valid too!
      if ( isValidKeyOrFileName ( fileName , true ) )
      {
// This file has to be existing!
        if ( isExistingBackedUpPasswordFile ( backupName , fileName , true ) )
        {
// Existing admin files are needed.
          if ( isExistingAdminFile ( appAdminFileName , true ) )
          {
// Then a confirmation is needed. (User has to type: yes.)
            if ( readYesElseAnything ( messageSureRestoreFile1 + fileName + messageSureRestoreFile2 + backupName + messageSureRestoreFile3 , messageFileWontBeRestored ) )
            {
// The current admin password will be questioned.
              readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
              if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
              {
// Let's restore this file!
                if ( restoreFile ( backupName , fileName ) )
                {
// Trying to save the admin content
                  if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                  {
// This operation has been finished successfully, message is going to the user!
                    outprintln ( messageYourFileHasBeenRestoredSuccessfully ) ;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
/*
** Restores all of the password container files from a given backup.
*/
  private static final void executeCommandBackupRestoreall ( String backupName )
  {
// This have to be valid!
    if ( isValidKeyOrFileName ( backupName , true ) )
    {
// This file has to be existing!
      if ( isExistingFolder ( appBackupDir + SEP + backupName , true ) )
      {
// Existing admin files are needed.
        if ( isExistingAdminFile ( appAdminFileName , true ) )
        {
// Then a confirmation is needed. (User has to type: yes.)
          if ( readYesElseAnything ( messageSureRestoreFiles , messageFilesWontBeRestored ) )
          {
// The current admin password will be questioned.
            readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And then the admin content will be decrypted.
            if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
            {
// Before doing anything, we are going to do an automated backup of the current state!
              outprintln ( "" + newLineChar + fold + messageAutomatedBackupBeforeRestoring ) ;
              if ( addBackup ( messageAutomatedBackupBeforeRestoring ) )
              {
// Prints the successful backup message.
                outprintln ( messageBackupHasBeenFinishedSuccessfully ) ;
// Trying to delete all of the password container files.
                if ( deleteAllPasswordContainerFiles ( ) )
                {
// Deleting all of the current password files!
                  File backupFolder = new File ( appBackupDir + SEP + backupName ) ;
                  if ( backupFolder != null )
                  {
// These are the files has to be restored.
                    File [ ] files = backupFolder . listFiles ( ) ;
                    if ( files != null )
                    {
// Looping on the files array and restore everything.
                      for ( File file : files )
                      {
                        if ( file != null )
                        {
                          if ( file . getName ( ) != null )
                          {
                            if ( file . getName ( ) . endsWith ( appPdPostfix ) )
                            {
// Trying to restore the file!
                              if ( ! restoreFile ( backupName , file . getName ( ) . substring ( 0 , file . getName ( ) . length ( ) - appPdPostfix . length ( ) ) ) )
                              {
                                systemexit ( "Error - restoreFile is false!, executeCommandBackupRestoreall" ) ;
                              }
                            }
                          }
                          else
                          {
                            systemexit ( "Error - file . getName ( ) is null, executeCommandBackupRestoreall" ) ;
                          }
                        }
                      }
                      if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                      {
// This operation has been finished successfully, message is going to the user!
                        outprintln ( messageAllBackedUpFilesHaveBeenHandeled ) ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - files is null, executeCommandBackupRestoreall" ) ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - backupFolder is null, executeCommandBackupRestoreall" ) ;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
/*
** Prints the hints of this application.
** (Hints: commands only.)
*/
  private static final void executeCommandHints ( )
  {
    outprintln ( messageHints ) ;
  }
/*
** Prints the usage of this application.
** (Help: commands with a short description.)
*/
  private static final void executeCommandHelp ( )
  {
    outprintln ( messageHelp ) ;
  }
/*
** This is for telling the user if the arguments are not corrects.
*/
  private static final void usageWrongParameters ( )
  {
    outprintln ( messageWrongParameters ) ;
    executeCommandHelp ( ) ;
  }
/*
** These functions are lower level functions and they are existing to support the above.
*/
/*
** Restores a file from backup.
*/
  private static final boolean restoreFile ( String backupName , String fileName )
  {
// This is false by default of course.
    boolean success = false ;
// This have to be valid!
    if ( isValidKeyOrFileName ( backupName , false ) )
    {
// This have to be valid too!
      if ( isValidKeyOrFileName ( fileName , false ) )
      {
// Is this a valid backed up file?
        if ( isExistingBackedUpPasswordFile ( backupName , fileName , false ) )
        {
// This is necessary, if it remains true then we can bring the file from the backup.
          boolean canBring = true ;
// Now Let's check the file in the current workspace, existing file?
          if ( isExistingPasswordFile ( fileName , false ) )
          {
// Existing. Now asking for a verification, really can we overwrite the existing file?
            if ( ! readYesElseAnything ( messageSureBringBackedUpFileAndOverwriteCurrentFile , messageFileWontBeOverwrittenByBackedUpFile ) )
            {
// If the answer is not "yes" then we cannot bring the backed up files into the existing files.
              canBring = false ;
            }
          }
// So can we bring the 3 files from backup?
          if ( canBring )
          {
// Bring the files with .nw extension.. (The original file existing or not, doesn't matter.)
            if ( copySingleFile ( appBackupDir + SEP + backupName + SEP + fileName + appPdPostfix , appPasswordDir + SEP + fileName + appPdPostfix + appNwPostfix ) )
            {
              if ( copySingleFile ( appBackupDir + SEP + backupName + SEP + fileName + appIvPostfix , appPasswordDir + SEP + fileName + appIvPostfix + appNwPostfix ) )
              {
                if ( copySingleFile ( appBackupDir + SEP + backupName + SEP + fileName + appSlPostfix , appPasswordDir + SEP + fileName + appSlPostfix + appNwPostfix ) )
                {
// And then we can remove (if exist) the old files and rename .nw to real filenames.
                  if ( removeOldFilesAndRenameNewFiles ( fileName , passwordTypeFile1 ) )
                  {
// Log this event: a file restore just made.
                    char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                    clearCharArray ( contentToLog ) ;
                    String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogRestoreFile + backupName + sep3 + fileName + newLineChar ;
                    prepareToLog ( contentToLog , contentToLog0 ) ;
                    doLog ( contentToLog ) ;
                    clearCharArray ( contentToLog ) ;
                    contentToLog = null ;
                    contentToLog0 = null ;
// The password of this file should be forgotten!
                    if ( toCachePasswords )
                    {
                      purgeCachedFilePassword ( fileName ) ;
                    }
// This operation has been successfully finished!
                    success = true ;
                  }
                }
                else
                {
                  outprintln ( messageUnableToCreateNwFiles + fileName ) ;
                }
              }
              else
              {
                outprintln ( messageUnableToCreateNwFiles + fileName ) ;
              }
            }
            else
            {
              outprintln ( messageUnableToCreateNwFiles + fileName ) ;
            }
          }
// This is not necessary, but..
          canBring = false ;
        }
      }
    }
// Give this
    return success ;
  }
/*
** Lists backups or searches for filenames in backups.
*/
  private static final void backupListOrFileSearch ( String toSearch )
  {
// This has to be a not null reference!
    if ( backupDirFolder != null )
    {
// The toSearch string has to be valid.
      if ( isASCIIandNONSPACE ( toSearch ) )
      {
// Then the file array listing the objects under the backup folder.
        File [ ] files = backupDirFolder . listFiles ( ) ;
        if ( files != null )
        {
// This will count the hits.
          int counter = 0 ;
// These are to be printed out to the user onto the console.
          String backupName = null ;
          String backupDescription = null ;
// Looping on the array.
          for ( File file : files )
          {
// This is just for formatting.
            if ( counter == 0 || ! "" . equals ( toSearch ) )
            {
              outprintln ( "" ) ;
            }
            if ( file != null )
            {
// We are looking for folders.
              if ( file . isDirectory ( ) )
              {
// These are the actual name and description values!
                backupName = file . getName ( ) ;
                backupDescription = readSingleLinedFile ( appBackupDir + SEP + backupName + SEP + appBackupDescriptionFileName ) ;
// Let's print these!
                outprintln ( fold + backupName + sep9 + backupDescription ) ;
// If we are searching for files..
                if ( ! "" . equals ( toSearch ) )
                {
                  fileListOrSearch ( toSearch , file , true ) ;
                }
              }
            }
            else
            {
              systemexit ( "Error - file is null, backupListOrFileSearch" ) ;
            }
// This has to be increased!
            counter ++ ;
          }
// A final message will go to the user.
          if ( counter == 0 )
          {
            outprintln ( messageNoBackupsHaveBeenFound ) ;
          }
          else if ( counter == 1 )
          {
            outprintln ( messageOneBackupHasBeenFound ) ;
          }
          else
          {
            outprintln ( newLineChar + fold + counter + messageBackupsHaveBeenFound ) ;
          }
          if ( "" . equals ( toSearch ) )
          {
            outprintln ( messageTheCountOfAvailableBackupsIs + ( appMaxNumOfBackups - counter ) ) ;
          }
// These are now unused.
          counter = 0 ;
          backupName = null ;
          backupDescription = null ;
        }
        else
        {
          systemexit ( "Error - files is null, backupListOrFileSearch" ) ;
        }
// This is also unused.
        files = null ;
      }
    }
    else
    {
      systemexit ( "Error - backupDirFolder is null, backupListOrFileSearch" ) ;
    }
  }
/*
** Doing a backup.
*/
  private static final boolean addBackup ( String description )
  {
// This is false by default.
    boolean success = false ;
    if ( backupDateFormat != null )
    {
// The name and the path of the backup will be:
      String backupName = backupDateFormat . format ( new Date ( ) ) ;
      String backupPath = appBackupDir + SEP + backupName ;
// This has to be a not null reference!
      if ( backupDirFolder != null )
      {
// Then the file array listing of the objects under the backup folder.
        File [ ] backups = backupDirFolder . listFiles ( ) ;
        if ( backups != null )
        {
          int numOfBackups = backups . length ;
// Can we create a new backup?
          if ( numOfBackups < appMaxNumOfBackups )
          {
            if ( isValidBackupDescription ( description ) )
            {
// This is for not to have the same folder name next time!
              threadsleep ( 1024 ) ;
// Message: this will be the backup.
              outprintln ( messageYourBackupIs + backupName ) ;
// Creating the base and then check if it is really existing.
              File backupFolder = new File ( backupPath ) ;
              if ( backupFolder != null )
              {
                backupFolder . mkdirs ( ) ;
                if ( isExistingFolder ( backupPath , false ) )
                {
                  if ( passwordDirFolder != null )
                  {
// Listing the files in the password dir folder.
                    File [ ] files = passwordDirFolder . listFiles ( ) ;
                    if ( files != null )
                    {
// Ok, let's copy all of the password files () into this place.
                      for ( File file : files )
                      {
                        if ( file != null )
                        {
                          if ( file . getName ( ) != null )
                          {
                            if ( file . getName ( ) . endsWith ( appPdPostfix ) || file . getName ( ) . endsWith ( appSlPostfix ) || file . getName ( ) . endsWith ( appIvPostfix ) )
                            {
                              if ( ! copySingleFile ( appPasswordDir + SEP + file . getName ( ) , backupPath + SEP + file . getName ( ) ) )
                              {
                                systemexit ( "Error - file copy has failed: " + file . getName ( ) + ", addBackup" ) ;
                              }
                            }
                          }
                          else
                          {
                            systemexit ( "Error - file . getName ( ) is null, addBackup" ) ;
                          }
                        }
                        else
                        {
                          systemexit ( "Error - file is null, addBackup" ) ;
                        }
                      }
// Let's create the file of the description.
                      if ( ! createSingleFile ( backupPath + SEP + appBackupDescriptionFileName , description ) )
                      {
                        systemexit ( "Error - failed to make description of backup, addBackup" ) ;
                      }
// Log this event: a backup just made.
                      char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                      clearCharArray ( contentToLog ) ;
                      String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogBackupMake + backupName + sep9 + description + newLineChar ;
                      prepareToLog ( contentToLog , contentToLog0 ) ;
                      doLog ( contentToLog ) ;
                      clearCharArray ( contentToLog ) ;
                      contentToLog = null ;
                      contentToLog0 = null ;
// This is the moment we can set it to true!
                      success = true ;
                    }
                    else
                    {
                      systemexit ( "Error - files is null, addBackup" ) ;
                    }
// This can be pointed nowhere
                    files = null ;
                  }
                  else
                  {
                    systemexit ( "Error - passwordDirFolder is null, addBackup" ) ;
                  }
                }
              }
              else
              {
                systemexit ( "Error - backupFolder is null, addBackup" ) ;
              }
// These are now releasable.
              backupFolder = null ;
            }
            else
            {
              systemexit ( "Error - description is not valid, addBackup" ) ;
            }
          }
          else
          {
            outprintln ( messageTooManyBackupsAreThere + appMaxNumOfBackups ) ;
          }
// This is unused.
          numOfBackups = 0 ;
        }
        else
        {
          systemexit ( "Error - backups is null, addBackup" ) ;
        }
// This is unused too.
        backups = null ;
      }
      else
      {
        systemexit ( "Error - backupDirFolder is null, addBackup" ) ;
      }
// Releasable.
      backupName = null ;
      backupPath = null ;
// Message if it is not successful
      if ( ! success )
      {
        outprintln ( messageBackupHasNotBeenDeletedSuccessfully + backupName ) ;
      }
    }
    else
    {
      systemexit ( "Error - backupDateFormat is null, addBackup" ) ;
    }
// Returning the result.
    return success ;
  }
/*
** Deletes a backup.
*/
  private static final boolean deleteBackup ( String backupName )
  {
// This is false by default.
    boolean success = false ;
// Valid folder name is expected.
    if ( isValidKeyOrFileName ( backupName , false ) )
    {
// Existing backup is needed.
      File backupFolder = new File ( appBackupDir + SEP + backupName ) ;
      if ( backupFolder != null )
      {
        if ( backupFolder . exists ( ) )
        {
          if ( backupFolder . isDirectory ( ) )
          {
// Errors during file deleting.
            boolean fileDeleteError = false ;
            boolean folderDeleteError = false ;
// These are the files has to be deleted.
            File [ ] files = backupFolder . listFiles ( ) ;
            if ( files != null )
            {
// Looping on the files array and deleting everything.
              for ( File file : files )
              {
                if ( file != null )
                {
// Delete and exit if it is not successful.
                  if ( ! file . delete ( ) )
                  {
                    outprintln ( messageErrorWhileDeletingFile + file . getName ( ) ) ;
                    if ( ! fileDeleteError )
                    {
                      fileDeleteError = true ;
                    }
                  }
                }
                else
                {
                  systemexit ( "Error - file is null, deleteBackup" ) ;
                }
              }
            }
            else
            {
              systemexit ( "Error - files is null, deleteBackup" ) ;
            }
// Then delete the folder itself.
            if ( ! backupFolder . delete ( ) )
            {
              outprintln ( messageErrorWhileDeletingFolder + backupName ) ;
              folderDeleteError = true ;
            }
// Let's log this event: a backup just deleted.
            char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
            clearCharArray ( contentToLog ) ;
            String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogBackupDelete + backupName + sep9 + ( ! fileDeleteError && ! folderDeleteError ) + newLineChar ;
            prepareToLog ( contentToLog , contentToLog0 ) ;
            doLog ( contentToLog ) ;
            clearCharArray ( contentToLog ) ;
            contentToLog = null ;
            contentToLog0 = null ;
// Now this should be marked as successful! (Really!)
            success = true ;
// These have to be cleared.
            fileDeleteError = false ;
            folderDeleteError = false ;
            files = null ;
          }
          else
          {
            systemexit ( "Error - backupFolder is a file, deleteBackup" ) ;
          }
        }
        else
        {
          outprintln ( messageFolderDoesNotExist + appBackupDir + SEP + backupName ) ;
        }
      }
      else
      {
        systemexit ( "Error - backupFolder is null, deleteBackup" ) ;
      }
// This can be null too.
      backupFolder = null ;
    }
// Message if it is not successful
    if ( ! success )
    {
      outprintln ( messageTheBackupCreationHasNotBeenFinishedSuccessfully ) ;
    }
// Returning of success.
    return success ;
  }
/*
** Listing the lines of admin file.
** Search string is available to filter the output or can be empty string.
** The searching is case sensitive.
*/
  private static final void adminReviewOrSearch ( String toSearch )
  {
// The toSearch string has to be valid.
    if ( isASCIIandNONSPACE ( toSearch ) )
    {
// The admin files have to be existing!
      if ( isExistingAdminFile ( appAdminFileName , true ) )
      {
// The admin password is needed.
        readPassword ( passwordTypeAdmin , false , appAdminFileName ) ;
// And the content of the admin after the successful decryption.
        if ( getFileContent ( appAdminFileName , passwordTypeAdmin ) )
        {
// The answer should be yes otherwise we won't print the lines.
          if ( readYesElseAnything ( messageNobodyIsAround , messageOk ) )
          {
            if ( fileContentAdminOrig != null )
            {
              if ( fileContentAdminOrig . length > 0 )
              {
// Ok, we are going to start now.
// The starting position and the ending position to print between will be searched for.
                int startPos = 0 ;
                int endPos = 0 ;
// The start pos is..
                for ( int i = 0 ; i < fileContentAdminOrig . length ; i ++ )
                {
                  if ( fileContentAdminOrig [ i ] == newLineChar )
                  {
                    startPos = i + 1 ;
                    break ;
                  }
                }
// The end pos is..
                for ( int i = startPos ; i < fileContentAdminOrig . length - 1 ; i ++ )
                {
                  if ( fileContentAdminOrig [ i ] == newLineChar && fileContentAdminOrig [ i + 1 ] == spaceChar )
                  {
                    endPos = i ;
                    break ;
                  }
                }
// If the end pos has not been found then this has to be the end of the whole content.
                if ( endPos == 0 )
                {
                  endPos = fileContentAdminOrig . length - 1 ;
                }
// Searching is requested or not.
                if ( "" . equals ( toSearch ) )
                {
// Not searching so the first line will be printed out.
                  outprintln ( messageTheHistoryOfApplication ) ;
// And then the others, all of the lines of the admin content.
// We will print the whole content char by char.
                  for ( int i = startPos ; i <= endPos ; i ++ )
                  {
                    outprint ( fileContentAdminOrig [ i ] ) ;
                  }
                }
                else
                {
// Searching! We have to filter the lines to print to the output.
// Currently we have no lines matched.
                  int hitsCount = 0 ;
// The position of the current line.
                  int currLinePos = startPos ;
// This will be the content of the current line.
                  char [ ] theLine = new char [ 0 ] ;
// This will be the length of the current line.
                  int theLineLength = 0 ;
// These two are needed for the searching operation.
                  boolean found = false ;
                  boolean innerBreak = false ;
// And now the searching itself!
// while cycle until the end of the content.
                  while ( currLinePos <= endPos )
                  {
// This should be zero by default.
                    theLineLength = 0 ;
// We will just count at first the characters to determine the length of this current line.
                    for ( int i = 0 ; i <= endPos ; i ++ )
                    {
                      theLineLength ++ ;
                      if ( fileContentAdminOrig [ i + currLinePos ] == newLineChar )
                      {
                        break ;
                      }
                    }
// Now the current line char array can be reinitialized.
                    theLine = new char [ theLineLength ] ;
                    if ( theLine != null )
                    {
// Let''s copy now the content of the current line.
                      for ( int i = 0 ; i < theLine . length ; i ++ )
                      {
                        theLine [ i ] = fileContentAdminOrig [ i + currLinePos ] ;
                      }
// The toSearch string is not found by default.
                      found = false ;
// We have to loop on all of the characters of the current line.
                      for ( int i = 0 ; i < theLine . length ; i ++ )
                      {
// Only if not found and the length of the toSearch string is shorter
// than the remaining part of the current line content.
                        if ( ! found && toSearch . length ( ) <= theLine . length - i )
                        {
// This is false by default.
// It can be true during the execution of the loop below.
                          innerBreak = false ;
// So, we are now in the position i in the current line.
// We have to loop on the characters of the toSearch string
// to test it: will it be contained or not!
// If a character of toSearch doesn't match to the character of the
// current line in the same position then the searching will be failed
// from this position i.
                          for ( int j = 0 ; j < toSearch . length ( ) ; j ++ )
                          {
                            if ( theLine [ i + j ] != toSearch . charAt ( j ) )
                            {
                              innerBreak = true ;
                              break ;
                            }
                          }
// If the inner break is false that means that all of the characters in the
// toSearch string matches to the characters of the current line at the same position,
// so we have found the first occurrence of the searched string!
                          if ( ! innerBreak )
                          {
                            found = true ;
                          }
                        }
// If the toSearch characters have been found, we will break this for loop because
// we won't search for another occurrence, this one is good enough for us.
                        if ( found )
                        {
                          break ;
                        }
                      }
// The current line has been discovered by the toSearch string.
// If the toSearch has been found then we have to print it out.
                      if ( found )
                      {
// Just for formatting.
                        if ( hitsCount == 0 )
                        {
                          outprintln ( "" ) ;
                        }
// Let the line be printed char by char.
                        for ( int i = 0 ; i < theLine . length ; i ++ )
                        {
                          outprint ( theLine [ i ] ) ;
                        }
// We have one plus hit.
                        hitsCount ++ ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - theLine is null, adminReviewOrSearch" ) ;
                    }
// The current line has been handled, so we are going to the next line.
                    currLinePos = currLinePos + theLineLength ;
// This is sensitive data so we have to clear it now.
                    clearCharArray ( theLine ) ;
                  }
// This can be cleared
                  clearCharArray ( theLine ) ;
                  theLine = null ;
// This is the end of the printing of searched content.
// Let's display the number of hits we have had.
                  if ( hitsCount == 0 )
                  {
                    outprintln ( newLineChar + fold + messageNoHitsHaveBeenFound + toSearch ) ;
                  }
                  else if ( hitsCount == 1 )
                  {
                    outprintln ( newLineChar + fold + hitsCount + messageHitHasBeenFound + toSearch ) ;
                  }
                  else
                  {
                    outprintln ( newLineChar + fold + hitsCount + messageHitsHaveBeenFound + toSearch ) ;
                  }
// This sensitive information has to be cleared from memory
                  clearCharArray ( theLine ) ;
// These variable are no longer used.
                  theLine = null ;
                  hitsCount = 0 ;
                  currLinePos = 0 ;
                  theLineLength = 0 ;
                  found = false ;
                  innerBreak = false ;
                }
// Let's log an event: an admin review or admin search has been made.
                char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                clearCharArray ( contentToLog ) ;
                String contentToLog0 = getBeginningOfHistoryEntry ( ) ;
                if ( "" . equals ( toSearch ) )
                {
                  contentToLog0 = contentToLog0 + messageLogAdminReview ;
                }
                else
                {
                  contentToLog0 = contentToLog0 + messageLogAdminSearch + toSearch ;
                }
                contentToLog0 = contentToLog0 + newLineChar ;
                prepareToLog ( contentToLog , contentToLog0 ) ;
                doLog ( contentToLog ) ;
                clearCharArray ( contentToLog ) ;
                contentToLog = null ;
                contentToLog0 = null ;
// Saving the admin file.
                saveFile ( appAdminFileName , passwordTypeAdmin ) ;
// These will be not used.
                startPos = 0 ;
                endPos = 0 ;
              }
              else
              {
                systemexit ( "Error - fileContentAdminOrig is empty, adminReviewOrSearch" ) ;
              }
            }
            else
            {
              systemexit ( "Error - fileContentAdminOrig is null, adminReviewOrSearch" ) ;
            }
          }
        }
      }
    }
  }
/*
** The key searching (searching for a key in a file) and the
** key listing (empty search string) can be handled using this method.
** The searching is case insensitive.
*/
  private static final void keyListOrSearch ( String fileName , String toSearch )
  {
// An existing file is needed at first.
    if ( isExistingPasswordFile ( fileName , true ) )
    {
// Let is read the password for the File1 type.
      readPassword ( passwordTypeFile1 , false , fileName ) ;
// The file content should be read successfully.
      if ( getFileContent ( fileName , passwordTypeFile1 ) )
      {
// This will be the array list which will store the found keys.
        ArrayList < String > keys = getSortedKeyList ( passwordTypeFile1 , toSearch ) ;
        if ( keys != null )
        {
// This will be the count of the found keys.
          int keyCounter = 0 ;
// Looping on the keys to print them out.
          for ( String aKey : keys )
          {
            if ( aKey != null )
            {
// This is for well formatting.
              if ( keyCounter == 0 )
              {
                outprintln ( "" ) ;
              }
// Printing the key.
              outprintln ( fold + fold2 + aKey ) ;
// This should be increased.
              keyCounter ++ ;
            }
            else
            {
              systemexit ( "Error - aKey is null, keyListOrSearch" ) ;
            }
          }
// Message to the user according to the count of the found keys.
          if ( keyCounter == 0 )
          {
            outprintln ( messageNoKeysHaveBeenFound ) ;
          }
          else if ( keyCounter == 1 )
          {
            outprintln ( messageKeyCountHasBeenFound ) ;
          }
          else
          {
            outprintln ( newLineChar + fold + keyCounter + messageKeysCountFound ) ;
          }
// If this is not a search then we will print the available number of keys can be created by the user in this file.
          if ( "" . equals ( toSearch ) )
          {
            outprintln ( messageAvailableKeysCount + ( appMaxNumOfKeysPerFile - keyCounter ) ) ;
          }
// Can be zero now.
          keyCounter = 0 ;
// These should be cleared.
          keys . clear ( ) ;
        }
        else
        {
          systemexit ( "Error - keys is null, keyListOrSearch" ) ;
        }
// This can be set to nowhere.
        keys = null ;
      }
    }
  }
/*
** The file searching (searching for file names) and the
** file listing (empty search string) can be handled using this method.
** The searching is case insensitive.
** Also handles the file searching in backups.
*/
  private static final void fileListOrSearch ( String toSearch , File folder , boolean inBackup )
  {
// This will be the count of found files.
    int counter = 0 ;
    if ( folder != null )
    {
// This is the object we will loop on.
      File [ ] passwordFiles = folder . listFiles ( ) ;
      if ( passwordFiles != null )
      {
        if ( appPdPostfix != null )
        {
// This is the loop. We will go thru the whole folder.
          for ( File passwordFile : passwordFiles )
          {
            if ( passwordFile != null )
            {
// This is good if this is a file a
              if ( passwordFile . exists ( ) && passwordFile . isFile ( ) )
              {
                if ( passwordFile . getName ( ) != null )
                {
// We are going to work with it if it has the proper postfix.
                  if ( passwordFile . getName ( ) . endsWith ( appPdPostfix ) )
                  {
                    if ( toSearch != null )
                    {
// Counting and listing if:
// - no search string has been specified ("")
// - or there is a not empty search string and it matches on the current filename.
                      if ( "" . equals ( toSearch ) || ( ! "" . equals ( toSearch ) && passwordFile . getName ( ) . toLowerCase ( ) . contains ( toSearch . toLowerCase ( ) ) ) )
                      {
// This is for formatting.
                        if ( counter == 0 )
                        {
                          outprintln ( "" ) ;
                        }
// Printing out the name of the file without file postfix.
                        outprintln ( fold + fold2 + passwordFile . getName ( ) . substring ( 0 , passwordFile . getName ( ) . length ( ) - appPdPostfix . length ( ) ) ) ;
// This has to be increased.
                        counter ++ ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - toSearch is null, fileListOrSearch" ) ;
                    }
                  }
                }
                else
                {
                  systemexit ( "Error - passwordFileGetName is null, fileListOrSearch" ) ;
                }
              }
            }
            else
            {
              systemexit ( "Error - passwordFile is null, fileListOrSearch" ) ;
            }
          }
// Final message depending on the count of the found files.
          if ( counter == 0 )
          {
            outprintln ( messageFilesCountEmpty ) ;
          }
          else if ( counter == 1 )
          {
            outprintln ( messageFilesCountOne ) ;
          }
          else
          {
            outprintln ( "" + newLineChar + fold + counter + messageFilesCountMore ) ;
          }
// If this is not a search then we will print the available number of files can be created by the user.
          if ( "" . equals ( toSearch ) && ! inBackup )
          {
            outprintln ( messageAvailableFilesCount + ( appMaxNumOfFiles - counter ) ) ;
          }
        }
        else
        {
          systemexit ( "Error - appPdPostfix is null, fileListOrSearch" ) ;
        }
      }
      else
      {
        systemexit ( "Error - passwordFiles is null, fileListOrSearch" ) ;
      }
// Not usable any more.
      passwordFiles = null ;
    }
    else
    {
      systemexit ( "Error - folder is null, fileListOrSearch" ) ;
    }
// This is no longer be used.
    counter = 0 ;
  }
/*
** Deletes all of the password container files!
*/
  private static final boolean deleteAllPasswordContainerFiles ( )
  {
// This is not success by default
    boolean success = false ;
// This will be the file array.
    File [ ] passwordFiles = passwordDirFolder . listFiles ( ) ;
    if ( passwordFiles != null )
    {
// Let's loop on this!
      for ( File passwordFile : passwordFiles )
      {
        if ( passwordFile != null )
        {
          if ( passwordFile . isFile ( ) && passwordFile . exists ( ) )
          {
            if ( passwordFile . getName ( ) != null )
            {
              if ( passwordFile . getName ( ) . endsWith ( appPdPostfix ) || passwordFile . getName ( ) . endsWith ( appSlPostfix ) || passwordFile . getName ( ) . endsWith ( appIvPostfix ) )
              {
                if ( ! passwordFile . delete ( ) )
                {
                  outprintln ( messageUnableToDeleteFile + passwordFile . getName ( ) ) ;
                }
              }
            }
            else
            {
              systemexit ( "Error - passwordFile . getName ( ) is null, deleteAllPasswordContainerFiles" ) ;
            }
          }
        }
        else
        {
          systemexit ( "Error - passwordFile is null, deleteAllPasswordContainerFiles" ) ;
        }
      }
      passwordFiles = null ;
      if ( toCachePasswords )
      {
        purgeCachedFilePasswords ( ) ;
      }
      char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
      clearCharArray ( contentToLog ) ;
      String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogFilesDelete + newLineChar ;
      prepareToLog ( contentToLog , contentToLog0 ) ;
      doLog ( contentToLog ) ;
      clearCharArray ( contentToLog ) ;
      contentToLog = null ;
      contentToLog0 = null ;
// Success!
      success = true ;
    }
    else
    {
      systemexit ( "Error - passwordFiles is null, deleteAllPasswordContainerFiles" ) ;
    }
// Returning this
    return success ;
  }
/*
** Deletes a key from the content.
*/
  private static final char [ ] keyDelete ( String passwordType , String key , int keyPos , String fileName )
  {
// This is the content we will delete, we should return this.
    char [ ] deletedContent = new char [ 0 ] ;
// This has to be valid!
    if ( keyPos > - 1 )
    {
// Valid fileName and key are needed.
      if ( isValidKeyOrFileName ( key , false ) && isValidKeyOrFileName ( fileName , false ) )
      {
// We need this variables to delete the key (and password of course).
// The second newLine will be searched to get the next key position.
        int newLineCounter = 0 ;
// This will be the position of the next key.
        int nextKeyPos = - 1 ;
// This is for having only one reference to the correct content char array.
        char [ ] fileContentOrig = null ;
        if ( passwordTypeFile1 != null && passwordTypeFile2 != null )
        {
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            fileContentOrig = fileContent1Orig ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            fileContentOrig = fileContent2Orig ;
          }
        }
        else
        {
          systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2, keyDelete" ) ;
        }
// If this is not null.. (else exiting)
        if ( fileContentOrig != null )
        {
// We are going to determine the position of the next key.
// Searching from the key pos until we have the second newLine char.
          for ( int i = keyPos ; i < fileContentOrig . length ; i ++ )
          {
            if ( fileContentOrig [ i ] == newLineChar )
            {
              newLineCounter ++ ;
            }
            if ( newLineCounter == 2 )
            {
              nextKeyPos = i + 1 ;
              break ;
            }
          }
// Now we can initialize the char array of the content which will be deleted.
          if ( nextKeyPos - keyPos > - 1 )
          {
            deletedContent = new char [ nextKeyPos - keyPos ] ;
            if ( deletedContent != null )
            {
// Let it be filled by the chars of the actual key and password.
              for ( int i = keyPos ; i < nextKeyPos ; i ++ )
              {
                deletedContent [ i - keyPos ] = fileContentOrig [ i ] ;
              }
// Trying to move the chars in the character array of the content.
// The from position and the difference is needed.
              int toMoveFromPos = nextKeyPos ;
              int toMoveDiff = keyPos - nextKeyPos ;
// If the difference is not zero then the shifting is needed.
              if ( toMoveDiff != 0 )
              {
                shiftFileContent ( passwordTypeFile1 , toMoveFromPos , toMoveDiff ) ;
              }
// These are set to zero now because we won't use them.
              toMoveFromPos = 0 ;
              toMoveDiff = 0 ;
// Finally let's log this event!
              char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
              clearCharArray ( contentToLog ) ;
              String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogKeyDelete + fileName + sep1 + key + newLineChar ;
              prepareToLog ( contentToLog , contentToLog0 ) ;
              doLog ( contentToLog ) ;
              clearCharArray ( contentToLog ) ;
              contentToLog = null ;
              contentToLog0 = null ;
            }
            else
            {
              systemexit ( "Error - deletedContent is null, keyDelete" ) ;
            }
          }
          else
          {
            systemexit ( "Error - nextKeyPos - keyPos is negative, keyDelete" ) ;
          }
        }
        else
        {
          systemexit ( "Error - fileContentOrig is null, keyDelete" ) ;
        }
// These can be cleared.
        newLineCounter = 0 ;
        nextKeyPos = - 1 ;
        fileContentOrig = null ;
      }
    }
    else
    {
      systemexit ( "Error - keyPos is negative, keyDelete" ) ;
    }
// Returning of the content which we just have deleted.
// (key + newLine + password + newLine)
    return deletedContent ;
  }
/*
** Moves a key from a file into another.
** Saves the files if it is requested.
*/
  private static final void keyMove ( String currentFileName , String newFileName , String key , boolean toSave )
  {
// The file names and the key have to be good formatted.
    if ( isValidKeyOrFileName ( currentFileName , false ) && isValidKeyOrFileName ( newFileName , false ) && isValidKeyOrFileName ( key , false ) )
    {
// Checking for the key in the current file: it has to be existing.
// Else: message to the user.
      int keyPosInCurrent = getKeyPos ( passwordTypeFile1 , key ) ;
      if ( keyPosInCurrent != - 1 )
      {
// Checking for the key in the new file: it has not to be existing!
// Else: message to the user.
        int keyPosInNew = getKeyPos ( passwordTypeFile2 , key ) ;
        if ( keyPosInNew == - 1 )
        {
// New file: File2.
// We should looking into the count of the keys. Can we move the key there?
// Else: message to the user.
          if ( getNumOfKeysInContent ( passwordTypeFile2 ) < appMaxNumOfKeysPerFile )
          {
// Let's delete the key and get the deleted part of the content!
            char [ ] deletedContent = keyDelete ( passwordTypeFile1 , key , keyPosInCurrent , currentFileName ) ;
            if ( deletedContent != null )
            {
              if ( deletedContent . length > 0 )
              {
                if ( fileContent2Orig != null )
                {
                  if ( fileContent2Orig . length > 0 )
                  {
// This is the position where we can start the appending.
// The moved keys always will go at the end of the File2 content.
                    int posToAppend = getFirstSpaceCharIndexBefore ( fileContent2Orig ) + 1 ;
                    if ( posToAppend > - 1 )
                    {
                      if ( posToAppend + 1 + deletedContent . length < fileContent2Orig . length )
                      {
// Appending the key and the password.
                        for ( int i = 0 ; i < deletedContent . length ; i ++ )
                        {
                          fileContent2Orig [ posToAppend + i ] = deletedContent [ i ] ;
                        }
// Logging this event.
                        char [ ] contentToLog = new char [ appMaxLengthToLog ] ;
                        clearCharArray ( contentToLog ) ;
                        String contentToLog0 = getBeginningOfHistoryEntry ( ) + messageLogKeyMove + currentFileName + sep1 + newFileName + sep1 + key + newLineChar ;
                        prepareToLog ( contentToLog , contentToLog0 ) ;
                        doLog ( contentToLog ) ;
                        clearCharArray ( contentToLog ) ;
                        contentToLog = null ;
                        contentToLog0 = null ;
// We can save this operation if it is requested.
// This method can be called from several other methods
// therefore the saving operation can be elsewhere.
// If not have to save the current operation then a simple
// message will go tho the user about the key moving.
                        if ( toSave )
                        {
// We have to save the file1 and file2 now.
                          if ( saveFile ( newFileName , passwordTypeFile2 ) && saveFile ( currentFileName , passwordTypeFile1 ) )
                          {
// Then the admin file should be saved (logged content).
                            if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                            {
// Message of successful saving operation.
// The empty string is necessary only when toSave.
                              outprintln ( "" ) ;
                              outprintln ( messageKeyHasBeenMovedWithFileSaving + key ) ;
                            }
                          }
                        }
                        else
                        {
                          outprintln ( messageKeyHasBeenMoved + key ) ;
                        }
// This can be zero now.
                        posToAppend = 0 ;
                      }
                      else
                      {
                        systemexit ( "Error - content is too long to move, keyMove" ) ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - key pos is negative, keyMove" ) ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - fileContent2Orig is empty, keyMove" ) ;
                  }
                }
                else
                {
                  systemexit ( "Error - fileContent2Orig is null, keyMove" ) ;
                }
              }
              else
              {
                systemexit ( "Error - deletedContent is empty, keyMove" ) ;
              }
            }
            else
            {
              systemexit ( "Error - deletedContent is null, KeyMove" ) ;
            }
// This has to be cleared now because it contains a password!
            clearCharArray ( deletedContent ) ;
            deletedContent = null ;
          }
          else
          {
            if ( toSave )
            {
              outprintln ( "" ) ;
            }
            outprintln ( messageTooManyKeysInFileNew ) ;
          }
        }
        else
        {
          if ( toSave )
          {
            outprintln ( "" ) ;
          }
          outprintln ( messageKeyFoundInNew + key ) ;
        }
        keyPosInNew = 0 ;
      }
      else
      {
        if ( toSave )
        {
          outprintln ( "" ) ;
        }
        outprintln ( messageKeyIsNotFoundInCurrent + key ) ;
      }
// This can be 0.
      keyPosInCurrent = 0 ;
    }
  }
/*
** Shows the password belonging to the given key.
** void so it doesn't return the password just prints it out
** to the user onto the console char by char.
*/
  private static final void passwordShowFile1 ( String key )
  {
// The valid key is necessary. Message if it is not correct.
    if ( isValidKeyOrFileName ( key , true ) )
    {
// We have to know that this key is available in the File1 content.
      if ( getKeyPos ( passwordTypeFile1 , key ) != - 1 )
      {
// The password will be shown only if that is a safe environment!
// (By the user's answer.)
        if ( readYesElseAnything ( messageNobodyIsAround , messageOk ) )
        {
// A message.
          outprintln ( messageYourPasswordIs ) ;
// Getting the password.
          char [ ] thePassword = getKeyPasswordFile1 ( key ) ;
          if ( thePassword != null )
          {
// Showing the password.
            for ( int i = 0 ; i < thePassword . length ; i ++ )
            {
// Printing out the actual character.
              outprint ( thePassword [ i ] ) ;
// If the password is a strong password then space characters are inserted.
// (To help the user not to fall into temptation: avoid copy-paste password.)
              if ( allowPasswordPartsFile1 == allowPasswordPartsNo )
              {
                outprint ( spaceChar ) ;
                if ( Math . random ( ) < 0.5 )
                {
                  outprint ( spaceChar ) ;
                }
              }
            }
// This has to be cleared immediately!
            clearCharArray ( thePassword ) ;
            thePassword = null ;
// A new line char is needed.
            outprint ( newLineChar ) ;
// This is for the user: don't forget to close this window!
            outprintln ( messageCloseThisWindow ) ;
// Displaying the password and a counter.
            displayPasswordShowStatus ( ) ;
// Clearing the screen by printing out a couple of empty lines.
            clearScreen ( appNumOfEmptyLinesToClearTheScreen ) ;
// Close window message again.
            outprint ( messageScreenHasBeenClearedBut ) ;
            outprintln ( messageCloseThisWindow ) ;
          }
          else
          {
            systemexit ( "Error - thePassword is null, passwordShowFile1" ) ;
          }
        }
      }
      else
      {
        outprintln ( messageKeyIsNotFound ) ;
      }
    }
  }
/*
** Generate the list of the keys located in the currently decrypted content.
** If the toSearch string doesn't equal the "" then it will search
** for the expression in the keys and will return just the matched keys.
** Otherwise all of the keys will be listed from that file content (by passwordType).
*/
  private static final ArrayList < String > getSortedKeyList ( String passwordType , String toSearch )
  {
// This will be the list which will be returned.
    ArrayList < String > keys = new ArrayList < String > ( ) ;
// The string we want to search for has to be valid.
// Else we will return with this empty list.
    if ( isASCIIandNONSPACE ( toSearch ) )
    {
// This will be the current key.
      String key = "" ;
// We are in a key or not while looping on the characters in the content.
      boolean inKey = true ;
// We are counting the number of newLine characters.
      int newLineCounter = 0 ;
// This will be the reference to the correct content char array.
      char [ ] fileContentOrig = null ;
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null )
      {
        if ( passwordTypeFile1 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent1Orig ;
        }
        else if ( passwordTypeFile2 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent2Orig ;
        }
// If the content char array is not null.. else exit!
        if ( fileContentOrig != null )
        {
// We are looping on the characters of the content character array.
          for ( int i = 0 ; i < fileContentOrig . length ; i ++ )
          {
// We can start if the newLine counter is greater than 2.
// So when we are in the first key!
            if ( newLineCounter >= 2 )
            {
// If we find a space char we will break immediately since
// there is no space in the stored keys and passwords.
              if ( fileContentOrig [ i ] != spaceChar )
              {
// The newLine char is the important for us.
// The char is newLine or not.
                if ( fileContentOrig [ i ] != newLineChar )
                {
                  if ( inKey )
                  {
// If the current char of the content is not a newLine char
// and we are in a key then this char should be appended
// into the end of current key string.
                    key = key + fileContentOrig [ i ] ;
                  }
                }
                else
                {
// newLine char! inKey must be changed!
                  inKey = ! inKey ;
                  if ( key != null )
                  {
// If the current key is not an empty string then we have to work on this.
                    if ( ! "" . equals ( key ) )
                    {
// Adding this key if the toSearch string matches to this or
// we are not searching for any string. (So the toSearch string is empty.)
                      if ( "" . equals ( toSearch ) || ( ! "" . equals ( toSearch ) && key . toLowerCase ( ) . contains ( toSearch . toLowerCase ( ) ) ) )
                      {
                        if ( keys != null )
                        {
                          keys . add ( key ) ;
                        }
                        else
                        {
                          systemexit ( "Error - keys is null, getSortedKeyList" ) ;
                        }
                      }
// This have to be empty now!
// The next key will be appended here.
                      key = "" ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - key is null, getSortedKeyList" ) ;
                  }
                }
              }
              else
              {
                break ;
              }
            }
// Counts the newLine chars.
            if ( fileContentOrig [ i ] == newLineChar )
            {
              newLineCounter ++ ;
            }
          }
// Do a sorting on the keys.
          Collections . sort ( keys ) ;
        }
        else
        {
          systemexit ( "Error - fileContentOrig is null, getSortedKeyList" ) ;
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2, getSortedKeyList" ) ;
      }
// These should be not used.
      key = "" ;
      inKey = false ;
      newLineCounter = 0 ;
      fileContentOrig = null ;
    }
// And returning the keys we have found!
    return keys ;
  }
/*
** Generates a good and random length password for the user.
** It generates password from character set: ASCII 33-126.
** It uses the constants initialized at the top:
** - appGoodPasswordMinLengthOfGoodPasswords
** - appMaxLengthOfGeneratedPasswords
*/
  private static final char [ ] getGeneratedGoodPassword ( )
  {
// This will be the password!
    char [ ] thePassword = new char [ 0 ] ;
// We will use this secure random object to create truly secure password.
    SecureRandom secureRandom = null ;
// We can start if we are able to determine the length of the password!
// Else exit!
    if ( appGoodPasswordMinLengthOfGoodPasswords <= appMaxLengthOfGeneratedPasswords )
    {
// 1. We will construct the array to select the characters from.
      char [ ] charsToUse = new char [ 126 - 33 + 1 ] ;
      if ( charsToUse != null )
      {
        for ( int i = 33 ; i <= 126 ; i ++ )
        {
          charsToUse [ i - 33 ] = ( char ) i ;
        }
// 2. We will replacing all of the characters secure randomly.
        int newIndex = 0 ;
        char tempChar = spaceChar ;
        secureRandom = new SecureRandom ( ) ;
        if ( secureRandom != null )
        {
          for ( int i = 0 ; i < charsToUse . length ; i ++ )
          {
            newIndex = secureRandom . nextInt ( charsToUse . length ) ;
            if ( newIndex != i )
            {
              tempChar = charsToUse [ i ] ;
              charsToUse [ i ] = charsToUse [ newIndex ] ;
              charsToUse [ newIndex ] = tempChar ;
            }
          }
          tempChar = spaceChar ;
          newIndex = 0 ;
// 3. We are going to generate the new password until it has a valid good password value.
          int lengthOfPassword = 0 ;
          while ( true )
          {
            secureRandom = null ;
            secureRandom = new SecureRandom ( ) ;
            lengthOfPassword = secureRandom . nextInt ( appMaxLengthOfGeneratedPasswords - appGoodPasswordMinLengthOfGoodPasswords + 1 ) + appGoodPasswordMinLengthOfGoodPasswords ;
            clearCharArray ( thePassword ) ;
            thePassword = null ;
            thePassword = new char [ lengthOfPassword ] ;
            secureRandom = null ;
            secureRandom = new SecureRandom ( ) ;
            for ( int i = 0 ; i < lengthOfPassword ; i ++ )
            {
              thePassword [ i ] = charsToUse [ secureRandom . nextInt ( charsToUse . length ) ] ;
            }
            if ( isValidGoodPassword ( thePassword , false ) )
            {
              break ;
            }
          }
// Let it be zero.
          lengthOfPassword = 0 ;
        }
        else
        {
          systemexit ( "Error - secureRandom is null, getGeneratedGoodPassword" ) ;
        }
// These should be cleared.
        newIndex = 0 ;
        tempChar = spaceChar ;
      }
      else
      {
        systemexit ( "Error - charsToUse is null, getGeneratedGoodPassword" ) ;
      }
// 4. clearing the array of the chars.
      clearCharArray ( charsToUse ) ;
      charsToUse = null ;
    }
    else
    {
      systemexit ( "Error - Wrong min or max length of password, getGeneratedGoodPassword" ) ;
    }
// This object is not needed.
    secureRandom = null ;
// Let it be returned!
    return thePassword ;
  }
/*
** Getting a stored password from file. (File1 password type)
** This will go into a character array and this function will return with it.
*/
  private static final char [ ] getKeyPasswordFile1 ( String key )
  {
// This will be the password!
// Empty by default.
    char [ ] thePassword = new char [ 0 ] ;
// The key must be valid.
    if ( isValidKeyOrFileName ( key , false ) )
    {
// We want to know where the key is.
      int keyPos = getKeyPos ( passwordTypeFile1 , key ) ;
// This should not be -1.
// It it is then the empty password will be returned!
      if ( keyPos != - 1 )
      {
// This will be the length of the stored password.
// We don't know yet.
        int passwordLength = 0 ;
        if ( fileContent1Orig != null )
        {
// We will count the letters of the password.
          for ( int i = keyPos + key . length ( ) + 1 ; i < fileContent1Orig . length ; i ++ )
          {
            if ( fileContent1Orig [ i ] != newLineChar )
            {
              passwordLength ++ ;
            }
            else
            {
              break ;
            }
          }
// The initialization can be done now using this length.
          thePassword = new char [ passwordLength ] ;
// Let's copy the characters of the password from the content into the char array.
          for ( int i = 0 ; i < thePassword . length ; i ++ )
          {
            thePassword [ i ] = fileContent1Orig [ keyPos + key . length ( ) + 1 + i ] ;
          }
// This can be zero now.
          passwordLength = 0 ;
        }
        else
        {
          systemexit ( "Error - fileContent1Orig is null, getKeyPasswordFile1" ) ;
        }
      }
// And this is too.
      keyPos = 0 ;
    }
// Giving back the password now.
    return thePassword ;
  }
/*
** Getting the index of the beginning of the given key
** (name of a password) in the given content by passwordType.
*/
  private static final int getKeyPos ( String passwordType , String key )
  {
// This will be -1 at first, this means not found.
    int keyPos = - 1 ;
// We have to have valid key.
    if ( isValidKeyOrFileName ( key , false ) )
    {
// These are necessary while searching for the key in the content.
      boolean inKey = false ;
      boolean found = true ;
// This will be the key we are looking for.
      String tempKey = newLineChar + key + newLineChar ;
// This will be used!
      char [ ] fileContentOrig = null ;
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null )
      {
// At first we have to point into the correct char array.
        if ( passwordTypeFile1 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent1Orig ;
        }
        else if ( passwordTypeFile2 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent2Orig ;
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2, getKeyPos" ) ;
      }
// If this is done.. Else we will exit!
      if ( fileContentOrig != null )
      {
// We will search for the key from the first key to the end of the content.
// First key index:
// 1. filesHeader . length ( ) - 1. -1: because we are looking for an index that starts from 0.
// 2. +2: the allowPasswordParts char + a newLineChar are the next in the file.
// And that is that newLine we want to start from exactly!
// We will break this searching if we find a space character.
        for ( int i = filesHeader . length ( ) - 1 + 2 ; i < fileContentOrig . length ; i ++ )
        {
// newLineChar and spaceChar are the important now.
// newLineChar: we can change the inKey boolean variable.
          if ( fileContentOrig [ i ] == newLineChar )
          {
// We are in key or not in key.
            inKey = ! inKey ;
// If we are currently in a key..
            if ( inKey )
            {
// This is true by default.
// The char-by-char comparison can change this to false.
              found = true ;
// Now we are going to start the comparison of the content and the tempKey by characters.
// The found variable remains true if there are no different chars!
              for ( int j = 0 ; j < tempKey . length ( ) ; j ++ )
              {
                if ( fileContentOrig [ i + j ] != tempKey . charAt ( j ) )
                {
                  found = false ;
                  break ;
                }
              }
// If the key has been found then mark the key pos!
// +1 means: the position in i is the enter before
// key so we have to increase this value by 1
// to have the actual position of that key!
// If found, then break the cycle of course,
// a key can be stored just one time in a file.
              if ( found )
              {
                keyPos = i + 1 ;
                break ;
              }
            }
          }
// spaceChar: breaks the loop.
          else if ( fileContentOrig [ i ] == spaceChar )
          {
            break ;
          }
        }
      }
      else
      {
        systemexit ( "Error - fileContentOrig is null, getKeyPos" ) ;
      }
// These have to be cleared.
      fileContentOrig = null ;
      inKey = false ;
      found = false ;
      tempKey = null ;
    }
// Return the position of the key.
// Remember, -1 if not found.
    return keyPos ;
  }
/*
** Upper level read functions.
*/
/*
** This is one of the most important methods in this application: reads the password.
** This will be used when:
** - reads a key password
** - reads the admin password
** - reads file passwords (File1 or File2) for any reason.
** Also handles the cached password reading and password caching.
** (won't prompt the user if that password is cached.)
** If the password is now cached but during the decryption the content will be not found
** (so the now given password is incorrect) then this now cached password will be forgotten,
** this will be happened in the getFileContent function.
*/
  private static final void readPassword ( String passwordType , boolean beVerified , String fileName )
  {
// At first we have to determine whether the password will be prompted or not.
    boolean haveToReadFromConsole = true ;
// This is also necessary, we will store the cached password in it if there is.
// Empty array by default, this is important.
    char [ ] cachedPassword = new char [ 0 ] ;
// These has to be not null.
    if ( fileName != null )
    {
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeKey != null && passwordTypeAdmin != null )
      {
// Valid filename is needed or passwordTypeKey is needed.
// (In case of key password, the filename is not relevant because that password will belong to a key and not to a file.)
        if ( isValidKeyOrFileName ( fileName , false ) || passwordTypeKey . equals ( passwordType ) )
        {
// Let's start.
// If the toCachePasswords boolean variable has been set to true.. else: have to read from console.
          if ( toCachePasswords )
          {
// If it should be verified or the fileName
// is an empty string or a key password will be read (which cannot be cached).. have to read from console.
            if ( beVerified || passwordTypeKey . equals ( passwordType ) )
            {
              haveToReadFromConsole = true ;
            }
            else
            {
// At this point, we will looking into a cached password.
              if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
              {
                cachedPassword = getCachedFilePassword ( fileName ) ;
              }
              else if ( passwordTypeAdmin . equals ( passwordType ) )
              {
                cachedPassword = getCachedAdminPassword ( ) ;
              }
// If the password is an empty array then we have to read from the console.
// Else we can use the cachedPassword array since it references to a not empty value.
              if ( cachedPassword . length == 0 )
              {
                haveToReadFromConsole = true ;
              }
              else
              {
                haveToReadFromConsole = false ;
              }
            }
          }
          else
          {
            haveToReadFromConsole = true ;
          }
// The decision has been made!
          if ( ! haveToReadFromConsole )
          {
// If not have to read from the console then
// the password char array should be cleared and set according the passwordType.
            if ( passwordTypeFile1 . equals ( passwordType ) )
            {
              clearCharArray ( passwordForFile1 ) ;
              passwordForFile1 = cachedPassword ;
            }
            else if ( passwordTypeFile2 . equals ( passwordType ) )
            {
              clearCharArray ( passwordForFile2 ) ;
              passwordForFile2 = cachedPassword ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              clearCharArray ( passwordForAdmin ) ;
              passwordForAdmin = cachedPassword ;
            }
          }
          else
          {
// If have to read the password from the console
// then we have to know whether the password part storing is
// enabled in that file (according to the passwordType) or not.
// Space char by default.
            char isPasswordPartAllowed = spaceChar ;
// File1 or Key.. This is because in case of passwordTypeKey always the passwordTypeFile1 is used.
// File2 trivial.
// Admin: it is not possible to store this value in the admin file so let it be no.
            if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeKey . equals ( passwordType ) )
            {
              isPasswordPartAllowed = allowPasswordPartsFile1 ;
            }
            else if ( passwordTypeFile2 . equals ( passwordType ) )
            {
              isPasswordPartAllowed = allowPasswordPartsFile2 ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              isPasswordPartAllowed = allowPasswordPartsNo ;
            }
// We will checking for a valid and verified password.
// One of these should be false to start the while cycle.
// It is not a bad thing to set to false both variables.
            boolean isValidPassword = false ;
            boolean isVerifiedPassword = false ;
// This block has to be repeated until it is not valid or not verified.
            while ( ! isValidPassword || ! isVerifiedPassword )
            {
// At this point valid but not verified.
// (valid will be true if valid and verified will be false if not verified)
              isValidPassword = false ;
              isVerifiedPassword = true ;
// Now we have to clear the char array used for the password reading.
              clearCharArray ( passwordFromInputOriginal ) ;
// By password type.
// 1: The password will be read
// 2: The correct password character array should be cleared.
// 3: That should be reinitialized by the length of the given password.
              if ( passwordTypeFile1 . equals ( passwordType ) )
              {
                passwordFromInputOriginal = readpassword ( messageEnterPasswordForFile ) ;
                clearCharArray ( passwordForFile1 ) ;
                passwordForFile1 = new char [ passwordFromInputOriginal . length ] ;
              }
              else if ( passwordTypeFile2 . equals ( passwordType ) )
              {
                passwordFromInputOriginal = readpassword ( messageEnterPasswordForFile ) ;
                clearCharArray ( passwordForFile2 ) ;
                passwordForFile2 = new char [ passwordFromInputOriginal . length ] ;
              }
              else if ( passwordTypeKey . equals ( passwordType ) )
              {
                passwordFromInputOriginal = readpassword ( messageEnterPasswordForKey ) ;
                clearCharArray ( passwordForKey ) ;
                passwordForKey = new char [ passwordFromInputOriginal . length ] ;
              }
              else if ( passwordTypeAdmin . equals ( passwordType ) )
              {
                passwordFromInputOriginal = readpassword ( messageEnterPasswordForAdmin ) ;
                clearCharArray ( passwordForAdmin ) ;
                passwordForAdmin = new char [ passwordFromInputOriginal . length ] ;
              }
// Validating the password.
              if ( isPasswordPartAllowed == allowPasswordPartsNo )
              {
// If this has to be a valid good password then the isValidGoodPassword validation should be used
// and in case of wrong formatted password the wrong password message should be printed to the user
// only if this password should be verified!
                isValidPassword = isValidGoodPassword ( passwordFromInputOriginal , beVerified ) ;
              }
              else
              {
// If this has to be a valid good password then the isValidPasswordPart validation should be used
// and in case of wrong formatted password the wrong password message should be printed to the user
                isValidPassword = isValidPasswordPart ( passwordFromInputOriginal , true ) ;
              }
// We will go into this only if we have a valid password.
// We will go back to the beginning of the while loop and start over.
              if ( isValidPassword )
              {
// We have to copy the chars of the passwordFromInputOriginal into the correct char array.
                for ( int i = 0 ; i < passwordFromInputOriginal . length ; i ++ )
                {
                  if ( passwordTypeFile1 . equals ( passwordType ) )
                  {
                    passwordForFile1 [ i ] = passwordFromInputOriginal [ i ] ;
                  }
                  else if ( passwordTypeFile2 . equals ( passwordType ) )
                  {
                    passwordForFile2 [ i ] = passwordFromInputOriginal [ i ] ;
                  }
                  else if ( passwordTypeKey . equals ( passwordType ) )
                  {
                    passwordForKey [ i ] = passwordFromInputOriginal [ i ] ;
                  }
                  else if ( passwordTypeAdmin . equals ( passwordType ) )
                  {
                    passwordForAdmin [ i ] = passwordFromInputOriginal [ i ] ;
                  }
                }
// At this point we can verify the password if it is requested.
                if ( beVerified )
                {
// The character array used for verify the password has to be cleared at first.
                  clearCharArray ( passwordFromInputVerified ) ;
// Now we have to read that password again.
                  passwordFromInputVerified = readpassword ( messageEnterPasswordVerify ) ;
// We will do the verification.
                  if ( passwordFromInputVerified . length != passwordFromInputOriginal . length )
                  {
// If the length of the password are not equals then it is not verified.
                    isVerifiedPassword = false ;
                  }
                  else
                  {
// The length of the two passwords are the same
// so we can start to check the value char by char.
// The value of the isVerifiedPassword no is true.
// It will be changed during this for loop if the first character is found
// that is not the same as the current value in the other char array.
                    for ( int i = 0 ; i < passwordFromInputVerified . length ; i ++ )
                    {
                      if ( passwordFromInputVerified [ i ] != passwordFromInputOriginal [ i ] )
                      {
                        isVerifiedPassword = false ;
                        break ;
                      }
                    }
                  }
// This is necessary.
                  clearCharArray ( passwordFromInputVerified ) ;
// If the verification is not success then the user should be informed
// and the password reading should be started over.
                  if ( ! isVerifiedPassword )
                  {
                    outprintln ( messagePasswordVerificationError ) ;
                  }
                }
              }
// At the end this char array also has to be cleared as at the beginning of this while loop.
              clearCharArray ( passwordFromInputOriginal ) ;
            }
// We have the password finally if we are here.
// We are going to cache the password into the correct object
// if it is necessary, but just after the password purge of course.
            if ( toCachePasswords )
            {
              if ( passwordTypeFile1 . equals ( passwordType ) )
              {
                purgeCachedFilePassword ( fileName ) ;
                cacheFilePassword ( fileName , passwordForFile1 ) ;
              }
              else if ( passwordTypeFile2 . equals ( passwordType ) )
              {
                purgeCachedFilePassword ( fileName ) ;
                cacheFilePassword ( fileName , passwordForFile2 ) ;
              }
              else if ( passwordTypeAdmin . equals ( passwordType ) )
              {
                purgeCachedAdminPassword ( ) ;
                cacheAdminPassword ( passwordForAdmin ) ;
              }
            }
// These can be cleared.
            isValidPassword = false ;
            isVerifiedPassword = false ;
            isPasswordPartAllowed = spaceChar ;
          }
        }
        else
        {
          systemexit ( "Error - invalid filename and the password type is not passwordTypeKey, readPassword" ) ;
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2|passwordTypeKey|passwordTypeAdmin, readPassword" ) ;
      }
    }
    else
    {
      systemexit ( "Error - fileName is null, readPassword" ) ;
    }
// These can be cleared too.
    haveToReadFromConsole = false ;
    cachedPassword = null ;
  }
/*
** Reads the key (name of a password) for the File1 passwordType.
*/
  private static final void readKeyFile1 ( )
  {
// This is needed for the verification and to determine if we should repeat the reading.
// Let it be false to start the reading procedure.
    boolean isValid = false ;
// This is a temp string to store the read value.
    String key = "" ;
// Starting a loop while the given key value is not valid.
    while ( ! isValid )
    {
// Prints the message to the user and waits for the key.
      key = readline ( messageEnterKey , appMaxLengthOfPasswordsAndKeysAndFileNames ) ;
// After this, the key will be validated and an error message
// will be printed if it is not in a correct format.
      isValid = isValidKeyOrFileName ( key , true ) ;
    }
// If we are here, we can set the value of key1.
    key1 = key ;
// These are clearable.
    isValid = false ;
    key = null ;
  }
/*
** Reads the attribute of allowing password parts in a file.
** Prints the question to the user and accept only yes or no answers as it is specified.
** File1 because the File2 or Admin password types don't require this operation.
*/
  private static final void readAllowPasswordPartsFile1 ( )
  {
// Let it be a space char only.
    allowPasswordPartsFile1 = spaceChar ;
// This is a temp string storing the user's answer.
// Empty string by default because in this way we will go into the while cycle.
    String allow = "" ;
// Continuously: repeat the question until the value of the allowPasswordPartsFile1 is not one of the expecteds.
    while ( ! ( allowPasswordPartsFile1 == allowPasswordPartsYes || allowPasswordPartsFile1 == allowPasswordPartsNo ) )
    {
// Printing the question and waiting for the answer.
      allow = readline ( messageAllowPasswordParts , appMaxLengthOfPasswordsAndKeysAndFileNames ) ;
      if ( allow != null )
      {
// If only one character is given..
        if ( allow . length ( ) == 1 )
        {
// Setting the value of the allowPasswordPartsFile1.
// We will check this value in the condition of the while loop.
          allowPasswordPartsFile1 = allow . charAt ( 0 ) ;
        }
      }
      else
      {
        systemexit ( "Error - allow is null, readAllowPasswordPartsFile1" ) ;
      }
    }
// This is not necessary, but we clearing this.
    allow = null ;
  }
/*
** Reading the answers to the questions should be answered by yes.
** Not all of this questions are questioned by this function!
** The reason of that is the different logic.
*/
  private static final boolean readYesElseAnything ( String questionMessage , String notYesMessage )
  {
// Is the answer "yes"? No by default.
    boolean success = false ;
// The message has to be well formatted.
    if ( isASCIIorNEWLINE ( questionMessage ) )
    {
// And this has too.
      if ( isASCIIorNEWLINE ( notYesMessage ) )
      {
        if ( yes != null )
        {
// Now is the point.
// Prompt the user with the question and waiting for the typed answer.
// If the answer is not "yes" then we will print the other message and the success will remain false.
          if ( yes . equals ( readline ( questionMessage , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
          {
// This is the only place to make it true.
            success = true ;
          }
          else
          {
            outprintln ( notYesMessage ) ;
          }
        }
        else
        {
          systemexit ( "Error - yes is null, readYesElseAnything" ) ;
        }
      }
    }
// Returning the result.
    return success ;
  }
/*
** Reads the short description of a backup.
*/
  private static final String readBackupDescription ( )
  {
// This is needed for the verification and to determine if we should repeat the reading.
// Let it be false to start the reading procedure.
    boolean isValid = false ;
// This is a temp string to store the read value.
    String description = "" ;
// Starting a loop while the given description value is not valid.
    while ( ! isValid )
    {
// Prints the message to the user and waits for the description.
      description = readline ( messageEnterBackupDescription , appMaxLengthOfBackupDescription ) ;
// After this, the short description will be validated
      isValid = isValidBackupDescription ( description ) ;
    }
// These are clearable.
    isValid = false ;
// Return this
    return description ;
  }
/*
** Functions for caching the given admin and file passwords if requested.
*/
/*
** Clears all of the admin and file passwords.
*/
  private static final void purgeCachedPasswords ( )
  {
// Clear the admin password.
    purgeCachedAdminPassword ( ) ;
// Clear all of the cached file passwords.
    purgeCachedFilePasswords ( ) ;
  }
/*
** Purges all of the cached file passwords!
*/
  private static final void purgeCachedFilePasswords ( )
  {
    if ( cachedFilePasswords != null )
    {
// Looping on the hashmap. We are going to clear all of the entries!
      for ( HashMap . Entry < String , char [ ] > cachedFilePassword : cachedFilePasswords . entrySet ( ) )
      {
        if ( cachedFilePassword != null )
        {
          if ( cachedFilePassword . getKey ( ) != null )
          {
            if ( cachedFilePassword . getValue ( ) != null )
            {
// This has to be cleared right now!
              clearCharArray ( cachedFilePassword . getValue ( ) ) ;
// Replace this with an empty char array.
              cachedFilePasswords . put ( cachedFilePassword . getKey ( ) , new char [ 0 ] ) ;
            }
            else
            {
              systemexit ( "Error - cachedFilePasswordValue is null, purgeCachedFilePasswords" ) ;
            }
          }
          else
          {
            systemexit ( "Error - cachedFilePasswordKey is null, purgeCachedFilePasswords" ) ;
          }
        }
        else
        {
          systemexit ( "Error - cachedFilePassword is null, purgeCachedFilePasswords" ) ;
        }
      }
    }
    else
    {
      systemexit ( "Error - cachedFilePasswords is null, purgeCachedFilePasswords" ) ;
    }
  }
/*
** Purge the cached file password belongs to fileName
*/
  private static final void purgeCachedFilePassword ( String fileName )
  {
// This has to be valid
    if ( isValidKeyOrFileName ( fileName , false ) )
    {
      if ( cachedFilePasswords != null )
      {
// Looping on the object above, we will search for the cached file password.
        for ( HashMap . Entry < String , char [ ] > cachedFilePassword : cachedFilePasswords . entrySet ( ) )
        {
          if ( cachedFilePassword != null )
          {
            if ( cachedFilePassword . getKey ( ) != null )
            {
              if ( cachedFilePassword . getValue ( ) != null )
              {
// If this entry is he perfect for us: having the expected file name as the key of the hashmap entry.
                if ( cachedFilePassword . getKey ( ) . equals ( fileName ) )
                {
// It always has to be cleared before dereferencing!
                  clearCharArray ( cachedFilePassword . getValue ( ) ) ;
// Change this object into an empty password.
                  cachedFilePasswords . put ( cachedFilePassword . getKey ( ) , new char [ 0 ] ) ;
// Breaking the hashmap loop, we have found our password.
                  break ;
                }
              }
              else
              {
                systemexit ( "Error - cachedFilePasswordValue is null, purgeCachedFilePassword" ) ;
              }
            }
            else
            {
              systemexit ( "Error - cachedFilePasswordKey is null, purgeCachedFilePassword" ) ;
            }
          }
          else
          {
            systemexit ( "Error - cachedFilePassword is null, purgeCachedFilePassword" ) ;
          }
        }
      }
      else
      {
        systemexit ( "Error - cachedFilePasswords is null, purgeCachedFilePassword" ) ;
      }
    }
  }
/*
** Purges the cached admin password.
*/
  private static final void purgeCachedAdminPassword ( )
  {
// This should be happened!
    clearCharArray ( cachedAdminPassword ) ;
// Just reinitialize this variable by a newly created empty password (char array) object.
    cachedAdminPassword = new char [ 0 ] ;
  }
/*
** Create a new password char array by the cached file password and returning it!
*/
  private static final char [ ] getCachedFilePassword ( String fileName )
  {
// This will be the new password char array object.
    char [ ] thePassword = new char [ 0 ] ;
// Will be continued in case of valid file name.
    if ( isValidKeyOrFileName ( fileName , false ) )
    {
      if ( cachedFilePasswords != null )
      {
// Looping on the cachedFilePassword and searching for the correct entry belonging to the file named fileName.
        for ( HashMap . Entry < String , char [ ] > cachedFilePassword : cachedFilePasswords . entrySet ( ) )
        {
          if ( cachedFilePassword != null )
          {
            if ( cachedFilePassword . getKey ( ) != null )
            {
              if ( cachedFilePassword . getValue ( ) != null )
              {
// If this is our entry.
                if ( cachedFilePassword . getKey ( ) . equals ( fileName ) )
                {
// Create a temporary reference into this password array.
                  char [ ] tempPassword = cachedFilePassword . getValue ( ) ;
// If it has at least on e char!
                  if ( tempPassword . length > 0 )
                  {
// If this is a good password value.. (Else purging!)
                    if ( isValidGoodPassword ( tempPassword , false ) )
                    {
// Now we can reinitialize the new password char array by the length of the found file password object.
                      thePassword = new char [ tempPassword . length ] ;
// Copying the characters into the new array
                      for ( int i = 0 ; i < tempPassword . length ; i ++ )
                      {
                        thePassword [ i ] = tempPassword [ i ] ;
                      }
// This date and time is now updated.
                      lastReadOrCacheCachablePassword = new Date ( ) ;
// Break the hashmap loop because we have found our password object.
                      break ;
                    }
                    else
                    {
                      purgeCachedFilePassword ( fileName ) ;
                    }
                  }
// This is not needed any more.
                  tempPassword = null ;
                }
              }
              else
              {
                systemexit ( "Error - cachedFilePasswordValue is null, getCachedFilePassword" ) ;
              }
            }
            else
            {
              systemexit ( "Error - cachedFilePasswordKey is null, getCachedFilePassword" ) ;
            }
          }
          else
          {
            systemexit ( "Error - cachedFilePassword is null, getCachedFilePassword" ) ;
          }
        }
      }
      else
      {
        systemexit ( "Error - cachedFilePasswords is null, getCachedFilePassword" ) ;
      }
    }
// The password will be given back!
    return thePassword ;
  }
/*
** Create a new password char array by the cached admin password and returning it!
*/
  private static final char [ ] getCachedAdminPassword ( )
  {
// This will be the password to give it back.
    char [ ] thePassword = new char [ 0 ] ;
    if ( cachedAdminPassword != null )
    {
// If it is a not empty object!
      if ( cachedAdminPassword . length != 0 )
      {
// If it contains a good password! (Else purge that!)
        if ( isValidGoodPassword ( cachedAdminPassword , true ) )
        {
// The temp password object can be now reinitialized according the length of the cachedAdminPassword
          thePassword = new char [ cachedAdminPassword . length ] ;
// Copy the chars into the new array.
          for ( int i = 0 ; i < cachedAdminPassword . length ; i ++ )
          {
            thePassword [ i ] = cachedAdminPassword [ i ] ;
          }
// This date and time should be now updated.
          lastReadOrCacheCachablePassword = new Date ( ) ;
        }
        else
        {
          purgeCachedAdminPassword ( ) ;
        }
      }
    }
    else
    {
      systemexit ( "Error - cachedAdminPassword is null, getCachedAdminPassword" ) ;
    }
// Giving back the password object.
    return thePassword ;
  }
/*
** Caches a file password to a file.
*/
  private static final void cacheFilePassword ( String fileName , char [ ] password )
  {
// The filename has be valid.
    if ( isValidKeyOrFileName ( fileName , false ) )
    {
// The password has to be valid.
      if ( isValidGoodPassword ( password , true ) )
      {
// This is necessary while it is possible to already have a password to this file.
// It is not a mistake to drop an already empty char array..
        purgeCachedFilePassword ( fileName ) ;
// A temporary character array object.
        char [ ] tempPassword = new char [ password . length ] ;
// Copy the content of the given char array object into this new temp array.
        for ( int i = 0 ; i < password . length ; i ++ )
        {
          tempPassword [ i ] = password [ i ] ;
        }
// This newly created array has to be added into the hashmap of cached file passwords.
        cachedFilePasswords . put ( fileName , tempPassword ) ;
// The reference of the temporary password object can point into nowhere.
        tempPassword = null ;
// This datetime object should be now updated.
        lastReadOrCacheCachablePassword = new Date ( ) ;
      }
    }
  }
/*
** Caches the admin password.
*/
  private static final void cacheAdminPassword ( char [ ] password )
  {
// Only if this is a valid password..
    if ( isValidGoodPassword ( password , true ) )
    {
// We will create a new char array object and copy the characters into it.
      char [ ] tempPassword = new char [ password . length ] ;
// Copying
      for ( int i = 0 ; i < password . length ; i ++ )
      {
        tempPassword [ i ] = password [ i ] ;
      }
// If there is a cached password then it has to be cleared now!
      purgeCachedAdminPassword ( ) ;
// The reference will point into the new object.
      cachedAdminPassword = tempPassword ;
// This reference can point into nowhere.
      tempPassword = null ;
// This date and time is now updated.
      lastReadOrCacheCachablePassword = new Date ( ) ;
    }
  }
/*
** Reinitializing the password cache objects.
*/
  private static final void cachedPasswordsIni ( )
  {
// We are purge all the passwords first.
    purgeCachedPasswords ( ) ;
// Reinitializing the file passwords caching
    cachedFilePasswords = new HashMap < String , char [ ] > ( ) ;
// Reinitializing the admin passwords caching.
    cachedAdminPassword = new char [ 0 ] ;
  }
/*
** Clears the cached admin and file passwords if these are read too many times ago.
** And of course if the password caching is enabled.
*/
  private static final void cachedPasswordsClearIfOld ( )
  {
// This will be the current time.
    Date currentTime = new Date ( ) ;
    if ( currentTime != null )
    {
      if ( lastReadOrCacheCachablePassword != null )
      {
// Do the reinitialization of caching object if the admin and file passwords are read too many times ago.
        if ( ( int ) ( ( currentTime . getTime ( ) - lastReadOrCacheCachablePassword . getTime ( ) ) / 1000 ) > appMaxNotReadCachedPasswordSeconds )
        {
          cachedPasswordsIni ( ) ;
        }
      }
      else
      {
        systemexit ( "Error - lastReadOrCacheCachablePassword is null, cachedPasswordsClearIfOld" ) ;
      }
    }
    else
    {
      systemexit ( "Error - currentTime is null, cachedPasswordsClearIfOld" ) ;
    }
// This is not needed now.
    currentTime = null ;
  }
/*
** Logging functions.
** These will help the content to be constructed and gone into the admin log file.
*/
/*
** Just constructs the beginning of the admin history entries.
** An actual date + sep9 will be returned.
*/
  private static final String getBeginningOfHistoryEntry ( )
  {
    if ( simpleDateFormat != null )
    {
      return ( simpleDateFormat . format ( new Date ( ) ) + sep9 ) ;
    }
    else
    {
      systemexit ( "Error - simpleDateFormat is null, getBeginningOfHistoryEntry" ) ;
      return "" ;
    }
  }
/*
** We will write the string containing the non-sensitive data into the character array.
** This char array will be logged later.
** The sensitive data (passwords) will be appended later.
*/
  private static final void prepareToLog ( char [ ] toLog , String whatToLog )
  {
// This should be ASCII now (at this point it has to contain spaces only.)
    if ( isASCII ( toLog ) )
    {
// This should also has to contain ASCII or newLine characters.
      if ( isASCIIorNEWLINE ( whatToLog ) )
      {
// To be 100% sure of the good length.
        int upper = Math . min ( Math . min ( whatToLog . length ( ) , appMaxLengthToLog ) , toLog . length ) ;
// Writing the string into the array char by char.
        for ( int i = 0 ; i < upper ; i ++ )
        {
          toLog [ i ] = whatToLog . charAt ( i ) ;
        }
// This is not needed now.
        upper = 0 ;
      }
    }
  }
/*
** Writes the message to log into the admin content.
** It will not save the admin file just will handle the content.
*/
  private static final void doLog ( char [ ] toLog )
  {
// ASCII (space included) or newLine characters are acceptable to log!
// Else exit!
    if ( isASCIIorNEWLINE ( toLog ) )
    {
// The length of the logged content is maximized.
// Exit if the content to log are too long.
      if ( toLog . length <= appMaxLengthToLog )
      {
        if ( fileContentAdminOrig != null )
        {
          if ( fileContentAdminOrig . length == appFileContentMaxLength )
          {
// These are necessary to handle the admin content.
            int startPos = - 1 ;
            int newLineCounter = 0 ;
            int endPos = - 1 ;
// At first we have to determine if the current admin content is long enough!
// If the current admin content is long then it may happen that the new content with the toLog char array
// will be longer than appFileContentMaxLength. This is forbidden.
// In this cases (while cycle) we will delete the second entries.
// (The first will be always there because that is the initialization message with date and time.)
// So we check the length of the toLog, can we append it after the current content of admin.
// while this is true, then we will go into this cycle, and delete second entry of the admin content.
            while ( getFirstNewLineAndSpaceCharIndex ( toLog ) > appFileContentMaxLength - 1 - getFirstNewLineAndSpaceCharIndex ( fileContentAdminOrig ) )
            {
// There is no newLine at first!
              newLineCounter = 0 ;
// The starting position is -1 by default at the beginning of while cycle.
              startPos = - 1 ;
// We will searching for the starting position of second entry.
              for ( int i = 0 ; i < fileContentAdminOrig . length ; i ++ )
              {
                if ( fileContentAdminOrig [ i ] == newLineChar )
                {
                  newLineCounter ++ ;
                }
                if ( fileContentAdminOrig [ i ] == newLineChar && newLineCounter == 2 )
                {
                  startPos = i + 1 ;
                  break ;
                }
              }
// Let it be just -1 by default, this will be the ending position of second admin entry.
              endPos = - 1 ;
// Searching for the ending position of the second entry.
// The admin entries are separated by newLine char so we are searching for that from the start pos!
              for ( int i = startPos ; i < fileContentAdminOrig . length ; i ++ )
              {
                if ( fileContentAdminOrig [ i ] == newLineChar )
                {
                  endPos = i + 1 ;
                  break ;
                }
              }
// These are for using the shiftFileContent function.
              int toMoveFromPos = endPos ;
              int toMoveDiff = startPos - endPos ;
// If it is not zero!! (Otherwise the shiftFileContent function will exit the whole application.)
// Else we will break the while cycle.
// So, we are going to shift the admin content to delete the second entry.
// We will grab the index toMoveFromPos of admin content and we will drag it by toMoveDiff.
              if ( toMoveDiff != 0 )
              {
                shiftFileContent ( passwordTypeAdmin , toMoveFromPos , toMoveDiff ) ;
              }
              else
              {
                break ;
              }
// These should be zero at the end.
              toMoveFromPos = 0 ;
              toMoveDiff = 0 ;
// If here, we will check again the changed current admin content and the toLog char array.
// Can we now append the content of toLog after the current admin content? -> beginning of while cycle.
            }
// We are now having the admin content that is in the correct length, we can append the content of toLog.
// This index is the position of last newLine char.
// (first newLine+spaceChar! The regular admin lines never start with space!)
            int lastNewLineCharPos = getFirstNewLineAndSpaceCharIndex ( fileContentAdminOrig ) ;
// This is to be absolutely sure about success.
// This index may be -1 if something wrong has happened -> exiting.
            if ( lastNewLineCharPos != - 1 )
            {
// This is the actual position to append the content of toLog from.
              int posToAppend = lastNewLineCharPos + 1 ;
// We will append the chars of toLog till it is a newLineChar!
// For failsafe considerations, the ending of this append operation will be checked by Math . min.
              for ( int i = 0 ; i < Math . min ( toLog . length , appFileContentMaxLength - posToAppend ) ; i ++ )
              {
                fileContentAdminOrig [ i + posToAppend ] = toLog [ i ] ;
                if ( toLog [ i ] == newLineChar )
                {
                  break ;
                }
              }
// This is not in use any more.
              posToAppend = 0 ;
            }
            else
            {
              systemexit ( "Error - lastNewLineCharPos is wrong, doLog" ) ;
            }
// These are not in use any more.
            lastNewLineCharPos = 0 ;
            startPos = 0 ;
            newLineCounter = 0 ;
            endPos = 0 ;
          }
          else
          {
            systemexit ( "Error - fileContentAdminOrig length proglem, doLog" ) ;
          }
        }
        else
        {
          systemexit ( "Error - fileContentAdminOrig is null, doLog" ) ;
        }
      }
      else
      {
        systemexit ( "Error - Too long content in toLog, doLog" ) ;
      }
    }
    else
    {
      systemexit ( "Error - toLog is not good formatted, doLog" ) ;
    }
  }
/*
** Validator functions
*/
/*
** Is this a valid backup description?
*/
  private static final boolean isValidBackupDescription ( String description )
  {
// False by default
    boolean valid = false ;
// Not null object is required
    if ( description != null )
    {
// ASCII (space included) characters are needed.
      if ( isASCII ( description ) )
      {
// The length of this has to be less than the upper bound.
        if ( description . length ( ) < appMaxLengthOfBackupDescription )
        {
          valid = true ;
        }
      }
    }
// Let's return the validation!
    return valid ;
  }
/*
** Check for a valid password.
** The function writes a message out if the input is not valid and it is requested to print out the message.
** Password char array reference and the boolean values are expected.
** This char array will be validated by the standards of good password.
*/
  private static final boolean isValidGoodPassword ( char [ ] password , boolean messageIfNot )
  {
// The password is not valid by default.
    boolean valid = false ;
// At first this would be ASCII and nonspace.
    if ( isASCIIandNONSPACE ( password ) )
    {
// The length must be between the correct upper and lower bounds.
      if ( password . length <= appMaxLengthOfPasswordsAndKeysAndFileNames )
      {
        if ( password . length >= appGoodPasswordMinLengthOfGoodPasswords )
        {
// The counts of letters will be collected by letter types.
          int countUCLetters = 0 ;
          int countLCLetters = 0 ;
          int countDigits = 0 ;
          int countSpecChars = 0 ;
// Let's count the letters by types.
          for ( int i = 0 ; i < password . length ; i ++ )
          {
            if ( password [ i ] >= 33 && password [ i ] <= 47 )
            {
              countSpecChars ++ ;
            }
            else if ( password [ i ] >= 48 && password [ i ] <= 57 )
            {
              countDigits ++ ;
            }
            else if ( password [ i ] >= 58 && password [ i ] <= 64 )
            {
              countSpecChars ++ ;
            }
            else if ( password [ i ] >= 65 && password [ i ] <= 90 )
            {
              countUCLetters ++ ;
            }
            else if ( password [ i ] >= 91 && password [ i ] <= 96 )
            {
              countSpecChars ++ ;
            }
            else if ( password [ i ] >= 97 && password [ i ] <= 122 )
            {
              countLCLetters ++ ;
            }
            else if ( password [ i ] >= 123 && password [ i ] <= 126 )
            {
              countSpecChars ++ ;
            }
          }
// These counts have to be above the correct bounds
          if ( countUCLetters >= appGoodPasswordMinCountOfUCLetters && countLCLetters >= appGoodPasswordMinCountOfLCLetters && countDigits >= appGoodPasswordMinCountOfDigits && countSpecChars >= appGoodPasswordMinCountOfSpecChars )
          {
// This is the case of valid name. Every other cases are invalid cases.
            valid = true ;
          }
// These should be out of using.
          countUCLetters = 0 ;
          countLCLetters = 0 ;
          countDigits = 0 ;
          countSpecChars = 0 ;
        }
      }
    }
// The message will be written out if it is requested.
    if ( ! valid && messageIfNot )
    {
      outprintln ( messageGoodPasswordIsNotValid ) ;
    }
// Give the validity back.
    return valid ;
  }
/*
** Check for a valid password part.
** The function writes a message out if the input is not valid and it is requested to print out the message.
** Password char array reference and the boolean values are expected.
** This char array won't be validated by the standards of good password.
** (Because it is allowed to use just a part of a valid good password
** so it is not checkable that the whole password is a good password or not.)
*/
  private static final boolean isValidPasswordPart ( char [ ] password , boolean messageIfNot )
  {
// The password part is not valid by default.
    boolean valid = false ;
// At first this would be ASCII and nonspace.
    if ( isASCIIandNONSPACE ( password ) )
    {
// The length must be between the correct upper and lower bounds.
      if ( password . length <= appMaxLengthOfPasswordsAndKeysAndFileNames )
      {
        if ( password . length >= appMinLengthOfPasswordPart )
        {
// This is the case of valid name. Every other cases are invalid cases.
          valid = true ;
        }
      }
    }
// The message will be written out if it is requested.
    if ( ! valid && messageIfNot )
    {
      outprintln ( messagePasswordPartIsNotValid ) ;
    }
// Give the validity back.
    return valid ;
  }
/*
** Check for a valid key or filename.
** The key name and the filename will be validated this single function.
** The function writes a message out if the input is not valid and it is requested to print out the message.
** File or key name and the boolean values are expected.
*/
  private static final boolean isValidKeyOrFileName ( String name , boolean messageIfNot )
  {
// The name is not valid by default.
    boolean valid = false ;
// At first this would be ASCII and nonspace.
    if ( isASCIIandNONSPACE ( name ) )
    {
// The length must be between the correct upper and lower bounds.
      if ( name . length ( ) <= appMaxLengthOfPasswordsAndKeysAndFileNames )
      {
        if ( name . length ( ) >= appMinLengthOfKeysAndFileNames )
        {
// This is the case of valid name. Every other cases are invalid cases.
          valid = true ;
        }
      }
    }
// The message will be written out if it is requested.
    if ( ! valid && messageIfNot )
    {
      outprintln ( messageNameIsNotValid ) ;
    }
// Give the validity back.
    return valid ;
  }
/*
** This is a valid file path or not.
*/
  private static final boolean isValidFilePath ( String filePath )
  {
// The name is not valid by default.
    boolean valid = false ;
// At first this would be ASCII and nonspace.
    if ( isASCII ( filePath ) )
    {
// Valid if the filePath starts and ends as the below.
      if ( ( filePath . startsWith ( appPasswordDir + SEP ) || filePath . startsWith ( appAdminDir + SEP ) || filePath . startsWith ( appBackupDir + SEP ) ) && ( filePath . endsWith ( appPdPostfix ) || filePath . endsWith ( appAnPostfix ) || filePath . endsWith ( appSlPostfix ) || filePath . endsWith ( appIvPostfix ) || filePath . endsWith ( appNwPostfix ) || filePath . endsWith ( appBackupDescriptionFileName ) ) )
      {
        valid = true ;
      }
    }
// Give the validity back.
    return valid ;
  }
/*
** This is a filter to have the good and usable arguments objects.
*/
  private static final boolean isGoodArgsObject ( String [ ] args )
  {
// Let the value true.
    boolean isGood = true ;
    if ( args != null )
    {
// Looping on the args object and checking for ASCII and nonspace members.
      for ( int i = 0 ; i < args . length ; i ++ )
      {
// The first occurrence of NOT (ASCII and nonspace) case means isGood false.
        if ( ! isASCIIandNONSPACE ( args [ i ] ) )
        {
          isGood = false ;
          break ;
        }
      }
    }
    else
    {
      isGood = false ;
    }
// The user gets a message if this args objects is not usable.
    if ( ! isGood )
    {
      usageWrongParameters ( ) ;
    }
// Give this.
    return isGood ;
  }
/*
** Looking for the existing backed up password container file.
*/
  private static final boolean isExistingBackedUpPasswordFile ( String backupName , String fileName , boolean messageIfNot )
  {
    return ( isExistingFile ( appBackupDir + SEP + backupName + SEP + fileName + appPdPostfix , messageIfNot ) && isExistingFile ( appBackupDir + SEP + backupName + SEP + fileName + appIvPostfix , messageIfNot ) && isExistingFile ( appBackupDir + SEP + backupName + SEP + fileName + appSlPostfix , messageIfNot ) ) ;
  }
/*
** Looking for the existing password container file.
*/
  private static final boolean isExistingPasswordFile ( String fileName , boolean messageIfNot )
  {
    return ( isExistingFile ( appPasswordDir + SEP + fileName + appPdPostfix , messageIfNot ) && isExistingFile ( appPasswordDir + SEP + fileName + appIvPostfix , messageIfNot ) && isExistingFile ( appPasswordDir + SEP + fileName + appSlPostfix , messageIfNot ) ) ;
  }
/*
** Looking for the existing admin file.
*/
  private static final boolean isExistingAdminFile ( String fileName , boolean messageIfNot )
  {
    return ( isExistingFile ( appAdminDir + SEP + fileName + appAnPostfix , messageIfNot ) && isExistingFile ( appAdminDir + SEP + fileName + appIvPostfix , messageIfNot ) && isExistingFile ( appAdminDir + SEP + fileName + appSlPostfix , messageIfNot ) ) ;
  }
/*
** Searching for a single file on the disk in the specified file path.
*/
  private static final boolean isExistingFile ( String filePath , boolean messageIfNot )
  {
// Success only at the end.
    boolean success = false ;
    File file = new File ( filePath ) ;
    if ( file != null )
    {
// Success if this file is existing and if it is really a file.
// Else user gets error messages.
      if ( file . exists ( ) )
      {
        if ( file . isFile ( ) )
        {
          success = true ;
        }
        else
        {
          if ( messageIfNot )
          {
            outprintln ( messageFileIsNotFile + filePath ) ;
          }
        }
      }
      else
      {
        if ( messageIfNot )
        {
          outprintln ( messageFileDoesNotExist + filePath ) ;
        }
      }
    }
    else
    {
      systemexit ( "Error - file is null, isExistingFile" ) ;
    }
// This can be released.
    file = null ;
// Returns the result.
    return success ;
  }
/*
** Searching for a folder on the disk in the specified file path.
*/
  private static final boolean isExistingFolder ( String filePath , boolean messageIfNot )
  {
// Success only at the end.
    boolean success = false ;
    File folder = new File ( filePath ) ;
    if ( folder != null )
    {
// Success if this file is existing and if it is not a file.
// Else user gets error messages.
      if ( folder . exists ( ) )
      {
        if ( folder . isDirectory ( ) )
        {
          success = true ;
        }
        else
        {
          if ( messageIfNot )
          {
            outprintln ( messageFolderIsFile + filePath ) ;
          }
        }
      }
      else
      {
        if ( messageIfNot )
        {
          outprintln ( messageFolderDoesNotExist + filePath ) ;
        }
      }
    }
    else
    {
      systemexit ( "Error - folder is null, isExistingFolder" ) ;
    }
// This can be released.
    folder = null ;
// Returns the result.
    return success ;
  }
/*
** ASCII validator functions.
** isASCII means in this application: 32-126 characters. (So space is included.)
** isASCIIorNEWLINE means 32-126 chars or char 10 (newLine)
** isASCIIandNONSPACE means 33-126 chars.
** We know that the set of ASCII characters is a wider set but nobody will type
** for example CR character into its password.
*/
  private static final boolean isASCIIorNEWLINE ( char c )
  {
// Returning immediately with this is a 32-126 characters or newLine character.
    return ( ( c >= 32 && c <= 126 ) || c == 10 ) ;
  }
  private static final boolean isASCIIorNEWLINE ( char [ ] cs )
  {
// This is success by default.
    boolean success = true ;
    if ( cs != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < cs . length ; i ++ )
      {
// 32-126 characters are acceptable and the newLine character.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( ( cs [ i ] >= 32 && cs [ i ] <= 126 ) || cs [ i ] == 10 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
  private static final boolean isASCIIorNEWLINE ( String s )
  {
// This is success by default.
    boolean success = true ;
    if ( s != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < s . length ( ) ; i ++ )
      {
// 32-126 characters are acceptable and the newLine character.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( ( s . charAt ( i ) >= 32 && s . charAt ( i ) <= 126 ) || s . charAt ( i ) == 10 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
  private static final boolean isASCII ( char [ ] cs )
  {
// This is success by default.
    boolean success = true ;
    if ( cs != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < cs . length ; i ++ )
      {
// 32-126 characters are acceptable.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( cs [ i ] >= 32 && cs [ i ] <= 126 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
  private static final boolean isASCII ( String s )
  {
// This is success by default.
    boolean success = true ;
    if ( s != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < s . length ( ) ; i ++ )
      {
// 32-126 characters are acceptable.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( s . charAt ( i ) >= 32 && s . charAt ( i ) <= 126 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
  private static final boolean isASCIIandNONSPACE ( char [ ] cs )
  {
// This is success by default.
    boolean success = true ;
    if ( cs != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < cs . length ; i ++ )
      {
// 33-126 characters are acceptable.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( cs [ i ] >= 33 && cs [ i ] <= 126 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
/*
** Checks the input for ASCII and non-space characters.
*/
  private static final boolean isASCIIandNONSPACE ( String s )
  {
// This is success by default.
    boolean success = true ;
    if ( s != null )
    {
// Cycle on the characters on the input.
      for ( int i = 0 ; i < s . length ( ) ; i ++ )
      {
// 33-126 characters are acceptable.
// If we find the first character that is not like this we will break and return false.
        if ( ! ( s . charAt ( i ) >= 33 && s . charAt ( i ) <= 126 ) )
        {
          success = false ;
          break ;
        }
      }
    }
    else
    {
      success = false ;
    }
// Giving the result back.
    return success ;
  }
/*
** ASCII bytes to chars and chars to bytes functions.
*/
/*
** Converts the chars into bytes.
** It works only in ASCII chars.
*/
  private static final byte [ ] toBytesASCII ( char [ ] chars )
  {
// This will be the bytes array
    byte [ ] bytes = new byte [ 0 ] ;
    if ( chars != null )
    {
// Reinitializing the array into the correct length.
      bytes = new byte [ chars . length ] ;
// Doing the conversion.
      for ( int i = 0 ; i < chars . length ; i ++ )
      {
        bytes [ i ] = ( byte ) chars [ i ] ;
      }
    }
    else
    {
      systemexit ( "Error - chars is null, toBytesASCII" ) ;
    }
// Give this back.
    return bytes ;
  }
/*
** Converts the bytes into chars.
** It works only in ASCII characters.
*/
  private static final char [ ] toCharsASCII ( byte [ ] bytes )
  {
// This will be the chars array.
    char [ ] chars = new char [ 0 ] ;
    if ( bytes != null )
    {
// Reinitializing the array into the correct length.
      chars = new char [ bytes . length ] ;
// Doing the conversion.
      for ( int i = 0 ; i < bytes . length ; i ++ )
      {
        chars [ i ] = ( char ) bytes [ i ] ;
      }
    }
    else
    {
      systemexit ( "Error - bytes is null, toCharsASCII" ) ;
    }
// Give this back.
    return chars ;
  }
/*
** Lower level reading functions.
*/
/*
** Reads a single input line from console and returns with it as a String.
** This is used only in non-interactive mode.
*/
  private static final String readline ( String s , int maxLength )
  {
// This is am empty string at the beginning, this will be the reading.
    String read = "" ;
    if ( s != null )
    {
      if ( console != null )
      {
// The time to type a line is limited!
// Let's create a timestamp.
        Date wait = new Date ( ) ;
        if ( wait != null )
        {
// Waiting for the user's input.
          read = console . readLine ( s ) ;
          if ( read != null )
          {
// Check the waiting time. If it took too long then exit.
            if ( ( int ) ( ( new Date ( ) . getTime ( ) - wait . getTime ( ) ) / 1000 ) > appMaxNotReadInputsSeconds )
            {
              systemexit ( "Error - Waited too long, readline" ) ;
            }
// Also exiting when it is too long.
            if ( read . length ( ) > maxLength )
            {
              systemexit ( "Error - Too long input has been read, readline" ) ;
            }
          }
          else
          {
            systemexit ( "Error - read is null, readline" ) ;
          }
        }
        else
        {
          systemexit ( "Error - wait is null, readline" ) ;
        }
// We don't need this object.
        wait = null ;
      }
      else
      {
        systemexit ( "Error - console is null, readline" ) ;
      }
    }
    else
    {
      systemexit ( "Error - s is null, readline" ) ;
    }
// Returning of the read.
    return read ;
  }
/*
** Reads a single input line from console and returns with it as a String.
** This is used only in interactive mode.
*/
  private static final String readiline ( String s )
  {
// This is am empty string at the beginning, this will be the reading.
    String read = "" ;
    if ( s != null )
    {
      if ( console != null )
      {
// Waiting for the user's input.
        read = console . readLine ( s ) ;
        if ( read != null )
        {
// If this is an ASCII input then we can continue. Or the read will be an empty string.
          if ( isASCII ( read ) )
          {
// Trimming first!
            read = read . trim ( ) ;
// And now checking the correct length of this input. Exiting if it is too long.
            if ( read . length ( ) > appMaxLengthOfPasswordsAndKeysAndFileNames * 3 + 25 )
            {
              systemexit ( "Error - Too long input has been read, readiline" ) ;
            }
          }
          else
          {
            read = "" ;
          }
        }
        else
        {
          systemexit ( "Error - read is null, readiline" ) ;
        }
      }
      else
      {
        systemexit ( "Error - console is null, readiline" ) ;
      }
    }
    else
    {
      systemexit ( "Error - s is null, readiline" ) ;
    }
// Give this.
    return read ;
  }
/*
** Reads a password from the console into char array and returns with it.
*/
  private static final char [ ] readpassword ( String s )
  {
// This will be the char array containing the password.
    char [ ] read = new char [ 0 ] ;
    if ( s != null )
    {
      if ( console != null )
      {
// The time to type a password is limited!
// Let's create a timestamp.
        Date wait = new Date ( ) ;
        if ( wait != null )
        {
// Waiting for the user's input.
          read = console . readPassword ( s ) ;
          if ( read != null )
          {
// Check the waiting time. If it took too long then exit.
            if ( ( int ) ( ( new Date ( ) . getTime ( ) - wait . getTime ( ) ) / 1000 ) > appMaxNotReadInputsSeconds )
            {
              systemexit ( "Error - Waited too long, readpassword" ) ;
            }
// Also exiting when it is too long.
            if ( read . length > appMaxLengthOfPasswordsAndKeysAndFileNames )
            {
              systemexit ( "Error - Too long password has been read, readpassword" ) ;
            }
            else
            {
// Checking the format of the read input.
// We will return an empty password instead of current value of read if it is not correct.
// (Empty password will fail in any validation.)
              if ( ! isASCIIandNONSPACE ( read ) )
              {
                read = new char [ 0 ] ;
              }
            }
// We don't need this object.
            wait = null ;
          }
          else
          {
            systemexit ( "Error - read is null, readpassword" ) ;
          }
        }
        else
        {
          systemexit ( "Error - wait is null, readpassword" ) ;
        }
      }
      else
      {
        systemexit ( "Error - console is null, readpassword" ) ;
      }
    }
    else
    {
      systemexit ( "Error - s is null, readpassword" ) ;
    }
// Returning the password contained character array.
    return read ;
  }
/*
** Character array cleaner methods to clear the class level byte and char arrays!
*/
/*
** Clears all of the used char arrays of the class.
*/
  private static final void clearCharArrays ( )
  {
    clearCharArray ( passwordFromInputOriginal ) ;
    clearCharArray ( passwordFromInputVerified ) ;
    clearCharArray ( passwordForFile1 ) ;
    clearCharArray ( passwordForFile2 ) ;
    clearCharArray ( passwordForKey ) ;
    clearCharArray ( passwordForAdmin ) ;
    clearCharArray ( fileContent1Orig ) ;
    clearCharArray ( fileContent1Trim ) ;
    clearCharArray ( fileContent2Orig ) ;
    clearCharArray ( fileContent2Trim ) ;
    clearCharArray ( fileContentAdminOrig ) ;
    clearCharArray ( fileContentAdminTrim ) ;
  }
/*
** Clears the given char array as fills that by space chars.
*/
  private static final void clearCharArray ( char [ ] charArray )
  {
    if ( charArray != null )
    {
// Filling by space chars.
      for ( int i = 0 ; i < charArray . length ; i ++ )
      {
        charArray [ i ] = spaceChar ;
      }
    }
  }
/*
** Clears all of the used byte arrays of the class.
*/
  private static final void clearByteArrays ( )
  {
    clearByteArray ( sl1 ) ;
    clearByteArray ( iv1 ) ;
    clearByteArray ( sl2 ) ;
    clearByteArray ( iv2 ) ;
    clearByteArray ( slAdmin ) ;
    clearByteArray ( ivAdmin ) ;
  }
/*
** Clears the given byte array as fills that by null bytes.
*/
  private static final void clearByteArray ( byte [ ] byteArray )
  {
    if ( byteArray != null )
    {
// Filling by null bytes.
      for ( int i = 0 ; i < byteArray . length ; i ++ )
      {
        byteArray [ i ] = nullByte ;
      }
    }
  }
/*
** Lower level character array functions.
*/
/*
** Gets the first space char index - 1.
** This is for handling File1 or File2 types of content. (So not for admin file.)
** The passwordType1 or passwordType2 file is not allowed to contain space chars!
** So, when we reach a space char we really reach the end of the content.
** We will hunt for this last character which is not a space char.
** (This will be a newLine char anyway but we won't determine this.)
*/
  private static final int getFirstSpaceCharIndexBefore ( char [ ] orig )
  {
// This will be the last index, not found (-1) by default.
    int index = - 1 ;
    if ( orig != null )
    {
// Searching for the last non-space character.
      for ( int i = 0 ; i < orig . length ; i ++ )
      {
        if ( orig [ i ] == spaceChar )
        {
          index = i - 1 ;
          break ;
        }
      }
    }
    else
    {
      systemexit ( "Error - orig is null, getFirstSpaceCharIndexBefore" ) ;
    }
// Returning the index.
    return index ;
  }
/*
** Gets the position of the last newline+space chars.
** This is used for handling the content of the admin.
** (Since it is allowed to store space chars in the admin file,
** but the lines of the admin file never starts with space char!
** The only time when the admin line starts with a space char
** when it is the last line and contains only space characters!
** This line doesn't go to the saved admin content.)
*/
  private static final int getFirstNewLineAndSpaceCharIndex ( char [ ] orig )
  {
// This will be the index, not found by default.
    int index = - 1 ;
    if ( orig != null )
    {
// Find the newLine+space chars.
      for ( int i = 0 ; i < orig . length - 1 ; i ++ )
      {
        if ( orig [ i ] == newLineChar && orig [ i + 1 ] == spaceChar )
        {
          index = i ;
          break ;
        }
      }
    }
    else
    {
      systemexit ( "Error - orig is null, getFirstNewLineAndSpaceCharIndex" ) ;
    }
    return index ;
  }
/*
** Counts the number of keys in a password container file.
** In case of wrong password type ( for example admin) it returns 0.
*/
  private static final int getNumOfKeysInContent ( String passwordType )
  {
// This will be the number of keys.
    int keysCount = 0 ;
// Only File1 and File2! The Admin typed file does not contain keys to be counted.
    if ( passwordTypeFile1 != null && passwordTypeFile2 != null )
    {
// File1 or File2 is the correct type, else 0 is returned.
      if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
      {
// Because of the structure of the password container files, this is the correct value.
// ( -2: because the first header line and the second stored password type character line have to be not counted.)
// ( /2: because the file contains the key-password values separated by newLine, so 1 password stored by 2 newLine chars.)
        keysCount = ( getNumOfNewLinesInContent ( passwordType ) - 2 ) / 2 ;
      }
    }
    else
    {
      systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2, getNumOfKeysInContent" ) ;
    }
// give this back.
    return keysCount ;
  }
/*
** Counts the new line chars while the next char is not space char.
*/
  private static final int getNumOfNewLinesInContent ( String passwordType )
  {
// This will be the counter.
    int newLineCount = 0 ;
// This is a temporary pointer to use one single char array variable.
    char [ ] fileContentOrig = null ;
    if ( passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeAdmin != null )
    {
// Selecting the correct char array.
      if ( passwordTypeFile1 . equals ( passwordType ) )
      {
        fileContentOrig = fileContent1Orig ;
      }
      else if ( passwordTypeFile2 . equals ( passwordType ) )
      {
        fileContentOrig = fileContent2Orig ;
      }
      else if ( passwordTypeAdmin . equals ( passwordType ) )
      {
        fileContentOrig = fileContentAdminOrig ;
      }
    }
    else
    {
      systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2|passwordTypeAdmin, getNumOfNewLinesInContent" ) ;
    }
// If this point into a not null object..
// Else exiting!
    if ( fileContentOrig != null )
    {
// Counting.
// Will be broken if the next character is a space char.
      for ( int i = 0 ; i < fileContentOrig . length ; i ++ )
      {
        if ( fileContentOrig [ i ] == newLineChar )
        {
          newLineCount ++ ;
        }
        else if ( fileContentOrig [ i ] == spaceChar )
        {
          break ;
        }
      }
    }
    else
    {
      systemexit ( "Error - fileContent is null, getNumOfNewLinesInContent" ) ;
    }
// This is not needed any more.
    fileContentOrig = null ;
// returning the content of the new lines in the content.
    return newLineCount ;
  }
/*
** Shifts the content (by passwordType) from a starting position by the given diff index count.
** This is used when:
** - a key changed
** - a password changed
** - a key is deleted
** - the content of the admin file is too long and the first entries have to be deleted.
** Exit when data will be lost!
*/
  private static final void shiftFileContent ( String passwordType , int startPos , int diff )
  {
// Only when it is not 0!
    if ( diff != 0 )
    {
// This will be the end of the content.
      int lastNonSpaceCharIndexOrig = 0 ;
// This will be the count of the content which are going to be shifted.
      int movedPartCount = 0 ;
// This is for using a single pointer into the correct object!
      char [ ] fileContentOrig = null ;
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeAdmin != null )
      {
// By password types.
// 1: select the correct character array.
// 2: get the last no space index.
// If this is the admin content then the last new line and space char is to be searched for.
        if ( passwordTypeFile1 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent1Orig ;
          lastNonSpaceCharIndexOrig = getFirstSpaceCharIndexBefore ( fileContentOrig ) ;
        }
        else if ( passwordTypeFile2 . equals ( passwordType ) )
        {
          fileContentOrig = fileContent2Orig ;
          lastNonSpaceCharIndexOrig = getFirstSpaceCharIndexBefore ( fileContentOrig ) ;
        }
        else if ( passwordTypeAdmin . equals ( passwordType ) )
        {
          fileContentOrig = fileContentAdminOrig ;
          lastNonSpaceCharIndexOrig = getFirstNewLineAndSpaceCharIndex ( fileContentOrig ) ;
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2|passwordTypeAdmin, shiftFileContent" ) ;
      }
// If this is really not null..
      if ( fileContentOrig != null )
      {
// We know now the count of the moved part of the content char array.
        movedPartCount = lastNonSpaceCharIndexOrig - startPos + 1 ;
// So we can create a temporary char array to store this.
        char [ ] movedPart = new char [ movedPartCount ] ;
// Clear this: let the characters to be space chars by default.
        clearCharArray ( movedPart ) ;
// trying to fill the movedPart char array with the actual moved part.
        for ( int i = startPos ; i <= lastNonSpaceCharIndexOrig ; i ++ )
        {
          movedPart [ i - startPos ] = fileContentOrig [ i ] ;
        }
// Before writing we would like to ensure that the data will be not lost!
// We will not try to write a part of the moved content before the file content
        if ( startPos + diff >= 0 )
        {
// We will not try to write a part of the moved content after the file content
          if ( startPos + diff + ( movedPart . length - 1 ) < fileContentOrig . length )
          {
// And now write it back into the content char array into the correct new position.
            for ( int i = 0 ; i < movedPart . length ; i ++ )
            {
              fileContentOrig [ startPos + diff + i ] = movedPart [ i ] ;
            }
// The final step is clear the correct chars depending on the diff.
// If we took the chars backward then the rest of the char array must be cleared after the moved part.
// Clear: fill with space characters.
            if ( diff < 0 )
            {
              for ( int i = startPos + diff + movedPartCount ; i <= lastNonSpaceCharIndexOrig ; i ++ )
              {
                fileContentOrig [ i ] = spaceChar ;
              }
            }
// If we took the chars forward then we have to clear the content before the moved part.
// It is taken from the start pos to count moved part count or diff, to which has the smallest count.
            else if ( diff > 0 )
            {
              for ( int i = startPos ; i < startPos + Math . min ( movedPartCount , diff ) ; i ++ )
              {
                fileContentOrig [ i ] = spaceChar ;
              }
            }
          }
          else
          {
            systemexit ( "Error - Writing after content, shiftFileContent" ) ;
          }
        }
        else
        {
          systemexit ( "Error - Write before content, shiftFileContent" ) ;
        }
// The movedPart array is a temp char array, its content must be cleared.
        clearCharArray ( movedPart ) ;
// And the char array must be set to null.
        movedPart = null ;
      }
      else
      {
        systemexit ( "Error - fileContentOrig is null, shiftFileContent" ) ;
      }
// These variables are not needed.
      fileContentOrig = null ;
      lastNonSpaceCharIndexOrig = 0 ;
      movedPartCount = 0 ;
    }
  }
/*
** The encrypted file reading and encrypted file writing functions!
*/
/*
** Getting the content of a file.
** This file can be a password container file or the admin file.
** The fileName string tells the name of the file.
** (In case of admin type passwordTypeAdmin the file path points into the admin folder.)
** The passwordTypeAdmin tells the type of the file:
** passwordTypeFile1
** passwordTypeFile2
** passwordTypeFileAdmin
** The successful operation is set after the header has been successfully found in the
** decrypted content.
*/
  private static final boolean getFileContent ( String fileName , String passwordType )
  {
// This is a boolean function so here is the returning value.
// False because we will set it to true only at the end. (header found)
    boolean success = false ;
// The fileName must be valid to continue.
    if ( isValidKeyOrFileName ( fileName , false ) )
    {
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeAdmin != null )
      {
// We can continue only if we have all of the necessary files: main (pd or an), sl and iv.
        if ( ( ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) ) && isExistingPasswordFile ( fileName , false ) ) || ( passwordTypeAdmin . equals ( passwordType ) && isExistingAdminFile ( appAdminFileName , false ) ) )
        {
// File1, File2 or Admin are the possible choices.
// We are going to clear the character arrays (just for to be sure),
// reinitialize the array and clear again the character array.
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            clearCharArray ( fileContent1Orig ) ;
            fileContent1Orig = new char [ appFileContentMaxLength ] ;
            clearCharArray ( fileContent1Orig ) ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            clearCharArray ( fileContent2Orig ) ;
            fileContent2Orig = new char [ appFileContentMaxLength ] ;
            clearCharArray ( fileContent2Orig ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            clearCharArray ( fileContentAdminOrig ) ;
            fileContentAdminOrig = new char [ appFileContentMaxLength ] ;
            clearCharArray ( fileContentAdminOrig ) ;
          }
// Now we have to read the sl and iv bytes from the disk.
// This is also by the type of passwordType: File1, File2, Admin
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            sl1 = readFileBytes ( appPasswordDir + SEP + fileName + appSlPostfix ) ;
            if ( sl1 == null )
            {
              systemexit ( "Error - sl1 is null, getFileContent" ) ;
            }
            else if ( sl1 . length == 0 )
            {
              systemexit ( "Error - sl1 is empty, getFileContent" ) ;
            }
            iv1 = readFileBytes ( appPasswordDir + SEP + fileName + appIvPostfix ) ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            sl2 = readFileBytes ( appPasswordDir + SEP + fileName + appSlPostfix ) ;
            if ( sl2 == null )
            {
              systemexit ( "Error - sl2 is null, getFileContent" ) ;
            }
            else if ( sl2 . length == 0 )
            {
              systemexit ( "Error - sl2 is empty, getFileContent" ) ;
            }
            iv2 = readFileBytes ( appPasswordDir + SEP + fileName + appIvPostfix ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            slAdmin = readFileBytes ( appAdminDir + SEP + fileName + appSlPostfix ) ;
            if ( slAdmin == null )
            {
              systemexit ( "Error - slAdmin is null, getFileContent" ) ;
            }
            else if ( slAdmin . length == 0 )
            {
              systemexit ( "Error - slAdmin is empty, getFileContent" ) ;
            }
            ivAdmin = readFileBytes ( appAdminDir + SEP + fileName + appIvPostfix ) ;
          }
// We are going to initialize the SecretKeyFactory object.
// Will get a nice exception if it is not correct on the computer and exit.
          SecretKeyFactory skf = null ;
          try
          {
            skf = SecretKeyFactory . getInstance ( appSecretKeyFactoryInstance ) ;
          }
          catch ( NoSuchAlgorithmException e )
          {
            systemexit ( "Exception - NoSuchAlgorithmException0, getFileContent" ) ;
          }
          if ( skf == null )
          {
            systemexit ( "Error - skf is null, getFileContent" ) ;
          }
// Now the next is the PBEKeySpec object.
// The salt and the password will be used as you can see.
          PBEKeySpec pbeks = null ;
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            pbeks = new PBEKeySpec ( passwordForFile1 , sl1 , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            pbeks = new PBEKeySpec ( passwordForFile2 , sl2 , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            pbeks = new PBEKeySpec ( passwordForAdmin , slAdmin , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
          }
          if ( pbeks == null )
          {
            systemexit ( "Error - pbeks is null, getFileContent" ) ;
          }
// The secret key is on the way.
// Exception and exit if it is not created successfully.
          SecretKey sk = null ;
          try
          {
            sk = skf . generateSecret ( pbeks ) ;
          }
          catch ( InvalidKeySpecException e )
          {
            systemexit ( "Exception - InvalidKeySpecException, getFileContent" ) ;
          }
          if ( sk == null )
          {
            systemexit ( "Error - sk is null, getFileContent" ) ;
          }
// The SecretKeySpec is the next after the SecretKey.
          SecretKeySpec sks = new SecretKeySpec ( sk . getEncoded ( ) , appSecretKeySpecAlgorythm ) ;
// We are almost there, the cipher will be initialized soon.
// Exiting if it will be not successful.
          Cipher cipher = null ;
          try
          {
            cipher = Cipher . getInstance ( appCipherInstance ) ;
          }
          catch ( NoSuchAlgorithmException e )
          {
            systemexit ( "Exception - NoSuchAlgorithmException1, getFileContent" ) ;
          }
          catch ( NoSuchPaddingException e )
          {
            systemexit ( "Exception - NoSuchPaddingException, getFileContent" ) ;
          }
          if ( cipher != null )
          {
// The IvParameterSpec is needed to cipher init, let's create it by passwordTypes
            IvParameterSpec ips = null ;
            if ( passwordTypeFile1 . equals ( passwordType ) )
            {
              ips = new IvParameterSpec ( iv1 ) ;
            }
            else if ( passwordTypeFile2 . equals ( passwordType ) )
            {
              ips = new IvParameterSpec ( iv2 ) ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              ips = new IvParameterSpec ( ivAdmin ) ;
            }
            if ( ips == null )
            {
              systemexit ( "Error - ips is null, getFileContent" ) ;
            }
// The cipher object is now ready to initialize for decryption!
// Let's do this!
// Exception and exit in case of InvalidAlgorithmParameter
// Message to the user if the Key is invalid (we will continue at this time.)
            try
            {
              cipher . init ( Cipher . DECRYPT_MODE , sks , ips ) ;
            }
            catch ( InvalidAlgorithmParameterException e )
            {
              systemexit ( "Exception - InvalidAlgorithmParameterException, getFileContent" ) ;
            }
            catch ( InvalidKeyException e )
            {
              systemexit ( "Exception - InvalidKeyException, getFileContent" ) ;
            }
// These are the byte array objects we want to use.
// bytes and decrypted bytes.
            byte [ ] decryptedBytes = null ;
            byte [ ] bytes = null ;
// The (now encrypted) bytes comes from the disk.
// File1 and File2 are pd type of files and Admin is the an type of file.
            if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
            {
              bytes = readFileBytes ( appPasswordDir + SEP + fileName + appPdPostfix ) ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              bytes = readFileBytes ( appAdminDir + SEP + fileName + appAnPostfix ) ;
            }
// We are trying to decrypt the encrypted byte array.
// Exception and exit when IllegalBlockSize
// Message to the user if BadPaddingException has occurred.
            try
            {
              decryptedBytes = cipher . doFinal ( bytes ) ;
            }
            catch ( IllegalBlockSizeException e )
            {
              systemexit ( "Exception - IllegalBlockSizeException, getFileContent" ) ;
            }
            catch ( BadPaddingException e )
            {
              outprintln ( messageIncorrectFilePassword + fileName ) ;
            }
// These objects are not needed any more.
            ips = null ;
            cipher = null ;
            sks = null ;
            sk = null ;
            pbeks = null ;
            skf = null ;
// Searching for header just to be sure about the successful decryption.
// The header is not found by default.
            boolean headerFound = false ;
            if ( decryptedBytes != null )
            {
// We can now read the bytes we have decrypted.
// Do the conversion.
              char [ ] tempChar = toCharsASCII ( decryptedBytes ) ;
// This byte array will be read into the correct type of content character array.
// The header will be searched during this.
// The appFileContentMaxLength will be used just to be absolutely sure about having the
// correct maximum size of content.
              if ( passwordTypeFile1 . equals ( passwordType ) )
              {
                for ( int i = 0 ; i < Math . min ( tempChar . length , appFileContentMaxLength ) ; i ++ )
                {
                  fileContent1Orig [ i ] = tempChar [ i ] ;
                }
                headerFound = isContentDecrypted ( passwordTypeFile1 ) ;
              }
              else if ( passwordTypeFile2 . equals ( passwordType ) )
              {
                for ( int i = 0 ; i < Math . min ( tempChar . length , appFileContentMaxLength ) ; i ++ )
                {
                  fileContent2Orig [ i ] = tempChar [ i ] ;
                }
                headerFound = isContentDecrypted ( passwordTypeFile2 ) ;
              }
              else if ( passwordTypeAdmin . equals ( passwordType ) )
              {
                for ( int i = 0 ; i < Math . min ( tempChar . length , appFileContentMaxLength ) ; i ++ )
                {
                  fileContentAdminOrig [ i ] = tempChar [ i ] ;
                }
                headerFound = isContentDecrypted ( passwordTypeAdmin ) ;
              }
// This temporary character array will be not used any more, can be cleared.
              clearCharArray ( tempChar ) ;
              tempChar = null ;
// The decrypted byte array is not needed too,
// and we have to clear it right now.
// We do not want to have this in the memory.
              clearByteArray ( decryptedBytes ) ;
              decryptedBytes = null ;
            }
            else
            {
              headerFound = false ;
            }
// The original byte array can be cleared.
            clearByteArray ( bytes ) ;
            bytes = null ;
// If we have the found header then we are good.
// The user gets a message if not.
            if ( headerFound )
            {
              if ( filesHeader != null )
              {
// Getting the character for using it later.
// The password part is allowed in the file or not.
// File1 and File2 passwordType only, There is no such a character in the admin file.
                if ( passwordTypeFile1 . equals ( passwordType ) )
                {
                  if ( fileContent1Orig != null )
                  {
                    allowPasswordPartsFile1 = fileContent1Orig [ filesHeader . length ( ) ] ;
                  }
                  else
                  {
                    systemexit ( "Error - fileContent1Orig is null, getFileContent" ) ;
                  }
                }
                else if ( passwordTypeFile2 . equals ( passwordType ) )
                {
                  if ( fileContent2Orig != null )
                  {
                    allowPasswordPartsFile2 = fileContent2Orig [ filesHeader . length ( ) ] ;
                  }
                  else
                  {
                    systemexit ( "Error - fileContent2Orig is null, getFileContent" ) ;
                  }
                }
// It is successfully finished if we are here!
                success = true ;
              }
              else
              {
                systemexit ( "Error - filesHeader is null, getFileContent" ) ;
              }
            }
            else
            {
              outprintln ( messageFileContentHasNotBeenFound + fileName ) ;
            }
// This is not necessary but..
            headerFound = false ;
          }
          else
          {
            systemexit ( "Error - cipher is null, getFileContent" ) ;
          }
        }
        else
        {
// We are not started yet because some file is missing.
// Message to the user: File1 and File2 types or Admin type.
          if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
          {
            outprintln ( messageMissingPwOrSlOrIvFile + fileName ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            outprintln ( messageMissingAnOrSlOrIvFile + fileName ) ;
          }
        }
// If it is not successful.
// The password of the password container file or the admin file may be cached.
// Now, we are trying to release this cached password if exists.
// If the above things are successful, the password can stay if we have passwords cache command executed.
        if ( ! success )
        {
          if ( toCachePasswords )
          {
// So, if we are not successful and we are caching files and admin passwords
// then this password should be forgotten.
// (The reason may be that the password hasn't been correct.)
            if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
            {
              purgeCachedFilePassword ( fileName ) ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              purgeCachedAdminPassword ( ) ;
            }
          }
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2|passwordTypeAdmin, getFileContent" ) ;
      }
    }
// The return of the success.
    return success ;
  }
/*
** Is the content being decrypted?
*/
  private static final boolean isContentDecrypted ( String passwordType )
  {
// This is true by default!
    boolean headerFound = true ;
// By password types: looping on the characters of the correct content
// and check for the correct char in the correct header string.
// Also check for the correct length of the content!
    if ( fileContent1Orig != null && fileContent2Orig != null && fileContentAdminOrig != null && filesHeader != null && adminHeader != null && passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeAdmin != null )
    {
      if ( passwordTypeFile1 . equals ( passwordType ) )
      {
        if ( fileContent1Orig . length == appFileContentMaxLength )
        {
          for ( int i = 0 ; i < filesHeader . length ( ) ; i ++ )
          {
            if ( fileContent1Orig [ i ] != filesHeader . charAt ( i ) )
            {
              headerFound = false ;
              break ;
            }
          }
        }
        else
        {
          headerFound = false ;
        }
      }
      else if ( passwordTypeFile2 . equals ( passwordType ) )
      {
        if ( fileContent2Orig . length == appFileContentMaxLength )
        {
          for ( int i = 0 ; i < filesHeader . length ( ) ; i ++ )
          {
            if ( fileContent2Orig [ i ] != filesHeader . charAt ( i ) )
            {
              headerFound = false ;
              break ;
            }
          }
        }
        else
        {
          headerFound = false ;
        }
      }
      else if ( passwordTypeAdmin . equals ( passwordType ) )
      {
        if ( fileContentAdminOrig . length == appFileContentMaxLength )
        {
          for ( int i = 0 ; i < adminHeader . length ( ) ; i ++ )
          {
            if ( fileContentAdminOrig [ i ] != adminHeader . charAt ( i ) )
            {
              headerFound = false ;
              break ;
            }
          }
        }
        else
        {
          headerFound = false ;
        }
      }
      else
      {
        headerFound = false ;
      }
    }
    else
    {
      systemexit ( "Error - One of these is null: fileContent1Orig|fileContent2Orig|fileContentAdminOrig|filesHeader|adminHeader|passwordTypeFile1|passwordTypeFile2|passwordTypeAdmin, isContentDecrypted" ) ;
    }
// Message if it is not decrypted.
    if ( ! headerFound )
    {
      outprintln ( messageContentIsNotDecrypted + passwordType ) ;
    }
// Returning the result.
    return headerFound ;
  }
/*
** This is the file saving function.
** Encrypts the data according to the given arguments and saves the data into NEW files!
** Another function (removeOldFilesAndRenameNewFiles) can handle the deleting of old files
** and renaming the new files into the old filenames.
** This is for failsafe considerations. If any of the operation will be failed then the
** old files are still there!
** In every saving operation the content will be written into a NEW file!
** The salt and the initialization vector bytes are also will be generated in every saving operation!
** The file name (string) and the password type are expected (File1, File2 or Admin).
*/
  private static final boolean saveFile ( String fileName , String passwordType )
  {
// Successful only at the end!
    boolean success = false ;
// This is necessary to have a correct file name.
    if ( isValidKeyOrFileName ( fileName , false ) )
    {
      if ( passwordTypeFile1 != null && passwordTypeFile2 != null && passwordTypeAdmin != null )
      {
// Our secure random object to generate safe random values.
        SecureRandom secureRandom = new SecureRandom ( ) ;
        if ( secureRandom != null )
        {
// The salt will be generated and written to disk (into new file) according to the password type.
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            sl1 = new byte [ appSaltLength ] ;
            secureRandom . nextBytes ( sl1 ) ;
            writeFileBytes ( appPasswordDir + SEP + fileName + appSlPostfix + appNwPostfix , sl1 ) ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            sl2 = new byte [ appSaltLength ] ;
            secureRandom . nextBytes ( sl2 ) ;
            writeFileBytes ( appPasswordDir + SEP + fileName + appSlPostfix + appNwPostfix , sl2 ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            slAdmin = new byte [ appSaltLength ] ;
            secureRandom . nextBytes ( slAdmin ) ;
            writeFileBytes ( appAdminDir + SEP + fileName + appSlPostfix + appNwPostfix , slAdmin ) ;
          }
        }
        else
        {
          systemexit ( "Error - secureRandom is null, saveFile" ) ;
        }
// This is done, we are not going to use this below.
        secureRandom = null ;
// We need a SecretKeyFactory object.
// Exception and exit if we cannot have this.
        SecretKeyFactory skf = null ;
        try
        {
          skf = SecretKeyFactory . getInstance ( appSecretKeyFactoryInstance ) ;
        }
        catch ( NoSuchAlgorithmException e )
        {
          systemexit ( "Exception - NoSuchAlgorithmException0, saveFile" ) ;
        }
        if ( skf == null )
        {
          systemexit ( "Error - skf is null, saveFile" ) ;
        }
// The next is the PBEKeySpec object depending on the current calling of this function.
        PBEKeySpec pbeks = null ;
        if ( passwordTypeFile1 . equals ( passwordType ) )
        {
          pbeks = new PBEKeySpec ( passwordForFile1 , sl1 , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
        }
        else if ( passwordTypeFile2 . equals ( passwordType ) )
        {
          pbeks = new PBEKeySpec ( passwordForFile2 , sl2 , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
        }
        else if ( passwordTypeAdmin . equals ( passwordType ) )
        {
          pbeks = new PBEKeySpec ( passwordForAdmin , slAdmin , appPbeKeySpecIterations , appPbeKeySpecKeyLength ) ;
        }
        if ( pbeks == null )
        {
          systemexit ( "Error - pbeks is null, saveFile" ) ;
        }
// We need a SecretKey too according this pbeks above.
// Exception and exit if it cannot be done.
        SecretKey sk = null ;
        try
        {
          sk = skf . generateSecret ( pbeks ) ;
        }
        catch ( InvalidKeySpecException e )
        {
          systemexit ( "Exception - InvalidKeyException, saveFile" ) ;
        }
        if ( sk == null )
        {
          systemexit ( "Error - sk is null, saveFile" ) ;
        }
// Almost there, the SecretKeySpec object is the next.
        SecretKeySpec sks = new SecretKeySpec ( sk . getEncoded ( ) , appSecretKeySpecAlgorythm ) ;
        if ( sks == null )
        {
          systemexit ( "Error - sks is null, saveFile" ) ;
        }
// Now trying to create the cipher object.
// Exception and exit too when it is not successful.
        Cipher cipher = null ;
        try
        {
          cipher = Cipher . getInstance ( appCipherInstance ) ;
        }
        catch ( NoSuchAlgorithmException e )
        {
          systemexit ( "Exception - NoSuchAlgorithmException1, saveFile" ) ;
        }
        catch ( NoSuchPaddingException e )
        {
          systemexit ( "Exception - NoSuchPaddingException, saveFile" ) ;
        }
        if ( cipher != null )
        {
// Now we are ready to initialize our cipher instance.
// Exception and exit if it is not successful.
          try
          {
            cipher . init ( Cipher . ENCRYPT_MODE , sks ) ;
          }
          catch ( InvalidKeyException e )
          {
            systemexit ( "Exception - InvalidKeyException, saveFile" ) ;
          }
// This object is needed to store the iv.
          AlgorithmParameters ap = cipher . getParameters ( ) ;
          if ( ap != null )
          {
// The iv will be cached into the correct byte array and will be saved onto the disk.
// The whole process will be broken in case of InvalidParameterSpecException.
            if ( passwordTypeFile1 . equals ( passwordType ) )
            {
              try
              {
                iv1 = ap . getParameterSpec ( IvParameterSpec . class ) . getIV ( ) ;
              }
              catch ( InvalidParameterSpecException e )
              {
                systemexit ( "Exception - InvalidParameterSpecException0, saveFile" ) ;
              }
              writeFileBytes ( appPasswordDir + SEP + fileName + appIvPostfix + appNwPostfix , iv1 ) ;
            }
            else if ( passwordTypeFile2 . equals ( passwordType ) )
            {
              try
              {
                iv2 = ap . getParameterSpec ( IvParameterSpec . class ) . getIV ( ) ;
              }
              catch ( InvalidParameterSpecException e )
              {
                systemexit ( "Exception - InvalidParameterSpecException1, saveFile" ) ;
              }
              writeFileBytes ( appPasswordDir + SEP + fileName + appIvPostfix + appNwPostfix , iv2 ) ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              try
              {
                ivAdmin = ap . getParameterSpec ( IvParameterSpec . class ) . getIV ( ) ;
              }
              catch ( InvalidParameterSpecException e )
              {
                systemexit ( "Exception - InvalidParameterSpecException2, saveFile" ) ;
              }
              writeFileBytes ( appAdminDir + SEP + fileName + appIvPostfix + appNwPostfix , ivAdmin ) ;
            }
          }
          else
          {
            systemexit ( "Error - ap is null, saveFile" ) ;
          }
// This object can be null now.
          ap = null ;
// The byte arrays are the following.
// The (original) bytes and the encrypted bytes, nulls at first.
          byte [ ] encryptedBytes = null ;
          byte [ ] bytes = null ;
// We have to know what is the end index of the original character array!
// (the further characters are spaces to the end of the array
// and we do not want to store these space chars in the encrypted content.)
// File1 and File2: last non-space char index is missing
// this will be a single newLine anyway, the end of the last password.
// Admin content: since it is allowed to store space character in the admin file,
// the last newLine and space character is missing.
          int endIndex = 0 ;
// By password types.
// 1: getting the endIndex.
// 2: clearing, reinitializing and clearing again the correct character array.
// 3: The content of the orig char array will be copied into the trim char array,
// but without the last space chars!! (for loop)
// 4: converting to byte array and place this into the bytes array
          if ( passwordTypeFile1 . equals ( passwordType ) )
          {
            endIndex = getFirstSpaceCharIndexBefore ( fileContent1Orig ) ;
            clearCharArray ( fileContent1Trim ) ;
            fileContent1Trim = new char [ endIndex + 1 ] ;
            clearCharArray ( fileContent1Trim ) ;
            for ( int i = 0 ; i < fileContent1Trim . length ; i ++ )
            {
              fileContent1Trim [ i ] = fileContent1Orig [ i ] ;
            }
            bytes = toBytesASCII ( fileContent1Trim ) ;
          }
          else if ( passwordTypeFile2 . equals ( passwordType ) )
          {
            endIndex = getFirstSpaceCharIndexBefore ( fileContent2Orig ) ;
            clearCharArray ( fileContent2Trim ) ;
            fileContent2Trim = new char [ endIndex + 1 ] ;
            clearCharArray ( fileContent2Trim ) ;
            for ( int i = 0 ; i < fileContent2Trim . length ; i ++ )
            {
              fileContent2Trim [ i ] = fileContent2Orig [ i ] ;
            }
            bytes = toBytesASCII ( fileContent2Trim ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            endIndex = getFirstNewLineAndSpaceCharIndex ( fileContentAdminOrig ) ;
            clearCharArray ( fileContentAdminTrim ) ;
            fileContentAdminTrim = new char [ endIndex + 1 ] ;
            clearCharArray ( fileContentAdminTrim ) ;
            for ( int i = 0 ; i < fileContentAdminTrim . length ; i ++ )
            {
              fileContentAdminTrim [ i ] = fileContentAdminOrig [ i ] ;
            }
            bytes = toBytesASCII ( fileContentAdminTrim ) ;
          }
// The final step is the following: encrypt the bytes array into the encryptedBytes!
// Exception and exit in case of failure.
          try
          {
            encryptedBytes = cipher . doFinal ( bytes ) ;
          }
          catch ( IllegalBlockSizeException e )
          {
            systemexit ( "Exception - IllegalBlockSizeException, saveFile" ) ;
          }
          catch ( BadPaddingException e )
          {
            systemexit ( "Exception - BadPaddingException, saveFile" ) ;
          }
// The encrypted bytes have to be written to the disk (into new file!)
// next to the earlier written and also new sl and iv files.
          if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
          {
            writeFileBytes ( appPasswordDir + SEP + fileName + appPdPostfix + appNwPostfix , encryptedBytes ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            writeFileBytes ( appAdminDir + SEP + fileName + appAnPostfix + appNwPostfix , encryptedBytes ) ;
          }
// These byte arrays have to be cleared!
          clearByteArray ( encryptedBytes ) ;
          encryptedBytes = null ;
          clearByteArray ( bytes ) ;
          bytes = null ;
        }
        else
        {
          systemexit ( "Error - cipher is null, saveFile" ) ;
        }
// These variables have to be set to null now.
        cipher = null ;
        sks = null ;
        sk = null ;
        pbeks = null ;
        skf = null ;
// It is important to clear these content (orig and trim)!
// They are not welcome being in the memory any more!
// The sl and iv byte arrays can be still there
// (they are on the disk so they are not sensitive data)
// but we will clear them too.
        if ( passwordTypeFile1 . equals ( passwordType ) )
        {
          clearCharArray ( fileContent1Orig ) ;
          clearCharArray ( fileContent1Trim ) ;
          clearByteArray ( sl1 ) ;
          clearByteArray ( iv1 ) ;
        }
        else if ( passwordTypeFile2 . equals ( passwordType ) )
        {
          clearCharArray ( fileContent2Orig ) ;
          clearCharArray ( fileContent2Trim ) ;
          clearByteArray ( sl2 ) ;
          clearByteArray ( iv2 ) ;
        }
        else if ( passwordTypeAdmin . equals ( passwordType ) )
        {
          clearCharArray ( fileContentAdminOrig ) ;
          clearCharArray ( fileContentAdminTrim ) ;
          clearByteArray ( slAdmin ) ;
          clearByteArray ( ivAdmin ) ;
        }
// We will use these objects, by password type.
        File fileNew = null ;
        File slFileNew = null ;
        File ivFileNew = null ;
// Searching for new files. (appNwPostfix postfix!).
        if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
        {
          fileNew = new File ( appPasswordDir + SEP + fileName + appPdPostfix + appNwPostfix ) ;
          slFileNew = new File ( appPasswordDir + SEP + fileName + appSlPostfix + appNwPostfix ) ;
          ivFileNew = new File ( appPasswordDir + SEP + fileName + appIvPostfix + appNwPostfix ) ;
        }
        else if ( passwordTypeAdmin . equals ( passwordType ) )
        {
          fileNew = new File ( appAdminDir + SEP + fileName + appAnPostfix + appNwPostfix ) ;
          slFileNew = new File ( appAdminDir + SEP + fileName + appSlPostfix + appNwPostfix ) ;
          ivFileNew = new File ( appAdminDir + SEP + fileName + appIvPostfix + appNwPostfix ) ;
        }
        if ( fileNew != null && slFileNew != null && ivFileNew != null )
        {
// These files above have to be existing!
          if ( fileNew . exists ( ) && slFileNew . exists ( ) && ivFileNew . exists ( ) )
          {
// We are almost finished.
// Removing the old files and renaming the new files into old file names are the remaining tasks.
// removeOldFilesAndRenameNewFiles function has to be returned as true!
            if ( removeOldFilesAndRenameNewFiles ( fileName , passwordType ) )
            {
// The saving operation is successfully done at this point.
              success = true ;
// The message can be printed out to the user.
              outprintln ( messageFileHasBeenSaved + fileName ) ;
            }
          }
          else
          {
// We are here because the saving operation has been not successful.
// We are printing a message to the user.
// File1 - File2 or Admin password type.
            if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
            {
              outprintln ( messageMissingNewPwOrSlOrIvFile ) ;
            }
            else if ( passwordTypeAdmin . equals ( passwordType ) )
            {
              outprintln ( messageMissingNewAnOrSlOrIvFile ) ;
            }
// We have to clean the mess we just have created.
// NEW files are going to be deleted.
// The old ones are untouched.
            if ( fileNew . exists ( ) )
            {
              if ( ! fileNew . delete ( ) )
              {
                outprintln ( messageErrorDeletingNewPwFile ) ;
              }
            }
            if ( slFileNew . exists ( ) )
            {
              if ( ! slFileNew . delete ( ) )
              {
                outprintln ( messageErrorDeletingNewSlFile ) ;
              }
            }
            if ( ivFileNew . exists ( ) )
            {
              if ( ! ivFileNew . delete ( ) )
              {
                outprintln ( messageErrorDeletingNewIvFile ) ;
              }
            }
          }
        }
        else
        {
          systemexit ( "Error - One of these is null: fileNew|slFileNew|ivFileNew, saveFile" ) ;
        }
// This variables are null now.
        fileNew = null ;
        slFileNew = null ;
        ivFileNew = null ;
      }
      else
      {
        systemexit ( "Error - One of these is null: passwordTypeFile1|passwordTypeFile2|passwordTypeAdmin, saveFile" ) ;
      }
    }
// Let the function return to caller.
    return success ;
  }
/*
** All the file operations can be rolled back.
** The modifications will be saved into new files at first.
** (-> not in this function! That is in the fileSave function.)
** If this operation can be successfully finished then the old files will be deleted
** ((pd or an) and sl and iv) and the new files will be renamed to the old file names.
** (-> this is in this function.)
*/
  private static final boolean removeOldFilesAndRenameNewFiles ( String fileName , String passwordType )
  {
// This is the variable which can be returned. False by default.
// It can be true just at the end.
    boolean success = false ;
// This is the validation of fileName string.
// We will do nothing if it is not valid.
    if ( isValidKeyOrFileName ( fileName , true ) )
    {
// These are the file objects.
// We are going to use them to get the correct files from the disk.
      File file = null ;
      File slFile = null ;
      File ivFile = null ;
// The old (the original) files will be read.
// The admin content will come from the admin path
// and the content of the password container files are from the normal file path.
// The main (pd or an) the sl and the iv files will be searched for.
      if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
      {
        file = new File ( appPasswordDir + SEP + fileName + appPdPostfix ) ;
        slFile = new File ( appPasswordDir + SEP + fileName + appSlPostfix ) ;
        ivFile = new File ( appPasswordDir + SEP + fileName + appIvPostfix ) ;
      }
      else if ( passwordTypeAdmin . equals ( passwordType ) )
      {
        file = new File ( appAdminDir + SEP + fileName + appAnPostfix ) ;
        slFile = new File ( appAdminDir + SEP + fileName + appSlPostfix ) ;
        ivFile = new File ( appAdminDir + SEP + fileName + appIvPostfix ) ;
      }
      if ( file != null && slFile != null && ivFile != null )
      {
// We are trying to check and delete them.
// If any of this won't be successful then won't continue and the user will get a message
// to do the correction manually. (old files delete, new files rename to old filenames.)
        if ( ( file . exists ( ) && ! file . delete ( ) ) || ( slFile . exists ( ) && ! slFile . delete ( ) ) || ( ivFile . exists ( ) && ! ivFile . delete ( ) ) )
        {
          outprintln ( messageErrorDeletingOldFilesOrRenameNewFiles + fileName ) ;
        }
        else
        {
// Now the old files are deleted.
// We will rename the new files into old filenames by using these objects.
          File fileOld = null ;
          File fileNew = null ;
          File fileOldSl = null ;
          File fileNewSl = null ;
          File fileOldIv = null ;
          File fileNewIv = null ;
// The normal password file and admin file are here also in a different case.
// File1 and File2 at first and Admin is the next depending on the parameter value of this function calling.
          if ( passwordTypeFile1 . equals ( passwordType ) || passwordTypeFile2 . equals ( passwordType ) )
          {
            fileOld = new File ( appPasswordDir + SEP + fileName + appPdPostfix + appNwPostfix ) ;
            fileNew = new File ( appPasswordDir + SEP + fileName + appPdPostfix ) ;
            fileOldSl = new File ( appPasswordDir + SEP + fileName + appSlPostfix + appNwPostfix ) ;
            fileNewSl = new File ( appPasswordDir + SEP + fileName + appSlPostfix ) ;
            fileOldIv = new File ( appPasswordDir + SEP + fileName + appIvPostfix + appNwPostfix ) ;
            fileNewIv = new File ( appPasswordDir + SEP + fileName + appIvPostfix ) ;
          }
          else if ( passwordTypeAdmin . equals ( passwordType ) )
          {
            fileOld = new File ( appAdminDir + SEP + fileName + appAnPostfix + appNwPostfix ) ;
            fileNew = new File ( appAdminDir + SEP + fileName + appAnPostfix ) ;
            fileOldSl = new File ( appAdminDir + SEP + fileName + appSlPostfix + appNwPostfix ) ;
            fileNewSl = new File ( appAdminDir + SEP + fileName + appSlPostfix ) ;
            fileOldIv = new File ( appAdminDir + SEP + fileName + appIvPostfix + appNwPostfix ) ;
            fileNewIv = new File ( appAdminDir + SEP + fileName + appIvPostfix ) ;
          }
          if ( fileOld != null && fileNew != null && fileOldSl != null && fileNewSl != null && fileOldIv != null && fileNewIv != null )
          {
// We are trying to rename the files into the old filenames!
// If it is not successful, the user gets the same message as a couple lines before.
// The success variable can be set to true in case of success.
            if ( ! fileOld . renameTo ( fileNew ) || ! fileOldSl . renameTo ( fileNewSl ) || ! fileOldIv . renameTo ( fileNewIv ) )
            {
              outprintln ( messageErrorDeletingOldFilesOrRenameNewFiles + fileName ) ;
            }
            else
            {
              success = true ;
            }
          }
          else
          {
            systemexit ( "Error - One of these is null: fileOld|fileNew|fileOldSl|fileNewSl|fileOldIv|fileNewIv, removeOldFilesAndRenameNewFiles" ) ;
          }
// These variables are not needed now.
          fileOld = null ;
          fileNew = null ;
          fileOldSl = null ;
          fileNewSl = null ;
          fileOldIv = null ;
          fileNewIv = null ;
        }
      }
      else
      {
        systemexit ( "Error - One of these is null: file|slFile|ivFile, removeOldFilesAndRenameNewFiles" ) ;
      }
// These variables are also not needed.
      file = null ;
      slFile = null ;
      ivFile = null ;
    }
// Let the function return!
    return success ;
  }
/*
** The lowest level read and write methods.
*/
/*
** This is for reading a file from a specified file path into a byte array and return with it.
*/
  private static final byte [ ] readFileBytes ( String filePath )
  {
// This will be the byte array, not null and empty by default.
    byte [ ] bytes = new byte [ 0 ] ;
// Let's check the file path, it has to be passed by the following validation.
// Else don't do anything.
    if ( isValidFilePath ( filePath ) )
    {
// At first we are creating a new File object.
      File file = new File ( filePath ) ;
      if ( file != null )
      {
// We can continue if this file is existing and really is a file.
// Else we have to break the whole program.
        if ( file . exists ( ) && file . isFile ( ) )
        {
// Now we can specify the size of the byte array, let's recreate it.
          bytes = new byte [ ( int ) file . length ( ) ] ;
// We can create now the FileInputStream object as null by default.
          FileInputStream fis = null ;
// Trying to create a valid FileInputStream object according to the filePath.
// If it remains null the we are going to exit.
          try
          {
            fis = new FileInputStream ( filePath ) ;
          }
          catch ( FileNotFoundException e )
          {
            systemexit ( "Exception - FileNotFoundException, readFileBytes" ) ;
          }
          if ( fis != null )
          {
// Trying to read and close the fis object.
// If it is not successful, we are going to exit.
            try
            {
              fis . read ( bytes ) ;
            }
            catch ( IOException e )
            {
              systemexit ( "Exception - IOException, readFileBytes" ) ;
            }
            finally
            {
              try
              {
                fis . close ( ) ;
              }
              catch ( Exception e )
              {
                systemexit ( "Exception - Exception, readFileBytes" ) ;
              }
            }
          }
          else
          {
            systemexit ( "Error - fis is null, readFileBytes" ) ;
          }
// This object is not needed any more.
          fis = null ;
        }
        else
        {
          systemexit ( "Error - File does not exist or it is not a file, readFileBytes" ) ;
        }
      }
      else
      {
        systemexit ( "Error - file is null, readFileBytes" ) ;
      }
    }
// Give this.
    return bytes ;
  }
/*
** This method is for writing a file with the given byte array to the given file path.
*/
  private static final void writeFileBytes ( String filePath , byte [ ] bytes )
  {
// Let's check the file path, it has to be passed by the following validation.
// Else don't do anything.
    if ( isValidFilePath ( filePath ) )
    {
// We will continue if the bytes object is not null
// Else exiting.
      if ( bytes != null )
      {
// This is null by default, has to be not null after the initialization.
        FileOutputStream fos = null ;
// Trying to create a new FileOutputStream object.
// If it is not possible (exception), exit.
        try
        {
          fos = new FileOutputStream ( filePath ) ;
        }
        catch ( FileNotFoundException e )
        {
          systemexit ( "Exception - FileNotFoundException, writeFileBytes" ) ;
        }
        if ( fos != null )
        {
// Now we are trying to write the bytes and close the fos object.
// If it is not successful, exit.
          try
          {
            fos . write ( bytes ) ;
          }
          catch ( IOException e )
          {
            systemexit ( "Exception - IOException, writeFileBytes" ) ;
          }
          finally
          {
            try
            {
              fos . close ( ) ;
            }
            catch ( Exception e )
            {
              systemexit ( "Exception - Exception, writeFileBytes" ) ;
            }
          }
        }
        else
        {
          systemexit ( "Error - fos is null, writeFileBytes" ) ;
        }
// We don't need this object any more.
        fos = null ;
      }
      else
      {
        systemexit ( "Error - bytes is null, writeFileBytes" ) ;
      }
    }
  }
/*
** Copies a single file from a source into another file.
*/
  private static final boolean copySingleFile ( String sourceFilePath , String targetFilePath )
  {
// Not success by default.
    boolean success = false ;
// Let's check the file paths, these have to be passed by the following validation.
    if ( isValidFilePath ( sourceFilePath ) )
    {
      if ( isValidFilePath ( targetFilePath ) )
      {
// These will be the file objects.
        File sourceFile = null ;
        File targetFile = null ;
// And the input and output stream objects.
        FileInputStream fis = null ;
        FileOutputStream fos = null ;
// These are for copying.
        int length ;
        byte [ ] buffer ;
// Let's create the object of the source file.
        sourceFile = new File ( sourceFilePath ) ;
        if ( sourceFile != null )
        {
// And let's create the object of the target file.
          targetFile = new File ( targetFilePath ) ;
          if ( targetFile != null )
          {
// Overwrite in any case so we are trying to delete the file if it exists.
            if ( targetFile . exists ( ) )
            {
              if ( ! targetFile . delete ( ) )
              {
                systemexit ( "Error - unable to delete file: " + targetFilePath + ", copySingleFile" ) ;
              }
            }
// The input streams can be created now.
// Input stream to read the source.
            try
            {
              fis = new FileInputStream ( sourceFile ) ;
            }
            catch ( FileNotFoundException e )
            {
              systemexit ( "Exception - FileNotFoundException (0), copySingleFile" ) ;
            }
            if ( fis != null )
            {
// Output stream to write the target file.
              try
              {
                fos = new FileOutputStream ( targetFile ) ;
              }
              catch ( FileNotFoundException e )
              {
                systemexit ( "Exception - FileNotFoundException (1), copySingleFile" ) ;
              }
              if ( fos != null )
              {
// These have to be initialized.
                buffer = new byte [ 1024 ] ;
                length = 0 ;
// Now the creation of the target file.
                try
                {
                  while ( ( length = fis . read ( buffer ) ) > 0 )
                  {
                    fos . write ( buffer , 0 , length ) ;
                    clearByteArray ( buffer ) ;
                  }
                }
                catch ( IOException e )
                {
                  systemexit ( "Exception - IOException (0), copySingleFile" ) ;
                }
// These 2 should be closed.
                try
                {
                  fis . close ( ) ;
                }
                catch ( IOException e )
                {
                  systemexit ( "Exception - IOException (1), copySingleFile" ) ;
                }
                try
                {
                  fos . close ( ) ;
                }
                catch ( IOException e )
                {
                  systemexit ( "Exception - IOException (2), copySingleFile" ) ;
                }
// This is the point we can mark this execution as successful.
                success = true ;
              }
              else
              {
                systemexit ( "Error - fos is null, copySingleFile" ) ;
              }
            }
            else
            {
              systemexit ( "Error - fis is null, copySingleFile" ) ;
            }
          }
          else
          {
            systemexit ( "Error - targetFile is null, copySingleFile" ) ;
          }
        }
        else
        {
          systemexit ( "Error - sourceFile is null, copySingleFile" ) ;
        }
        fis = null ;
        fos = null ;
        sourceFile = null ;
        targetFile = null ;
        length = 0 ;
        buffer = null ;
      }
      else
      {
        systemexit ( "Error - targetFilePath is not valid, copySingleFile" ) ;
      }
    }
    else
    {
      systemexit ( "Error - sourceFilePath is not valid, copySingleFile" ) ;
    }
// Give this back
    return success ;
  }
/*
** Reads a single lined file, or the first line of a file.
** For example backup description reading.
** In case of not existing file an empty string will be returned.
*/
  private static final String readSingleLinedFile ( String filePath )
  {
// This is the string we will return with.
    String line = null ;
// Let's check the file path, it has to be passed by the following validation.
// Else don't do anything.
    if ( isValidFilePath ( filePath ) )
    {
// These are our objects.
      File file = null ;
      FileInputStream fis = null ;
      InputStreamReader isr = null ;
      BufferedReader br = null ;
// Let's create the file object first.
      file = new File ( filePath ) ;
      if ( file != null )
      {
// We can continue if this file is existing and really is a file.
// Else we have to break the whole program.
        if ( file . exists ( ) && file . isFile ( ) )
        {
// Let's create the other objects!
          try
          {
            fis = new FileInputStream ( file ) ;
          }
          catch ( FileNotFoundException e )
          {
            systemexit ( "Exception - FileNotFoundException, readSingleLinedFile" ) ;
          }
          isr = new InputStreamReader ( fis ) ;
          br = new BufferedReader ( isr ) ;
// This is the first line of the file.
          try
          {
            line = br . readLine ( ) ;
          }
          catch ( IOException e )
          {
            systemexit ( "Exception - IOException (0), readSingleLinedFile" ) ;
          }
// Close buffered reader.
          try
          {
            br . close ( ) ;
          }
          catch ( IOException e )
          {
            systemexit ( "Exception - IOException (1), readSingleLinedFile" ) ;
          }
        }
        else
        {
          systemexit ( "Error - File does not exist or it is not a file, readSingleLinedFile" ) ;
        }
      }
      else
      {
        systemexit ( "Error - file is null, readSingleLinedFile" ) ;
      }
    }
// In case of null we want to return an empty string.
    if ( line == null )
    {
      line = "" ;
    }
// Returning the first line!
    return line ;
  }
/*
** Creates a single file with a string content.
*/
  private static final boolean createSingleFile ( String filePath , String content )
  {
// False by default.
    boolean success = false ;
// This has to be a valid file path
    if ( isValidFilePath ( filePath ) )
    {
      if ( isASCII ( content ) )
      {
// These are the objects we are going to use. File and file output stream.
        File file = null ;
        FileOutputStream fop = null ;
// Let's create the file object
        file = new File ( filePath ) ;
// This has to be deleted!
        file . delete ( ) ;
// Creating a new empty file.
        try
        {
          file . createNewFile ( ) ;
        }
        catch ( IOException e )
        {
          systemexit ( "Exception - IOException (0), createSingleFile" ) ;
        }
// This is the output stream.
        try
        {
          fop = new FileOutputStream ( file ) ;
        }
        catch ( FileNotFoundException e )
        {
          systemexit ( "Exception - FileNotFoundException, createSingleFile" ) ;
        }
        if ( fop != null )
        {
// Write it.
          try
          {
            fop . write ( content . getBytes ( ) ) ;
          }
          catch ( IOException e )
          {
            systemexit ( "Exception - IOException (1), createSingleFile" ) ;
          }
// Close it.
          try
          {
            fop . close ( ) ;
          }
          catch ( IOException e )
          {
            systemexit ( "Exception - IOException (2), createSingleFile" ) ;
          }
// These should be point to null.
          fop = null ;
          file = null ;
// If we are here then we can set this to true.
          success = true ;
        }
        else
        {
          systemexit ( "Error - fop is null, createSingleFile" ) ;
        }
      }
    }
    else
    {
      systemexit ( "Error - filePath is not valid, createSingleFile" ) ;
    }
// Returning.
    return success ;
  }
/*
** Other low level functions.
*/
/*
** Displays a status of the displaying time of the password.
*/
  private static final void displayPasswordShowStatus ( )
  {
// This will be the upper margin to show a reference.
    String margin = "" ;
    if ( margin != null )
    {
      if ( messageCloseThisWindow != null )
      {
// Should be at least 1 character
        if ( messageCloseThisWindow . length ( ) > 0 )
        {
// Let it grow to the length of the appPasswordShowSeconds
          while ( margin . length ( ) < messageCloseThisWindow . length ( ) )
          {
            margin = margin + passwordStatusMargin ;
          }
// Let's print it out.
          outprintln ( margin ) ;
// The counter of the seconds.
          int counter = 0 ;
// This is the number of milliseconds to sleep this thread.
// At this point, we cannot divide by zero.
          int msToSleep = ( int ) ( appPasswordShowSeconds * 1000 / messageCloseThisWindow . length ( ) ) ;
// This cycle is while the time remains.
// Prints a character.
          while ( counter < messageCloseThisWindow . length ( ) )
          {
            outprint ( passwordStatusStatus ) ;
            threadsleep ( msToSleep ) ;
            counter ++ ;
          }
          outprint ( newLineChar ) ;
// These will be not used later.
          msToSleep = 0 ;
          counter = 0 ;
        }
        else
        {
          systemexit ( "Error - messageCloseThisWindow is empty, displayPasswordShowStatus" ) ;
        }
      }
      else
      {
        systemexit ( "Error - messageCloseThisWindow is null, displayPasswordShowStatus" ) ;
      }
    }
    else
    {
      systemexit ( "Error - margin is null, displayPasswordShowStatus" ) ;
    }
// Releasable.
    margin = null ;
  }
/*
** This method clears the screen by printing out several new line characters.
*/
  private static final void clearScreen ( int numOfEmptyLinesToPrintOut )
  {
// The string to be printed out
    String clearScreenString = "" ;
// It is faster to construct one long string.
    for ( int i = 0 ; i < numOfEmptyLinesToPrintOut ; i ++ )
    {
      clearScreenString = clearScreenString + newLineChar ;
    }
// So we are gonna print just one string containing several newline characters
    outprintln ( clearScreenString ) ;
// This should be null.
    clearScreenString = null ;
  }
/*
** This method is to pause the execution.
*/
  private static final void threadsleep ( int ms )
  {
// Trying to sleep and exit if it is not possible.
    try
    {
      Thread . sleep ( ms ) ;
    }
    catch ( InterruptedException e )
    {
      systemexit ( "Exception - InterruptedException, threadsleep" ) ;
    }
  }
/*
** Prints the message to the user and exits this program with the given code.
*/
  private static final void systemexit ( String s )
  {
    outprintln ( messageExiting + s ) ;
    System . exit ( 1 ) ;
  }
/*
** Print the message and a new line onto the console if the input is fine.
*/
  private static final void outprintln ( String s )
  {
    if ( isASCIIorNEWLINE ( s ) )
    {
      System . out . println ( s ) ;
    }
  }
/*
** Print the message and a new line onto the console if the input is fine.
*/
  private static final void outprintln ( char c )
  {
    if ( isASCIIorNEWLINE ( c ) )
    {
      System . out . println ( c ) ;
    }
  }
/*
** Print the message and a new line onto the console if the input is fine.
*/
  private static final void outprint ( String s )
  {
    if ( isASCIIorNEWLINE ( s ) )
    {
      System . out . print ( s ) ;
    }
  }
/*
** Print the message and a new line onto the console if the input is fine.
*/
  private static final void outprint ( char c )
  {
    if ( isASCIIorNEWLINE ( c ) )
    {
      System . out . print ( c ) ;
    }
  }
/*
** Debug functions as putting characters onto the console.
** These are not necessary at all, can be removed if you wish.
*/
/*
** Debug message for strings (and new line after)
*/
  private static final void debugln ( String s )
  {
    outprintln ( "# " + s ) ;
  }
/*
** Debug message for char (and new line after)
*/
  private static final void debugln ( char c )
  {
    outprintln ( "# " + c ) ;
  }
/*
** Debug message for string
*/
  private static final void debug ( String s )
  {
    outprint ( s ) ;
  }
/*
** Debug message for char
*/
  private static final void debug ( char c )
  {
    outprint ( c ) ;
  }
/*
** These are for prevent serialize-deserialize.
*/
/*
** This is for security considerations.
** It isn't allow to serialize or deserialize the object.
** Just throw an IOException.
*/
  private final void readObject ( ObjectInputStream in )
    throws IOException
  {
    throw new IOException ( "" ) ;
  }
/*
** This is for security considerations.
** It isn't allow to serialize or deserialize the object.
** Just throw an IOException.
*/
  private final void writeObject ( ObjectOutputStream out )
    throws IOException
  {
    throw new IOException ( "" ) ;
  }
/*
** The main and last production function of the class.
*/
/*
** The main method..
** Creating the admin stuff and starting the process if the args are correct.
** Before and after it clearing the used byte and char arrays of the class.
*/
  public static final void main ( String [ ] args )
  {
    if ( console != null )
    {
// We can step further only if the arguments are correct.
      if ( isGoodArgsObject ( args ) )
      {
// Let's create these objects right now.
        passwordDirFolder = new File ( appPasswordDir ) ;
        adminDirFolder = new File ( appAdminDir ) ;
        backupDirFolder = new File ( appBackupDir ) ;
// To decide whether we have to create the admin stuff we need this variable.
        boolean adminStuffNeeded = true ;
        if ( argHelp != null && argQuestionMark != null && argApplication != null && argDescribe != null && argStory != null && argWelcome != null && argScreen != null && argGood != null && argPassword != null && argPart != null && argClear != null && argScreen != null )
        {
// We have to create admin things except
// - we have no argument
// - or we have "?" or "help"
// - or we have "application describe" or "application story" or "welcome screen" or "good password" or "password part"
// - or "clear screen <a_number>"
          if ( args . length == 0 || ( ( args . length == 1 ) && ( argQuestionMark . equals ( args [ 0 ] . toLowerCase ( ) ) || argHelp . equals ( args [ 0 ] . toLowerCase ( ) ) ) ) || ( ( args . length == 2 ) && ( ( argApplication . equals ( args [ 0 ] . toLowerCase ( ) ) && argDescribe . equals ( args [ 1 ] . toLowerCase ( ) ) ) || ( argApplication . equals ( args [ 0 ] . toLowerCase ( ) ) && argStory . equals ( args [ 1 ] . toLowerCase ( ) ) ) || ( argWelcome . equals ( args [ 0 ] . toLowerCase ( ) ) && argScreen . equals ( args [ 1 ] . toLowerCase ( ) ) ) || ( argGood . equals ( args [ 0 ] . toLowerCase ( ) ) && argPassword . equals ( args [ 1 ] . toLowerCase ( ) ) ) || ( argPassword . equals ( args [ 0 ] . toLowerCase ( ) ) && argPart . equals ( args [ 1 ] . toLowerCase ( ) ) ) ) ) || ( ( args . length == 3 ) && ( ( argClear . equals ( args [ 0 ] . toLowerCase ( ) ) && argScreen . equals ( args [ 1 ] . toLowerCase ( ) ) ) ) ) )
          {
            adminStuffNeeded = false ;
          }
// We need a not null passwordDirFolder.
          if ( passwordDirFolder != null )
          {
// So if we have to create admin things and the password directory is not existing..
            if ( ! passwordDirFolder . exists ( ) && adminStuffNeeded )
            {
              if ( yes != null )
              {
// Asking the user for this class is in a safe place
                if ( yes . equals ( readline ( messageIsFolderSafe , appMaxLengthOfPasswordsAndKeysAndFileNames ) ) )
                {
// Creating the folder of the password container files.
                  passwordDirFolder . mkdirs ( ) ;
// Now we need a not null backupDirFolder.
                  if ( backupDirFolder != null )
                  {
// Let's check for the backup folder, creating if not existing.
// If it is existing that is bad, exiting.
                    if ( ! backupDirFolder . exists ( ) )
                    {
                      backupDirFolder . mkdirs ( ) ;
// Now we need a not null adminDirFolder.
                      if ( adminDirFolder != null )
                      {
// Let's check for the admin folder, creating if not existing.
// If it is existing that is bad, exiting.
                        if ( ! adminDirFolder . exists ( ) )
                        {
                          adminDirFolder . mkdirs ( ) ;
// Creating an object to get the number of objects inside.
                          File [ ] adminFiles = adminDirFolder . listFiles ( ) ;
                          if ( adminFiles != null )
                          {
// If the adminFiles array is of length 0 then we are good.
// Else exiting! We can continue only if we have an empty admin folder.
                            if ( adminFiles . length == 0 )
                            {
// The first run screen is printed out.
                              outprintln ( messageWelcomeScreen ) ;
// Message to the user: admin password won't have to be forgotten!
                              outprintln ( messageDoNotForgetYourAdminPassword ) ;
// Reading the user's admin password!
                              readPassword ( passwordTypeAdmin , true , appAdminFileName ) ;
// Now we have the user's admin password.
// Let's create the encrypted admin file with an initialization message in it.
// (using this admin password.)
// At first we have to clear, recreate and clear again the char array used for storing
// the content of the admin file.
// We are creating now the whole admin content and not reading it from file first.
// Because there is no file yet.
                              clearCharArray ( fileContentAdminOrig ) ;
                              fileContentAdminOrig = new char [ appFileContentMaxLength ] ;
                              clearCharArray ( fileContentAdminOrig ) ;
// The content of the admin file initialized into the default value.
// This is a string by default.
                              String adminIniContent = "" + adminHeader + simpleDateFormat . format ( new Date ( ) ) + sep9 + messageLogApplicationInstanceInitialize + newLineChar ;
                              if ( adminIniContent != null )
                              {
// The content of the files or admin file is a char array.
// So let's add these char-by-char.
                                for ( int i = 0 ; i < Math . min ( adminIniContent . length ( ) , appMaxLengthToLog ) ; i ++ )
                                {
                                  fileContentAdminOrig [ i ] = adminIniContent . charAt ( i ) ;
                                }
// We can now save the user's admin file and print a message if this has been created successfully.
                                if ( saveFile ( appAdminFileName , passwordTypeAdmin ) )
                                {
                                  outprintln ( messageAdminFileHasBeenCreated ) ;
                                }
// This is needed, the char array must be cleared..
                                clearCharArray ( fileContentAdminOrig ) ;
                              }
                              else
                              {
                                systemexit ( "Error - adminIniContent is null, main" ) ;
                              }
// .. and the content into the admin file too.
                              adminIniContent = null ;
                            }
                            else
                            {
                              systemexit ( "Error - Admin folder is not empty, main" ) ;
                            }
                          }
                          else
                          {
                            systemexit ( "Error - adminFiles is null , main" ) ;
                          }
// This should be released.
                          adminFiles = null ;
                        }
                        else
                        {
                          systemexit ( "Error - adminDirFolder already exists, main" ) ;
                        }
                      }
                      else
                      {
                        systemexit ( "Error - adminDirFolder is null, main" ) ;
                      }
                    }
                    else
                    {
                      systemexit ( "Error - backupDirFolder already exists, main" ) ;
                    }
                  }
                  else
                  {
                    systemexit ( "Error - backupDirFolder is null, main" ) ;
                  }
                }
                else
                {
                  systemexit ( "Error - Folder is not safe by answer, main" ) ;
                }
              }
              else
              {
                systemexit ( "Error - yes is null, main" ) ;
              }
            }
          }
          else
          {
            systemexit ( "Error - passwordDirFolder is null, main" ) ;
          }
        }
        else
        {
          systemexit ( "Error - One of these is null: argHelp|argQuestionMark|argApplication|argDescribe|argStory|argWelcome|argScreen|argGood|argPassword|argPart|argClear|argScreen, main" ) ;
        }
// If we are here: having
// - our admin stuffs
// - not null console object
// - good arguments.
// Let's clear the used byte and char arrays.
        clearCharArrays ( ) ;
        clearByteArrays ( ) ;
// give the args object to the letsWork method and let the fun begin.
        letsWork ( args ) ;
// We are done so we have to clear again our byte and char arrays.
        clearCharArrays ( ) ;
        clearByteArrays ( ) ;
// This should be false.
        adminStuffNeeded = false ;
      }
    }
    else
    {
      systemexit ( "Error - console is null, main" ) ;
    }
// Just for fun.
    System . exit ( 0 ) ;
  }
}