# MyPwStock

MyPwStock is a tiny command-line password manager. It stores passwords — or any
key/value sensitive data — in strongly encrypted files on the local filesystem.
Every secret lives inside an authenticated, password-protected container; nothing
is ever written to disk in clear text.

- **Developed by:** Jozsef Kiss — KissCode Systems Kft
- **License:** GNU General Public License, version 3
- **Current version:** 2.5

## Concept

- Secrets are grouped into **password container files**. Each file is protected by
  its own strong password (the "file password").
- Inside a file you store **key → value** entries (for example a website name as
  the key and the password as the value).
- A value can be stored either as a **whole good password** (validated against the
  strength policy) or as a **note**. The storage mode is chosen per file when the
  file is created.
- A **note** is free-form text: printable ASCII (32–126), **spaces allowed**, a
  single line (no line breaks), from 1 up to **999** characters; input longer than
  that is **truncated** to 999 characters (you are notified). Notes are entered
  in plain view (not masked). Non-ASCII input is best-effort **converted to ASCII**
  (accents are stripped — "café" → "cafe", smart quotes/dashes are mapped, and
  characters with no ASCII equivalent such as other scripts or emoji are dropped);
  you are notified when this changes what you typed. Note files created this way use
  storage mode `r`; note files created by older versions keep their original
  no-space behavior.
- A separate **admin password** guards application-wide tasks (admin review,
  admin search, changing the admin password).
- The application can run as a one-shot command (`MyPwStock <args>`) or in
  **interactive mode**, which keeps a session open and adds terminal-style command
  history and optional password caching.

## Directory layout

On first run MyPwStock initializes three working directories in the current
directory:

| Directory | Purpose                                                |
| --------- | ------------------------------------------------------ |
| `pd`      | Password container files (encrypted payload + IV/salt) |
| `an`      | Admin file and admin-related data                      |
| `bp`      | Backups (snapshots of the stored data)                 |

Each encrypted file is accompanied by its own per-file initialization vector
(`.iv`) and salt (`.sl`); a fresh salt and IV are generated on every save.

## Security model (short)

- **Cipher:** AES-GCM (`AES/GCM/NoPadding`), 256-bit key, 128-bit auth tag — the
  authenticated tag both protects integrity and acts as the "correct key" check.
- **Key derivation:** PBKDF2WithHmacSHA512, 600,000 iterations, 256-bit output,
  256-byte random salt per file.
- **Random header:** every file begins with a header line of a random number of
  random lowercase letters, so there is no fixed/known plaintext for an offline
  attacker to verify guesses against.
- Secrets are held in `char[]`/`byte[]` and wiped after use. In interactive mode
  the clipboard is cleared after a timeout, and a JVM shutdown hook wipes the
  clipboard / restores the terminal on abrupt exit (Ctrl+C).

## Build

MyPwStock is a single-package, dependency-free Java program. Building it is just a
`javac` compile plus packaging the runnable jar (these commands assume the
repository root as the working directory):

```bash
./MyPwStock_build_linux.sh
```

```bash
./MyPwStock_build_macos.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File .\MyPwStock_build_windows.ps1
```

This produces `MyPwStock.jar` in the repository root. A JDK 8 or newer is
sufficient; no external libraries are required to build or run the application
itself (JUnit/Hamcrest are only needed for the test suite, see below).

## Run

Launch the jar with the same `<arguments>` shown throughout this document:

```bash
java -jar MyPwStock.jar help          # print usage / hints
java -jar MyPwStock.jar welcome screen
java -jar MyPwStock.jar interactive mode
```

If you have not packaged the jar you can run straight from the compiled classes:

```bash
java -cp build/main_out com.kisscodesystems.MyPwStock.MyPwStockMain help
```

> **Note:** the application reads passwords from the terminal via the system
> console, so it must be run in a real interactive terminal. Running it with its
> output piped or redirected (no attached TTY) exits with
> `Error - console is null, main`.

### Tests

The regression suite is driven by `test/MyPwStock_run_tests_<platform>`. It compiles the current
sources, then runs the JUnit tests that check the validators, password
generation and the encrypted-file format:

```bash
bash test/MyPwStock_run_tests_linux.sh
```

```bash
bash test/MyPwStock_run_tests_macos.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File .\test\MyPwStock_run_tests_windows.ps1
```

The script needs `junit-4.12.jar` and `hamcrest-core-1.3.jar`; both are bundled in
the repository's `lib/` directory, so no extra setup is required.

## Getting started (how to initialize)

The application is invoked as `java -jar MyPwStock.jar <arguments>`.

### Initialize and store your first password

1. **`java -jar MyPwStock.jar welcome screen`**
   Read and do this. Please copy the `MyPwStock.jar` into a safe place according
   to this information.

2. Open a command line and navigate into the new place of `MyPwStock.jar`.

3. **`java -jar MyPwStock.jar ?`** — or, for more detail,
   **`java -jar MyPwStock.jar help`**
   Read the available commands to use the application.

4. **`java -jar MyPwStock.jar admin review`**
   Read about the history of using your MyPwStock instance. At this point we
   don't have any history, so we have to create our admin password. Please
   construct your admin password carefully and do not forget it!

5. **`java -jar MyPwStock.jar file add myfile1`**
   The password container file called `myfile1` will be created and the password
   of this file will be prompted. You can choose the same password as the admin
   password, but it is much safer to choose a different password. (File name not
   included!) What will happen exactly:
   - You have to type your admin password constructed before.
   - You have to type your new file password.
   - You have to choose the type of the stored passwords in this password
     container file. Choose `n` in this case. (Full and valid passwords can be
     stored in this file.)

6. **`java -jar MyPwStock.jar key add myfile1`**
   This is it. We will put our internet bank password into our `myfile1` file
   made before.
   - The file password will be prompted.
   - The admin password too.
   - The key (a name) will be questioned, let it be as `ibank_pwd`.
   - The password of this key will be prompted.

   We are done.

7. **`java -jar MyPwStock.jar admin review`**
   It can be seen that we have initialized our application, have created a new
   password container file and have added a new password into this file. By
   repeating this command, it can also be seen that the admin review has been
   called.

### Read a password back

An exact example for the password reading.

1. Open a command line and navigate to the place of `MyPwStock.jar`.

2. **`java -jar MyPwStock.jar file list`**
   List our file names we want to read a password from.

3. **`java -jar MyPwStock.jar key list myfile1`**
   List our keys (names of our passwords) added before into `myfile1`. The
   password of this file will be prompted.

4. **`java -jar MyPwStock.jar password show myfile1 ibank_pwd`**
   This is it. The command above shows the password placed into `myfile1` and
   belonging to the `ibank_pwd` key. The password of the file will be prompted of
   course.

5. **`java -jar MyPwStock.jar password copy myfile1 ibank_pwd`**
   In this case, your password goes to system clipboard only (for a limited time).

## Important functions

### Folder initialization

On the first run (when no `pd` directory exists yet) MyPwStock confirms the
location is safe, then creates the `pd`, `an` and `bp` directories, prompts for
the **admin password**, and writes the initial admin file. After this one-time
setup the application is ready to store files and keys.

### Application info / help

| Command                | What it does                                              |
| ---------------------- | -------------------------------------------------------- |
| `help` · `?`           | Print the full usage / hints.                            |
| `application describe` | Print application limits, directories and parameters.    |
| `application story`    | Print the basic concept and recommended usage.           |
| `welcome screen`       | Reprint the first-run welcome screen.                    |
| `good password`        | Print the strength rules for a fully stored password.    |
| `password note`        | Print the rules for a stored note.                       |
| `clear screen <n>`     | Clear the terminal by printing `n` empty lines.          |

### Password files

| Command                       | What it does                                                              |
| ----------------------------- | ------------------------------------------------------------------------ |
| `file add <name>`             | **Create a new password container file.** Prompts for the file password and the storage mode (whole passwords vs. notes). |
| `file list`                   | List all password files.                                                 |
| `file search <expr>`          | List files whose name matches `<expr>`.                                  |
| `file describe <name>`        | Print the properties of a file.                                          |
| `file password change <name>` | Re-encrypt a file under a new file password.                             |
| `file delete <name>`          | Delete a single password file.                                           |
| `file deleteall`              | Delete all password files.                                               |

### Keys (entries inside a file)

| Command                          | What it does                                          |
| -------------------------------- | ---------------------------------------------------- |
| `key add <file>`                 | **Add a new key/value entry** to a file.             |
| `key list <file>`                | List the keys stored in a file.                      |
| `key search <file> <expr>`       | Search keys in a file by expression.                 |
| `key change <file> <key> <new>`  | Rename / update a key.                               |
| `key move <file> <key> <dest>`   | Move one key to another file.                        |
| `key moveall <file> <dest>`      | Move all keys to another file.                       |
| `key delete <file> <key>`        | Delete a single key.                                 |
| `key deleteall <file>`           | Delete all keys in a file.                           |

### Showing and copying passwords

| Command                       | What it does                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `password show <file> <key>`  | **Reveal the stored value on screen** for a limited time (30 s), shown behind a "close this window" prompt with an animated countdown. |
| `password copy <file> <key>`  | **Copy the stored value to the system clipboard** instead of printing it. A countdown runs while you paste; in interactive mode the clipboard is cleared automatically after 30 s. For **note** files this instead reveals the value on screen (like `password show`), since notes are not clipboard secrets. |
| `password change <file> <key>`| Change the value stored under a key.                                                           |
| `password type change <file>` | Switch a file between whole-password and note storage.                                         |

> During either countdown, pressing **any key** in the (focused) MyPwStock
> terminal jumps straight to the end (on Linux/macOS).

### Admin functions

Admin tasks are protected by the admin password and operate across the whole
store.

| Command                  | What it does                                  |
| ------------------------ | --------------------------------------------- |
| `admin review`           | Review admin/log information.                  |
| `admin search <expr>`    | Search admin records by expression.            |
| `admin password change`  | Change the admin password.                     |

### Backup functions

| Command                            | What it does                                            |
| ---------------------------------- | ------------------------------------------------------ |
| `backup add`                       | **Create a new backup** (snapshot) of the stored data. |
| `backup list`                      | List existing backups.                                 |
| `backup file list <backup>`        | List the files contained in a backup.                  |
| `backup file search <backup> <e>`  | Search files within a single backup.                   |
| `backup file searchall <expr>`     | Search files across all backups.                       |
| `backup restore <backup> <file>`   | Restore a single file from a backup.                   |
| `backup restoreall <backup>`       | Restore everything from a backup.                      |
| `backup delete <backup>`           | Delete a single backup.                                |
| `backup deleteall`                 | Delete all backups.                                    |

### Interactive mode

| Command             | What it does                                                                 |
| ------------------- | --------------------------------------------------------------------------- |
| `interactive mode`  | Start a persistent session (with Up/Down command history).                  |
| `exit`              | Leave interactive mode.                                                      |
| `passwords cache`   | Cache file/admin passwords for the session (enter each password only once). |
| `passwords purge`   | Forget cached passwords (re-prompt every time).                             |

When caching is on and you open a file that has no cached password, the passwords
already cached for other files are tried automatically; if one opens the file it is
reused (and cached for that file too) so you are not asked again. This is convenient
if you reuse one password across files; you are still prompted when none of the
cached passwords fit.
