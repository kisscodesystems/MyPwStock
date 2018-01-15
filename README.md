# MyPwStock
The java password management application.

  You can defend your real passwords using MyPwStock application even one
  password!
  You now have to memorize just 1 password to know the other good and hard to
  guess (and hard to memorize) passwords.

  This application has been developed in java technology and can be used in
  command line in every operating systems that contain (min 1.8) java installed.

  The AES encryption is used 128 bit length of encryption key default but 192
  and 256 key length are also available by downloading the
  Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
  from Oracle. But, the 128 length will be enough for a couple of years.

  The most important goals we have achieved:
  - there are no passwords written to disk in plain text format
  - there are unencrypted passwords in the system memory only in mutable objects
  - there are unencrypted passwords in the system memory while they are needed
    (it is possible to use MyPwStock in an unsecure way to speed up the manual
    password handling job: it can cache the admin and file passwords to not have
    to type these every time, this is for the user's exact command)
  - the file and password operations are fully logged.
  
Read more: https://openso.kisscodesystems.com
