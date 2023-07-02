# Directory-Encryptor
A simple program designed to encrypt/decrypt a given file directory using AES-CFB-256.

This program has two modes of operation: Encryption and Decryption.

Encryption mode will ask the user to input a desired directory, and ask the user for a password to encrypt that directory. Each file in
the given directory will be encrypted using AES-CFB-256 encryption, and the source files will be deleted. A keystore file containing the
encryption keys and an ivstore file containing the encryption IVs will also be created next to the encrypted files.

Decryption mode will ask the user to input a desired encrypted directory, and will ask the user for the password that was previously
used to encrypt it. Each file in the given directory (except for the keystore and ivstore files) will be decrypted using the AES-CFB-256 
algorithm. The encrypted versions of the files will be deleted, along with the keystore and ivstore files.

Note: This program only works with files using the UTF-8 charset, like most .txt or .bat files.
