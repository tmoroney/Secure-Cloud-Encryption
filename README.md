# Secure-Cloud-Encryption
A secure application for encrypting files before they are uploaded to the cloud, as well as decrypting files that are in the encryption group. Uses a combination of symmetric and asymmetric encryption to ensure that the files are completely secure, and to enable the adding and removing users from the encryption group so that files can be shared between multiple people.

### Overview
- A user’s private key is stored locally on their device. If they lose it, they will no longer be able to decrypt the files.
- A user’s public key is stored in the **database** for anyone to access (firebase database).
- Symmetric AES keys for each user is encrypted with their public key and also stored in the **database** (firebase database).
- All encrypted files are stored in the storage area (firebase storage)
- All user account passwords are automatically hashed by firebase Auth using Scrypt which is considered a very secure hashing algorithm.
- The account password is used to encrypt the locally stored private key so that the private key can only be used when the user is logged in.
