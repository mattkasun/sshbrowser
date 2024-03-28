# sshbrowser
Proof of Concept for registration/login to website using ssh keys
## Steps
### Registration
 * user selects ssh public key to upload
 * username populated from public key
### Login
 * user select ssh private key for signing
    * **note:  if key requires a passphrase, a prompt is displayed to enter the passphrase.  This should really be a modal dialog with a password field so the passphrase is hidden**
 * use inputs email address as username
 * server is contacted to obtain a random string
 * random string is signed with private key
 * username, original message and signed message is returned to server
 * server validates signed message using stored public key
## [Live Demo](https://demo.nusak.ca)
 * registrations are stored in map
 * server is restarted daily; thus all registrations are deleted daily
 
