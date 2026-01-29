# sshbrowser
Proof of Concept for registration/login to website using ssh keys
## Steps
### Registration
 * user selects ssh public key to upload
 * username populated from public key
### Login
 * user select ssh private key for signing
 * use inputs email address as username and ssh key passphrase (if required)
 * server is contacted to obtain a random string
 * random string is signed with private key
 * username, original message and signed message is returned to server
 * server validates signed message using stored public key
## [Live Demo](https://demo.nusak.ca)
 * registrations are stored in map
 * server is restarted daily; thus all registrations are deleted daily
 
