# SRP

- pswd is not sent to server
- server does not store the pswd

## Registration

### Client
1. enter username and pswd
2. salt = generateSalt()
3. verifier = generateVerifier(username, pswd and salt) 
4. POST to server => payload: {username, salt verifier}

### Server
5. Client stores {username, salt verifier}
   - indexed by username
   - salt given to anyone who asks
   - verifier NOT revealed

## Login

1. client sends username and gets the salt