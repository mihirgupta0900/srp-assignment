const {
  registerUser,
  challenge,
  loginUser,
  transformPassword,
  rfc5054,
  HTTPError,
} = require("./dist/crypto");

// generate the client session class from the client session factory using the safe prime constants
const SRP6JavascriptClientSession = require("thinbus-srp/client")(
  rfc5054.N_base10,
  rfc5054.g_base10,
  rfc5054.k_base16
);

// generate the server session class from the server session factory using the safe prime constants
const SRP6JavascriptServerSession = require("thinbus-srp/server")(
  rfc5054.N_base10,
  rfc5054.g_base10,
  rfc5054.k_base16
);

const username = "mihirgupta";
const password = "mihir1234";
const hashedPswd = transformPassword(password);

// instantiate a client session
const clientSession = new SRP6JavascriptClientSession();

// instantiate a server session
const serverSession = new SRP6JavascriptServerSession();

// generate a random salt that should be stored with the user verifier
let salt = clientSession.generateRandomSalt();

// generate the users password verifier that should be stored with their salt.
const verifier = clientSession.generateVerifier(salt, username, hashedPswd);
const userData = { username, salt, verifier };

// Test registration
test("Register a user", () => {
  return registerUser({ username, secret: { salt, verifier } }).then((data) => {
    expect(data).toEqual(userData);
  });
});

// Test user authentication
test("Authenticate user", async () => {
  try {
    const registeredUser = await registerUser({
      username,
      secret: { salt, verifier },
    });

    // client starts with the username and password.
    clientSession.step1(username, hashedPswd);

    // challenge server and get {A, M1}
    const cred = await challenge(username, serverSession);

    // client creates a password proof from the salt, challenge and the username and password provided at step1. this generates `A` the cliehnt public ephemeral number and `M1` the hash of `M1` of a shared session key derived from both `A` and `B`. You  post `A` and `M1` to the server (e.g. seperated by a colon) instead of a password.
    let { A, M1 } = clientSession.step2(cred.salt, cred.B);

    // authenticate from server => Get M2
    const M2_string = await loginUser({ username, A, M1, serverSession });

    // client verifies that the server shows proof of the shared session key which demonstrates that it knows the verifier that matchews the password.
    clientSession.step3(M2_string);

    // we can now use the shared session key that hasn't crossed the network for follow on cryptography (such as JWT token signing or whatever)
    const clientSessionKey = clientSession.getSessionKey();
    const serverSessionKey = serverSession.getSessionKey();

    expect(clientSessionKey).toEqual(serverSessionKey);
  } catch (err) {
    console.log(err);
  }
});
