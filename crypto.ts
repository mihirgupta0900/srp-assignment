// RFC 5054 2048bit constants
export const rfc5054 = {
  N_base10:
    "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
  g_base10: "2",
  k_base16: "5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
};

// Require server srp
const SRP6JavascriptServerSession = require("thinbus-srp/server.js")(
  rfc5054.N_base10,
  rfc5054.g_base10,
  rfc5054.k_base16
);

import bcrypt from "bcrypt";
import memdown from "memdown";
import levelup from "levelup";

// const serverSession = new SRP6JavascriptServerSession();

/** Just an exception class with an HTTP error code */
export class HTTPError extends Error {
  code: number;
  constructor(message: string, code: number) {
    super(message);
    this.code = code;
  }
}

// memdown is an in memory db that disappears when you restart the process
const db = levelup(memdown());
const cache = levelup(memdown());

interface secretType {
  salt: string;
  verifier: string;
}

/**
 * Register a user (server-side)
 * @param form
 */
export const registerUser = async ({
  username,
  secret,
}: {
  username: string;
  secret: secretType;
}) => {
  try {
    await db.put(username, JSON.stringify(secret));
  } catch (err) {
    if (err) throw new HTTPError("Saving to DB failed", 500);
  }
  try {
    const resultString = await db.get(username, { asBuffer: false });
    const result: secretType = JSON.parse(resultString);
    const savedData = { username, ...result };
    return savedData;
  } catch (err) {
    if (err) throw new HTTPError("User not found", 404);
  }
};

/**
 * Challenge the server (server-side)
 * @param form
 */

export const challenge = async (username: string, serverSession: any) => {
  if (typeof username === "undefined") {
    throw new HTTPError("Username is undefined", 400);
  }
  try {
    // Get secret from db
    const secret = await db.get(username, { asBuffer: false });
    const result: secretType = JSON.parse(secret);
    const { salt, verifier } = result;

    // server generates B and b, sends B to client and b to a cache
    // const serverSession = new SRP6JavascriptServerSession();
    const B = serverSession.step1(username, salt, verifier);
    const privateState = serverSession.toPrivateStoreState();
    const cacheJson = JSON.stringify(privateState);

    // store the cacheJson in a temporary cache
    // return B and salt to the client.
    try {
      await cache.put(username, cacheJson);
    } catch (err) {
      if (err) throw new HTTPError("Could not save cache", 500);
    }
    return { salt, B };
  } catch (err) {
    if (err) throw new HTTPError("User not found - challenge", 404);
  }
};

/**
 * Authenticate a user (server-side)
 * @param form
 */
export const loginUser = async ({
  username,
  A,
  M1,
  serverSession,
}: {
  username: string;
  A: string;
  M1: string;
  serverSession: any;
}) => {
  try {
    const cacheJson: string = await cache.get(username, { asBuffer: false });
    // we now need to load the challenge data from the cache to check the credentials {A,M1}
    const newPrivate = JSON.parse(cacheJson);
    // const serverSession = new SRP6JavascriptServerSession();
    serverSession.fromPrivateStoreState(newPrivate);

    // the server takes `A`, internally computes `M1` based on the verifier, and checks that its `M1` matches the value sent from the client. If not it throws an exception. If the `M1` match then the password proof is valid. It then generates `M2` which is a proof that the server has the shared session key.
    const M2 = serverSession.step2(A, M1);
    const M2_string = encodeURIComponent(M2);
    return M2_string;
  } catch (err) {
    throw new HTTPError("Cache not found", 404);
  }
};

/**
 * Return the hash here that is fed in the above two functions
 * @param pass plaintext password
 */
export const transformPassword = async (pass: string) => {
  const saltRounds = 10;
  try {
    const hash = await bcrypt.hash(pass, saltRounds);
    return hash;
  } catch (err) {
    if (err) throw new HTTPError("Error in hashing password", 400);
  }
};
