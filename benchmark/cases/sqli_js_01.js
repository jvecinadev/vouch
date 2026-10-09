// expect: CWE-89
// INTENTIONALLY INSECURE. Benchmark case, never use in production.
const db = require("./db");

function login(email) {
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return db.query(query);
}

module.exports = { login };
