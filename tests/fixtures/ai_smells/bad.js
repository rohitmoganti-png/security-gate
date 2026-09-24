// Every block below SHOULD trigger an ai-smell rule (positive test cases).
const https = require("https");
const cp = require("child_process");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const agent = new https.Agent({ rejectUnauthorized: false });     // 2 TLS disabled
function findUser(db, id) { return db.query(`SELECT * FROM users WHERE id = ${id}`); }  // 3 SQL
function run(name) { cp.exec("ls " + name); }                      // 4 shell with built string
function load() { try { return JSON.parse("{}"); } catch (e) {} }  // 5 silent failure
app.use(cors());                                                  // 6 CORS any origin
function who(token) { return jwt.decode(token); }                 // 8 JWT not verified
