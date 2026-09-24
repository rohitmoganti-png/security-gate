// The SAFE versions: NONE of these should trigger an ai-smell rule (negative test cases).
const https = require("https");
const cp = require("child_process");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const agent = new https.Agent({ keepAlive: true });                           // 2 TLS verified
function findUser(db, id) { return db.query("SELECT * FROM users WHERE id = $1", [id]); } // 3
function run(name) { cp.execFile("ls", [name]); }                               // 4 arg array
function load() { try { return JSON.parse("{}"); } catch (e) { console.error(e); throw e; } } // 5
app.use(cors({ origin: ["https://app.example.com"] }));                        // 6 allow-list
function who(token, key) { return jwt.verify(token, key); }                    // 8 verified
