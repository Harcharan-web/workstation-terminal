// Sign in with a key file: open an OpenSSH ed25519 private key (plain, or locked with a passphrase the way
// `ssh-keygen -N` does it: bcrypt KDF + aes256-ctr) in this page and sign the login challenge exactly like
// `ssh-keygen -Y sign` (PROTOCOL.sshsig). The key and passphrase never leave the browser; only the signature is sent.
// Needs vendor/nacl-fast.min.js and vendor/bcrypt-pbkdf.js. Sets window.KeySign = { openKey, sign }.
(function () {
  "use strict";

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const notAKey = () => new Error("That file isn't a key we can read. Pick the .key file you were given.");

  function reader(bytes) {
    let i = 0;
    const take = (n) => {
      if (i + n > bytes.length) throw notAKey();
      i += n;
      return bytes.subarray(i - n, i);
    };
    const u32 = () => new DataView(take(4).slice().buffer).getUint32(0);
    const str = () => take(u32());
    return { u32, str, text: () => dec.decode(str()) };
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let i = 0;
    for (const p of parts) { out.set(p, i); i += p.length; }
    return out;
  }
  const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
  const sshString = (b) => concat(u32(b.length), typeof b === "string" ? enc.encode(b) : b);
  const fromBase64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toBase64 = (b) => btoa(Array.from(b, (c) => String.fromCharCode(c)).join(""));

  // -> { pub: public key blob, sk: 64-byte ed25519 secret key (seed + public half) }
  async function openKey(text, passphrase) {
    const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(text || "");
    if (!m) throw notAKey();
    let raw;
    try { raw = fromBase64(m[1].replace(/\s+/g, "")); } catch (_) { throw notAKey(); }
    const magic = "openssh-key-v1\0";
    if (dec.decode(raw.subarray(0, magic.length)) !== magic) throw notAKey();
    const r = reader(raw.subarray(magic.length));
    const cipher = r.text(), kdf = r.text(), kdfOptions = r.str();
    if (r.u32() !== 1) throw notAKey();
    const pub = r.str();
    let secret = r.str();

    if (cipher !== "none") {
      if (cipher !== "aes256-ctr" || kdf !== "bcrypt") {
        throw new Error("This key is locked in a way this page can't open. Use “Sign in with a command” below.");
      }
      if (!passphrase) throw new Error("Type the key's passphrase.");
      const o = reader(kdfOptions);
      const salt = o.str(), rounds = o.u32();
      const pass = enc.encode(passphrase);
      const derived = new Uint8Array(48); // aes-256 key + 16-byte counter
      if (window.bcryptPbkdf.pbkdf(pass, pass.length, salt, salt.length, derived, derived.length, rounds) !== 0) {
        throw notAKey();
      }
      const aes = await crypto.subtle.importKey("raw", derived.slice(0, 32), "AES-CTR", false, ["decrypt"]);
      secret = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-CTR", counter: derived.slice(32, 48), length: 128 }, aes, secret));
    }

    const s = reader(secret);
    // Two equal random numbers open the private part: if they differ, the passphrase was wrong.
    if (s.u32() !== s.u32()) throw new Error("That passphrase isn't right. Check it and try again.");
    if (s.text() !== "ssh-ed25519") {
      throw new Error("Only ed25519 keys can sign in here. Use “Sign in with a command” below.");
    }
    s.str(); // public half again
    const sk = s.str();
    if (sk.length !== 64) throw notAKey();
    return { pub, sk };
  }

  // The armored SSH signature `ssh-keygen -Y sign -n <namespace>` makes for `message` (hash sha512).
  async function sign(key, message, namespace) {
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", enc.encode(message)));
    const tail = concat(sshString(namespace), sshString(""), sshString("sha512"));
    const sig = window.nacl.sign.detached(concat(enc.encode("SSHSIG"), tail, sshString(hash)), key.sk);
    const blob = concat(enc.encode("SSHSIG"), u32(1), sshString(key.pub), tail,
      sshString(concat(sshString("ssh-ed25519"), sshString(sig))));
    return "-----BEGIN SSH SIGNATURE-----\n" + toBase64(blob).replace(/.{1,70}/g, "$&\n") +
      "-----END SSH SIGNATURE-----\n";
  }

  window.KeySign = { openKey, sign };
})();
