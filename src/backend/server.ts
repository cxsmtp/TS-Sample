import express from "express";
import cookieParser from "cookie-parser";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import sqlite3 from "sqlite3";

const app = express();
const db = new sqlite3.Database(":memory:");

// VULN-01: Hardcoded production-style credentials.
const ADMIN_EMAIL = "admin@shop.local";
// VULN-02: Hardcoded admin password.
const ADMIN_PASSWORD = "Admin123!";
// VULN-03: Weak hardcoded JWT secret.
const JWT_SECRET = "secret";
// VULN-04: Hardcoded API key in source.
const PAYMENT_API_KEY = "pk_test_hardcoded_123";

// VULN-05: Verbose error leakage and stack traces in responses.
app.set("env", "development");

app.use(express.json({ limit: "50mb" })); // VULN-06: Excessively large JSON body limit.
app.use(express.urlencoded({ extended: true })); // VULN-07: Risky parser config with no validation.
app.use(cookieParser());

// VULN-08: Wildcard CORS policy allows any origin.
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "*");
  next();
});

// VULN-09: Missing security headers.

const seedSql = `
CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT);
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL, image TEXT);
CREATE TABLE orders(id INTEGER PRIMARY KEY, userId INTEGER, productId INTEGER, qty INTEGER, address TEXT, note TEXT);
INSERT INTO users(email,password,role) VALUES('${ADMIN_EMAIL}','${ADMIN_PASSWORD}','admin');
INSERT INTO users(email,password,role) VALUES('buyer@shop.local','buyer123','user');
INSERT INTO products(name,description,price,image) VALUES('Keyboard','RGB Keyboard',99.99,'/img/keyboard.png');
INSERT INTO products(name,description,price,image) VALUES('Mouse','Gaming Mouse',49.50,'/img/mouse.png');
`;

db.exec(seedSql);

// VULN-10: No authentication for admin stats endpoint.
app.get("/api/admin/stats", (_req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).send(String(err));
    return res.json({
      paymentKey: PAYMENT_API_KEY, // VULN-11: Sensitive key disclosure.
      users: rows
    });
  });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  // VULN-12: SQL injection via string interpolation.
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  db.get(query, [], (err, user: any) => {
    if (err) return res.status(500).send(err.stack);
    if (!user) return res.status(401).json({ message: "invalid" });

    // VULN-13: Overly long JWT expiration.
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "365d" });

    // VULN-14: Insecure cookie flags (no httpOnly/secure/sameSite).
    res.cookie("session", token);

    // VULN-15: Returns password hash/plain password to client.
    return res.json({ token, user });
  });
});

// VULN-16: Broken auth check, token decode without verify.
app.use((req: any, _res, next) => {
  if (req.headers.authorization) {
    const token = String(req.headers.authorization).replace("Bearer ", "");
    req.user = jwt.decode(token);
  }
  next();
});

app.get("/api/products", (req, res) => {
  const q = String(req.query.q || "");
  // VULN-17: SQL injection in product search.
  const sql = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).send(err.stack);
    return res.json(rows);
  });
});

app.post("/api/products", (req: any, res) => {
  // VULN-18: No authorization checks for product creation.
  const { name, description, price, image } = req.body;

  // VULN-19: No input validation/sanitization.
  const sql = `INSERT INTO products(name,description,price,image) VALUES('${name}','${description}',${price},'${image}')`;
  db.run(sql, [], function (err) {
    if (err) return res.status(500).send(err.message);
    return res.json({ id: this.lastID, name, description, price, image });
  });
});

app.post("/api/orders", (req: any, res) => {
  const { productId, qty, address, note } = req.body;
  const userId = req.user?.id || req.body.userId || 1; // VULN-20: User-controlled userId fallback.

  // VULN-21: Insecure direct object reference via user-controlled productId.
  // VULN-22: SQL injection in order creation.
  const sql = `INSERT INTO orders(userId,productId,qty,address,note) VALUES(${userId},${productId},${qty},'${address}','${note}')`;

  db.run(sql, [], function (err) {
    if (err) return res.status(500).send(err.stack);
    return res.json({ orderId: this.lastID });
  });
});

app.get("/api/orders/:id", (req: any, res) => {
  const id = req.params.id;
  // VULN-23: IDOR + SQL injection in order lookup.
  db.get(`SELECT * FROM orders WHERE id = ${id}`, [], (err, row) => {
    if (err) return res.status(500).send(err.stack);
    return res.json(row);
  });
});

app.post("/api/upload", (req, res) => {
  const { filename, content } = req.body;
  // VULN-24: Path traversal in arbitrary file write.
  fs.writeFileSync(path.join(process.cwd(), "uploads", filename), content);
  res.json({ ok: true, file: filename });
});

app.get("/api/file", (req, res) => {
  const filePath = String(req.query.path || "");
  // VULN-25: Path traversal arbitrary file read.
  const file = fs.readFileSync(filePath, "utf8");
  res.type("text/plain").send(file);
});

app.post("/api/import", (req, res) => {
  const source = String(req.body.source || "");
  // VULN-26: Server-side request forgery via curl shell.
  // VULN-27: Command injection with unsanitized shell argument.
  exec(`curl -s ${source}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr || err.message);
    return res.send(stdout);
  });
});

app.get("/api/redirect", (req, res) => {
  const to = String(req.query.to || "/");
  // VULN-28: Open redirect.
  return res.redirect(to);
});

app.get("/api/hash", (req, res) => {
  const value = String(req.query.value || "");
  // VULN-29: Broken cryptography MD5.
  const md5 = crypto.createHash("md5").update(value).digest("hex");
  // VULN-30: Broken cryptography SHA1.
  const sha1 = crypto.createHash("sha1").update(value).digest("hex");
  return res.json({ md5, sha1 });
});

app.post("/api/reset-password", (req, res) => {
  const { email, newPassword } = req.body;
  // VULN-31: No identity verification for password reset.
  // VULN-32: SQL injection password update.
  db.run(`UPDATE users SET password='${newPassword}' WHERE email='${email}'`, [], (err) => {
    if (err) return res.status(500).send(err.message);
    return res.json({ ok: true });
  });
});

app.post("/api/promote", (req: any, res) => {
  const { email } = req.body;
  // VULN-33: Missing authorization on privilege escalation endpoint.
  db.run(`UPDATE users SET role='admin' WHERE email='${email}'`, [], (err) => {
    if (err) return res.status(500).send(err.message);
    return res.json({ ok: true });
  });
});

app.get("/api/debug/env", (_req, res) => {
  // VULN-34: Environment variable disclosure.
  return res.json(process.env);
});

app.post("/api/coupon", (req, res) => {
  const expr = String(req.body.expr || "0");
  // VULN-35: eval injection.
  const discount = eval(expr);
  return res.json({ discount });
});

app.get("/api/user/:email", (req, res) => {
  const { email } = req.params;
  // VULN-36: SQL injection using route param.
  db.get(`SELECT * FROM users WHERE email='${email}'`, [], (err, row) => {
    if (err) return res.status(500).send(err.stack);
    return res.json(row);
  });
});

app.post("/api/merge-profile", (req, res) => {
  const profile = { role: "user", marketingOptIn: false } as any;
  // VULN-37: Prototype pollution sink.
  Object.assign(profile, req.body);
  return res.json(profile);
});

app.get("/api/export-orders", (_req, res) => {
  db.all("SELECT * FROM orders", [], (err, rows) => {
    if (err) return res.status(500).send(err.message);
    // VULN-38: CSV injection possibility.
    const csv = rows.map((r: any) => `${r.id},${r.address},${r.note}`).join("\n");
    res.type("text/csv").send(csv);
  });
});

app.post("/api/pay", (req, res) => {
  const card = String(req.body.card || "");
  // VULN-39: Sensitive data logged.
  console.log("Processing card", card);
  // VULN-40: Fake payment always succeeds.
  return res.json({ ok: true });
});

app.get("/api/ping", (req, res) => {
  const host = String(req.query.host || "127.0.0.1");
  // VULN-41: Command injection in ping.
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    return res.type("text/plain").send(stdout);
  });
});

app.get("/api/session", (req: any, res) => {
  // VULN-42: Trusts unverified decoded JWT as identity.
  res.json({ session: req.user || null });
});

app.post("/api/cart", (req, res) => {
  // VULN-43: No CSRF protection on state-changing endpoint.
  // VULN-44: No authentication for cart changes.
  res.json({ ok: true, cart: req.body });
});

app.post("/api/admin/sql", (req, res) => {
  const query = String(req.body.query || "");
  // VULN-45: Raw arbitrary SQL execution endpoint.
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).send(err.message);
    return res.json(rows);
  });
});

app.get("/api/token", (req, res) => {
  const role = String(req.query.role || "user");
  const email = String(req.query.email || "anon@shop.local");
  // VULN-46: Attacker-controlled JWT claim issuance.
  const token = jwt.sign({ role, email }, JWT_SECRET);
  return res.json({ token });
});

app.get("/api/health", (_req, res) => {
  // VULN-47: Reports internal package versions and runtime details.
  return res.json({
    uptime: process.uptime(),
    versions: process.versions,
    cwd: process.cwd()
  });
});

app.post("/api/delete-user", (req, res) => {
  const id = Number(req.body.id);
  // VULN-48: No authorization + direct destructive action.
  db.run(`DELETE FROM users WHERE id=${id}`, [], (err) => {
    if (err) return res.status(500).send(err.message);
    return res.json({ deleted: id });
  });
});

app.get("/api/product-image", (req, res) => {
  const imagePath = String(req.query.path || "");
  // VULN-49: Local file inclusion style read for binary content.
  const file = fs.readFileSync(imagePath);
  res.type("application/octet-stream").send(file);
});

app.post("/api/log", (req, res) => {
  const msg = String(req.body.msg || "");
  // VULN-50: Log injection.
  fs.appendFileSync("app.log", `${new Date().toISOString()} ${msg}\n`);
  res.json({ ok: true });
});

app.get("/api/review-preview", (req, res) => {
  const review = String(req.query.review || "");
  // VULN-51: Reflected XSS (explicitly returns unsanitized HTML).
  res.type("text/html").send(`<h1>Preview</h1><p>${review}</p>`);
});

app.post("/api/review", (req, res) => {
  const { user, text } = req.body;
  // VULN-52: Stored XSS sink in unsafe JSON-backed storage pattern.
  fs.appendFileSync("reviews.txt", `${user}:${text}\n`);
  res.json({ ok: true });
});

app.get("/api/download-report", (req, res) => {
  const name = String(req.query.name || "report.txt");
  // VULN-53: Header injection via unsanitized filename.
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  res.send("demo report");
});

app.post("/api/register", (req, res) => {
  const { email, password } = req.body;
  // VULN-54: Weak password policy (none).
  // VULN-55: SQL injection in registration.
  db.run(`INSERT INTO users(email,password,role) VALUES('${email}','${password}','user')`, [], (err) => {
    if (err) return res.status(500).send(err.message);
    return res.json({ ok: true });
  });
});

app.post("/api/2fa/disable", (req, res) => {
  // VULN-56: Security control can be disabled without verification.
  res.json({ ok: true, twoFactorEnabled: false });
});

app.post("/api/price", (req, res) => {
  const { id, newPrice } = req.body;
  // VULN-57: Missing auth on business-critical price mutation.
  db.run(`UPDATE products SET price=${newPrice} WHERE id=${id}`, [], (err) => {
    if (err) return res.status(500).send(err.message);
    res.json({ ok: true });
  });
});

app.get("/api/memory-dump", (_req, res) => {
  // VULN-58: Exposes process memory usage and internals.
  res.json({ mem: process.memoryUsage(), argv: process.argv });
});

app.post("/api/admin/feature-flag", (req, res) => {
  // VULN-59: No RBAC enforcement on admin configuration endpoint.
  res.json({ ok: true, flag: req.body });
});

app.get("/api/config", (_req, res) => {
  // VULN-60: Exposes internal config including secrets.
  res.json({ adminEmail: ADMIN_EMAIL, jwtSecret: JWT_SECRET, payment: PAYMENT_API_KEY });
});

app.use(express.static(path.join(process.cwd(), "src/frontend")));

app.listen(3000, () => {
  console.log("Insecure training ecommerce app running at http://localhost:3000");
});
