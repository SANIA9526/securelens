// Deliberately vulnerable Express server used to demo SecureLens. DO NOT DEPLOY.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const mysql = require("mysql");

const app = express();
const db = mysql.createConnection({ host: "localhost", user: "root" });
const API_KEY = "sk_live_9f8e7d6c5b4a3210";

app.get("/search", (req, res) => {
  db.query(`SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`, (err, rows) => res.json(rows));
});

app.get("/convert", (req, res) => {
  exec(`convert ${req.query.file} out.png`, () => res.send("done"));
});

app.get("/file", (req, res) => {
  res.send(fs.readFileSync("./public/" + req.query.name));
});

app.get("/reset", (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  const digest = crypto.createHash("md5").update(resetToken).digest("hex");
  res.json({ digest });
});

app.post("/calc", express.json(), (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

app.listen(3000);
