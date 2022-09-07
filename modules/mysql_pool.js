const fs = require("fs");
const mysql = require("mysql2/promise");

const data = fs.readFileSync("./modules/.hosts", "utf8");
const hosts = JSON.parse(data);
hosts.connectionLimit = 10;

const pool = mysql.createPool(hosts);

module.exports = pool;
