require("dotenv").config();

const MySQL = require("mysql2");

console.log("MYSQLHOST:", process.env.MYSQLHOST ? "FOUND" : "MISSING");
console.log("MYSQLPORT:", process.env.MYSQLPORT ? "FOUND" : "MISSING");
console.log("MYSQLDATABASE:", process.env.MYSQLDATABASE ? "FOUND" : "MISSING");

const DB = MySQL.createPool({
    host: process.env.MYSQLHOST || "localhost",
    port: process.env.MYSQLPORT || 3306,
    user: process.env.MYSQLUSER || "root",
    password: process.env.MYSQLPASSWORD || "",
    database: process.env.MYSQLDATABASE || "kicksync",

    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

DB.getConnection((err, connection) => {
    if (err) {
        console.error("MySQL connection failed:");
        console.error(err.message);
        return;
    }

    console.log("Connected to MySQL database.");

    connection.release();
});

module.exports = DB;