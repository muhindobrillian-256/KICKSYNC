require("dotenv").config();

const mysql = require("mysql2");

const db = mysql.createConnection({
    host: process.env.MYSQLHOST || "localhost",
    user: process.env.MYSQLUSER || "root",
    password: process.env.MYSQLPASSWORD || "",
    database: process.env.MYSQLDATABASE || "kicksync",
    port: process.env.MYSQLPORT || 3306
});

db.connect((err) => {
    if (err) {
        console.error("MySQL connection failed:");
        console.error(err.message);
        return;
    }

    console.log("Connected to MySQL database.");
});

module.exports = db;