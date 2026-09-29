require("dotenv").config();

const MySQL = require("mysql2");

const DB = MySQL.createPool({
    host: process.env.MYSQLHOST || process.env.MYSQL_HOST || "localhost",

    port: process.env.MYSQLPORT || process.env.MYSQL_PORT || 3306,

    user: process.env.MYSQLUSER || process.env.MYSQL_USER || "root",

    password: process.env.MYSQLPASSWORD || process.env.MYSQL_PASSWORD || "",

    database: process.env.MYSQLDATABASE || process.env.MYSQL_DATABASE || "kicksync",

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