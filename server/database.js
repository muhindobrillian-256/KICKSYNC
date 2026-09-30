require("dotenv").config();

const MySQL = require("mysql2");

console.log("MYSQL_URL exists:", !!process.env.MYSQL_URL);

const DB = MySQL.createPool(process.env.MYSQL_URL || "mysql://root:@localhost:3306/kicksync");

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