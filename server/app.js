const express = require("express");
const path = require("path");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const crypto = require("crypto");
const db = require("./database");
const QRCode = require("qrcode");

const app = express();

const PORT = process.env.PORT || 3000;

const APP_URL = process.env.APP_URL || `http://192.168.1.190:${PORT}`;

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "kicksync-secret-key";


// ==========================================
// BASIC APP SETTINGS
// ==========================================

app.disable("x-powered-by");


// ==========================================
// MIDDLEWARE
// ==========================================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionStoreOptions = {
    host: process.env.MYSQLHOST,
    port: process.env.MYSQLPORT,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,

    schema: {
        tableName: "login_sessions",
        columnNames: {
            session_id: "session_id",
            expires: "expires",
            data: "data"
        }
    }
};

const sessionStore = new MySQLStore(sessionStoreOptions);

app.use(
    session({
        key: "kicksync_session",
        secret: SESSION_SECRET,
        store: sessionStore,
        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 8 * 60 * 60 * 1000
        }
    })
);


// ==========================================
// STATIC FILES
// ==========================================

app.use(
    express.static(
        path.join(__dirname, "../public")
    )
);

app.use(
    "/public",
    express.static(
        path.join(__dirname, "../public")
    )
);


// ==========================================
// DATABASE PROMISE HELPER
// ==========================================

function dbQuery(sql, values = []) {
    return new Promise((resolve, reject) => {
        db.query(sql, values, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}


// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

function requireLogin(req, res, next) {

    if (!req.session.user) {

        if (req.path.startsWith("/api/")) {
            return res.status(401).json({
                error: "You must be logged in."
            });
        }

        return res.redirect("/");
    }

    next();
}


// ==========================================
// PASSWORD SECURITY
// ==========================================

function hashPassword(password) {

    const salt = crypto.randomBytes(16).toString("base64");

    const hash = crypto.scryptSync(
        password,
        salt,
        64
    ).toString("base64");

    return `scrypt$${salt}$${hash}`;
}


function isHashedPassword(password) {

    return (
        typeof password === "string" &&
        password.startsWith("scrypt$")
    );
}


function verifyPassword(password, storedPassword) {

    if (!isHashedPassword(storedPassword)) {
        return false;
    }

    const parts = storedPassword.split("$");

    if (parts.length !== 3) {
        return false;
    }

    const salt = parts[1];
    const storedHash = parts[2];

    try {

        const calculatedHash = crypto.scryptSync(
            password,
            salt,
            64
        );

        const storedHashBuffer =
            Buffer.from(storedHash, "base64");

        if (
            calculatedHash.length !==
            storedHashBuffer.length
        ) {
            return false;
        }

        return crypto.timingSafeEqual(
            calculatedHash,
            storedHashBuffer
        );

    } catch (error) {

        console.error(
            "Password verification error:",
            error
        );

        return false;
    }
}


// ==========================================
// PAGE ROUTES
// ==========================================

app.get("/", (req, res) => {

    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.sendFile(
        path.join(
            __dirname,
            "../views/login.html"
        )
    );
});


app.get(
    "/dashboard",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/dashboard.html"
            )
        );

    }
);


app.get(
    "/trainees",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/trainees.html"
            )
        );

    }
);


app.get(
    "/register",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/register.html"
            )
        );

    }
);


app.get(
    "/attendance",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/attendance.html"
            )
        );

    }
);


app.get(
    "/qr",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/qr.html"
            )
        );

    }
);


app.get(
    "/sessions",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/sessions.html"
            )
        );

    }
);


app.get(
    "/report",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/report.html"
            )
        );

    }
);


app.get(
    "/profile",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/profile.html"
            )
        );

    }
);


app.get(
    "/groups",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/groups.html"
            )
        );

    }
);


app.get(
    "/settings",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/settings.html"
            )
        );

    }
);


app.get(
    "/edit/:id",
    requireLogin,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../views/edit.html"
            )
        );

    }
);


// ==========================================
// COACH REGISTRATION PAGE
// ==========================================

app.get("/coach-register", (req, res) => {

    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.send(`
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Create Coach Account - KICKSYNC</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, sans-serif;
            background: #eef4fb;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .register-box {
            width: 100%;
            max-width: 460px;
            background: white;
            border-radius: 14px;
            padding: 35px;
            box-shadow: 0 10px 35px rgba(0,0,0,0.12);
        }

        .logo {
            text-align: center;
            margin-bottom: 25px;
        }

        .logo h1 {
            margin: 0;
            color: #0756a3;
            font-size: 30px;
            font-weight: 800;
        }

        .logo span {
            color: #f5c400;
        }

        .logo p {
            margin-top: 7px;
            color: #667085;
            font-size: 14px;
        }

        h2 {
            text-align: center;
            color: #183b63;
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 7px;
            font-weight: 700;
            color: #344054;
            font-size: 14px;
        }

        input {
            width: 100%;
            padding: 13px;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            margin-bottom: 18px;
            font-size: 15px;
            outline: none;
        }

        input:focus {
            border-color: #0756a3;
            box-shadow: 0 0 0 3px rgba(7,86,163,0.10);
        }

        button {
            width: 100%;
            border: none;
            background: #0756a3;
            color: white;
            padding: 13px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
        }

        button:hover {
            background: #064684;
        }

        .back {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #0756a3;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
        }

        .note {
            margin-top: 20px;
            background: #f8fafc;
            border: 1px solid #e4e7ec;
            border-radius: 8px;
            padding: 12px;
            color: #667085;
            font-size: 12px;
            line-height: 1.5;
        }

    </style>

</head>

<body>

    <div class="register-box">

        <div class="logo">

            <h1>
                KICK<span>SYNC</span>
            </h1>

            <p>
                KCCA FC Academy Management System
            </p>

        </div>

        <h2>Create Coach Account</h2>

        <form method="POST" action="/coach-register">

            <label>Full Name</label>

            <input
                type="text"
                name="full_name"
                placeholder="Enter your full name"
                required
            >

            <label>Username</label>

            <input
                type="text"
                name="username"
                placeholder="Choose a username"
                required
            >

            <label>Password</label>

            <input
                type="password"
                name="password"
                placeholder="At least 8 characters"
                required
            >

            <label>Confirm Password</label>

            <input
                type="password"
                name="confirm_password"
                placeholder="Repeat your password"
                required
            >

            <button type="submit">
                Create Coach Account
            </button>

        </form>

        <a
            href="/"
            class="back"
        >
            ← Back to Login
        </a>

        <div class="note">
            Coach accounts are created with the
            <strong>Coach</strong> role.
            Passwords are securely hashed before
            being stored in the database.
        </div>

    </div>

</body>

</html>
    `);
});


// ==========================================
// COACH REGISTRATION
// ==========================================

app.post("/coach-register", async (req, res) => {

    const {
        full_name,
        username,
        password,
        confirm_password
    } = req.body;

    const cleanName =
        String(full_name || "").trim();

    const cleanUsername =
        String(username || "")
            .trim()
            .toLowerCase();

    if (
        !cleanName ||
        !cleanUsername ||
        !password ||
        !confirm_password
    ) {

        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>Please fill in all fields.</p>
            <a href="/coach-register">
                Try Again
            </a>
        `);

    }

    if (cleanUsername.length < 3) {

        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>
                Username must contain at least 3 characters.
            </p>
            <a href="/coach-register">
                Try Again
            </a>
        `);

    }

    if (password.length < 8) {

        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>
                Password must contain at least 8 characters.
            </p>
            <a href="/coach-register">
                Try Again
            </a>
        `);

    }

    if (password !== confirm_password) {

        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>
                Passwords do not match.
            </p>
            <a href="/coach-register">
                Try Again
            </a>
        `);

    }

    try {

        const existing = await dbQuery(
            `
            SELECT id
            FROM users
            WHERE username = ?
            `,
            [cleanUsername]
        );

        if (existing.length > 0) {

            return res.status(409).send(`
                <h2>Registration Failed</h2>
                <p>
                    That username is already in use.
                </p>
                <a href="/coach-register">
                    Try Again
                </a>
            `);

        }

        const hashedPassword =
            hashPassword(password);

        await dbQuery(
            `
            INSERT INTO users
            (
                full_name,
                username,
                password,
                role
            )
            VALUES (?, ?, ?, ?)
            `,
            [
                cleanName,
                cleanUsername,
                hashedPassword,
                "Coach"
            ]
        );

        res.send(`
<!DOCTYPE html>

<html>

<head>

    <title>Account Created - KICKSYNC</title>

    <style>

        body {
            font-family: Arial, sans-serif;
            background: #eef4fb;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }

        .box {
            background: white;
            padding: 40px;
            border-radius: 14px;
            text-align: center;
            box-shadow: 0 10px 35px rgba(0,0,0,0.12);
            max-width: 430px;
        }

        h2 {
            color: #0756a3;
        }

        a {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 20px;
            background: #0756a3;
            color: white;
            text-decoration: none;
            border-radius: 7px;
            font-weight: bold;
        }

    </style>

</head>

<body>

    <div class="box">

        <h2>Coach Account Created</h2>

        <p>
            Your coach account has been created successfully.
        </p>

        <p>
            You can now log in using your new username
            and password.
        </p>

        <a href="/">
            Go to Login
        </a>

    </div>

</body>

</html>
        `);

    } catch (error) {

        console.error(
            "Coach registration error:",
            error
        );

        res.status(500).send(`
            <h2>Registration Failed</h2>
            <p>
                An unexpected database error occurred.
            </p>
            <a href="/coach-register">
                Try Again
            </a>
        `);

    }

});


// ==========================================
// LOGIN
// ==========================================

app.post("/login", async (req, res) => {

    const username =
        String(req.body.username || "")
            .trim()
            .toLowerCase();

    const password =
        String(req.body.password || "");

    if (!username || !password) {

        return res.status(400).send(`
            <h2>Login Failed</h2>
            <p>
                Please enter your username and password.
            </p>
            <a href="/">Try Again</a>
        `);

    }

    try {

        const results = await dbQuery(
            `
            SELECT *
            FROM users
            WHERE username = ?
            LIMIT 1
            `,
            [username]
        );

        if (results.length === 0) {

            return res.status(401).send(`
                <h2>Login Failed</h2>
                <p>
                    Incorrect username or password.
                </p>
                <a href="/">Try Again</a>
            `);

        }

        const user = results[0];

        let passwordCorrect = false;

        if (isHashedPassword(user.password)) {

            passwordCorrect =
                verifyPassword(
                    password,
                    user.password
                );

        }

        else {

            passwordCorrect =
                password === user.password;

            if (passwordCorrect) {

                const newHash =
                    hashPassword(password);

                await dbQuery(
                    `
                    UPDATE users
                    SET password = ?
                    WHERE id = ?
                    `,
                    [
                        newHash,
                        user.id
                    ]
                );

            }

        }

        if (!passwordCorrect) {

            return res.status(401).send(`
                <h2>Login Failed</h2>
                <p>
                    Incorrect username or password.
                </p>
                <a href="/">Try Again</a>
            `);

        }

        req.session.user = {

            id: user.id,

            full_name:
                user.full_name,

            username:
                user.username,

            role:
                user.role || "Coach"

        };

        res.redirect("/dashboard");

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).send(`
            <h2>Login Error</h2>
            <p>
                Something went wrong while logging in.
            </p>
            <a href="/">Try Again</a>
        `);

    }

});


// ==========================================
// LOGOUT
// ==========================================

app.get("/logout", (req, res) => {

    req.session.destroy((err) => {

        if (err) {

            console.error(
                "Logout error:",
                err
            );

            return res.status(500).send(
                "Logout failed."
            );

        }

        res.clearCookie("kicksync_session");

        res.redirect("/");

    });

});


// ==========================================
// PROFILE API
// ==========================================

app.get(
    "/api/profile",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                `
                SELECT
                    id,
                    full_name,
                    username,
                    role
                FROM users
                WHERE id = ?
                `,
                [req.session.user.id]
            );

            if (results.length === 0) {

                return res.status(404).json({
                    error: "User not found."
                });

            }

            res.json(results[0]);

        } catch (error) {

            console.error(
                "Profile error:",
                error
            );

            res.status(500).json({
                error: "Failed to load profile."
            });

        }

    }
);


// ==========================================
// TRAINEE API
// ==========================================

// GET ALL TRAINEES (optionally filtered by group)
// Examples:
//   /api/trainees            -> all trainees
//   /api/trainees?group=u15  -> only U15 trainees

app.get(
    "/api/trainees",
    requireLogin,
    async (req, res) => {

        try {

            const group = String(req.query.group || "")
                .trim()
                .toLowerCase();

            let results;

            if (
                group === "u15" ||
                group === "u17" ||
                group === "u20"
            ) {

                results = await dbQuery(
                    `
                    SELECT *
                    FROM players
                    WHERE group_name = ?
                    ORDER BY id DESC
                    `,
                    [group]
                );

            } else {

                results = await dbQuery(
                    `
                    SELECT *
                    FROM players
                    ORDER BY id DESC
                    `
                );

            }

            res.json(results);

        } catch (error) {

            console.error(
                "Error loading trainees:",
                error
            );

            res.status(500).json({
                error:
                    "Error loading trainees"
            });

        }

    }
);


// GET ONE TRAINEE
app.get(
    "/api/trainees/:id",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                `
                SELECT *
                FROM players
                WHERE id = ?
                `,
                [req.params.id]
            );

            if (results.length === 0) {

                return res.status(404).json({
                    error:
                        "Trainee not found"
                });

            }

            res.json(results[0]);

        } catch (error) {

            console.error(
                "Error loading trainee:",
                error
            );

            res.status(500).json({
                error:
                    "Database error"
            });

        }

    }
);


// ==========================================
// REGISTER TRAINEE
// (Handles both form-based registration
//  and the JSON registration from
//  groups.html which sends { name, group })
// ==========================================

app.post(
    "/api/trainees",
    requireLogin,
    async (req, res) => {

        // ---- JSON registration from groups.html ----
        if (req.is("application/json")) {

            const name =
                String(req.body.name || "").trim();

            const group =
                String(req.body.group || "")
                    .trim()
                    .toLowerCase();

            if (!name || !group) {

                return res.status(400).json({
                    message:
                        "Trainee name and group are required."
                });

            }

            // Derive an age from the group
            let age = 14;

            if (group === "u15") age = 14;
            else if (group === "u17") age = 16;
            else if (group === "u20") age = 19;
            else {

                return res.status(400).json({
                    message:
                        "Invalid training group."
                });

            }

            const position = "Trainee";

            try {

                await dbQuery(
                    `
                    INSERT INTO players
                    (
                        full_name,
                        age,
                        position,
                        group_name
                    )
                    VALUES (?, ?, ?, ?)
                    `,
                    [
                        name,
                        age,
                        position,
                        group
                    ]
                );

                return res.status(201).json({
                    message:
                        "Trainee registered successfully."
                });

            } catch (error) {

                console.error(
                    "Registration error:",
                    error
                );

                return res.status(500).json({
                    message:
                        "Failed to register trainee."
                });

            }

        }

        // ---- Original form-based registration ----
        const full_name =
            String(req.body.full_name || "").trim();

        const age =
            req.body.age;

        const position =
            String(req.body.position || "").trim();

        if (
            !full_name ||
            !age ||
            !position
        ) {

            return res.status(400).send(
                "Please fill in all fields."
            );

        }

        try {

            await dbQuery(
                `
                INSERT INTO players
                (
                    full_name,
                    age,
                    position
                )
                VALUES (?, ?, ?)
                `,
                [
                    full_name,
                    age,
                    position
                ]
            );

            res.redirect("/trainees");

        } catch (error) {

            console.error(
                "Registration error:",
                error
            );

            res.status(500).send(
                "Registration failed."
            );

        }

    }
);


// UPDATE TRAINEE

app.post(
    "/api/trainees/:id/update",
    requireLogin,
    async (req, res) => {

        const full_name =
            String(req.body.full_name || "").trim();

        const age =
            req.body.age;

        const position =
            String(req.body.position || "").trim();

        if (
            !full_name ||
            !age ||
            !position
        ) {

            return res.status(400).send(
                "Please fill in all fields."
            );

        }

        try {

            await dbQuery(
                `
                UPDATE players
                SET
                    full_name = ?,
                    age = ?,
                    position = ?
                WHERE id = ?
                `,
                [
                    full_name,
                    age,
                    position,
                    req.params.id
                ]
            );

            res.redirect("/trainees");

        } catch (error) {

            console.error(
                "Update error:",
                error
            );

            res.status(500).send(
                "Failed to update trainee."
            );

        }

    }
);


// DELETE TRAINEE

app.post(
    "/api/trainees/:id/delete",
    requireLogin,
    async (req, res) => {

        try {

            await dbQuery(
                `
                DELETE FROM attendance
                WHERE player_id = ?
                `,
                [req.params.id]
            );

            await dbQuery(
                `
                DELETE FROM players
                WHERE id = ?
                `,
                [req.params.id]
            );

            res.redirect("/trainees");

        } catch (error) {

            console.error(
                "Delete error:",
                error
            );

            res.status(500).send(
                "Failed to delete trainee."
            );

        }

    }
);


// ==========================================
// GROUPS API
// Counts are based on group_name so they
// match the /api/trainees filter exactly.
// ==========================================

app.get(
    "/api/groups/stats",
    requireLogin,
    async (req, res) => {

        try {

            const u15 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u15'"
            );

            const u17 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u17'"
            );

            const u20 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u20'"
            );

            const total = await dbQuery(
                "SELECT COUNT(*) AS count FROM players"
            );

            res.json({
                u15: u15[0].count,
                u17: u17[0].count,
                u20: u20[0].count,
                total: total[0].count
            });

        } catch (error) {

            console.error(
                "Error loading group stats:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load group stats."
            });

        }

    }
);


// Backwards-compatible alias
app.get(
    "/api/groups/counts",
    requireLogin,
    async (req, res) => {

        try {

            const u15 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u15'"
            );

            const u17 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u17'"
            );

            const u20 = await dbQuery(
                "SELECT COUNT(*) AS count FROM players WHERE group_name = 'u20'"
            );

            const total = await dbQuery(
                "SELECT COUNT(*) AS count FROM players"
            );

            res.json({
                u15: u15[0].count,
                u17: u17[0].count,
                u20: u20[0].count,
                total: total[0].count
            });

        } catch (error) {

            console.error(
                "Error loading group counts:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load group counts."
            });

        }

    }
);


// ==========================================
// DATABASE TEST
// ==========================================

app.get(
    "/test-db",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                "SELECT * FROM players"
            );

            res.json(results);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error:
                    "Database connection failed"
            });

        }

    }
);


// ==========================================
// TRAINING SESSIONS API
// ==========================================

app.get(
    "/api/sessions",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                `
                SELECT

                    id,

                    DATE_FORMAT(
                        session_date,
                        '%Y-%m-%d'
                    ) AS session_date,

                    TIME_FORMAT(
                        session_time,
                        '%H:%i'
                    ) AS session_time,

                    location,
                    session_type,
                    coach,
                    status

                FROM sessions

                ORDER BY
                    session_date DESC,
                    session_time DESC
                `
            );

            res.json(results);

        } catch (error) {

            console.error(
                "Error loading sessions:",
                error
            );

            res.status(500).json({
                error:
                    "Error loading sessions"
            });

        }

    }
);


app.post(
    "/api/sessions",
    requireLogin,
    async (req, res) => {

        const {
            session_date,
            session_time,
            location,
            session_type,
            coach,
            status
        } = req.body;

        if (
            !session_date ||
            !session_time ||
            !location ||
            !session_type ||
            !coach ||
            !status
        ) {

            return res.status(400).send(
                "Please fill in all session fields."
            );

        }

        try {

            await dbQuery(
                `
                INSERT INTO sessions
                (
                    session_date,
                    session_time,
                    location,
                    session_type,
                    coach,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                `,
                [
                    session_date,
                    session_time,
                    location,
                    session_type,
                    coach,
                    status
                ]
            );

            res.send(
                "Training session created successfully."
            );

        } catch (error) {

            console.error(
                "Session creation error:",
                error
            );

            res.status(500).send(
                "Failed to create training session."
            );

        }

    }
);


// ==========================================
// MANUAL ATTENDANCE API
// ==========================================

app.post(
    "/api/attendance",
    requireLogin,
    async (req, res) => {

        let records = req.body;

        if (!Array.isArray(records)) {
            records = [records];
        }

        if (records.length === 0) {

            return res.status(400).json({
                error:
                    "No attendance records received."
            });

        }

        try {

            const saved = [];
            const skipped = [];

            for (const record of records) {

                const {
                    player_id,
                    attendance_date,
                    status,
                    session_id
                } = record;

                if (
                    !player_id ||
                    !attendance_date ||
                    !status ||
                    !session_id
                ) {

                    continue;
                }

                const player =
                    await dbQuery(
                        `
                        SELECT id
                        FROM players
                        WHERE id = ?
                        `,
                        [player_id]
                    );

                if (player.length === 0) {
                    continue;
                }

                const trainingSession =
                    await dbQuery(
                        `
                        SELECT
                            id,
                            session_date
                        FROM sessions
                        WHERE id = ?
                        `,
                        [session_id]
                    );

                if (
                    trainingSession.length === 0
                ) {
                    continue;
                }

                const existing =
                    await dbQuery(
                        `
                        SELECT id
                        FROM attendance
                        WHERE player_id = ?
                        AND session_id = ?
                        `,
                        [
                            player_id,
                            session_id
                        ]
                    );

                if (existing.length > 0) {

                    skipped.push(
                        Number(player_id)
                    );

                    continue;
                }

                // =====================================
                // SAFETY RULE
                //
                // The coach route may only write
                // 'Absent'.  'Present' is written
                // exclusively by the QR scan route.
                //
                // Any incoming 'Present' (or anything
                // other than 'Absent') is rejected.
                // =====================================

                if (status !== "Absent") {

                    skipped.push(
                        Number(player_id)
                    );

                    continue;
                }

                const result =
                    await dbQuery(
                        `
                        INSERT INTO attendance
                        (
                            player_id,
                            attendance_date,
                            status,
                            session_id
                        )
                        VALUES (?, ?, ?, ?)
                        `,
                        [
                            player_id,
                            attendance_date,
                            "Absent",
                            session_id
                        ]
                    );

                saved.push(
                    result.insertId
                );
            }

            res.json({

                message:
                    "Attendance processed successfully.",

                saved_count:
                    saved.length,

                skipped_count:
                    skipped.length,

                attendance_ids:
                    saved

            });

        } catch (error) {

            console.error(
                "Attendance save error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to save attendance."
            });

        }

    }
);


// ==========================================
// TODAY'S ATTENDANCE
// ==========================================

app.get(
    "/api/attendance/today",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                `
                SELECT *
                FROM attendance
                WHERE attendance_date = CURDATE()
                `
            );

            res.json(results);

        } catch (error) {

            console.error(
                "Error loading today's attendance:",
                error
            );

            res.status(500).json({
                error:
                    "Error loading today's attendance"
            });

        }

    }
);


// ==========================================
// ATTENDANCE REPORT
// ==========================================

app.get(
    "/api/attendance/report",
    requireLogin,
    async (req, res) => {

        try {

            const results = await dbQuery(
                `
                SELECT

                    attendance.id,
                    attendance.attendance_date,
                    attendance.status,
                    attendance.session_id,

                    players.id AS player_id,
                    players.full_name,
                    players.age,
                    players.position,

                    sessions.session_date,
                    sessions.session_time,
                    sessions.location,
                    sessions.session_type,
                    sessions.coach

                FROM attendance

                INNER JOIN players
                    ON attendance.player_id =
                       players.id

                LEFT JOIN sessions
                    ON attendance.session_id =
                       sessions.id

                ORDER BY
                    attendance.attendance_date DESC,
                    players.full_name ASC
                `
            );

            res.json(results);

        } catch (error) {

            console.error(
                "Error loading attendance report:",
                error
            );

            res.status(500).json({
                error:
                    "Error loading attendance report"
            });

        }

    }
);


// ==========================================
// QR CODE GENERATION
// ==========================================

app.get(
    "/api/qr/:sessionId",
    requireLogin,
    async (req, res) => {

        const sessionId =
            req.params.sessionId;

        if (!sessionId) {

            return res.status(400).json({
                error:
                    "Session ID is required."
            });

        }

        try {

            const sessions =
                await dbQuery(
                    `
                    SELECT
                        id,
                        session_date,
                        session_time,
                        location,
                        session_type,
                        coach,
                        status
                    FROM sessions
                    WHERE id = ?
                    `,
                    [sessionId]
                );

            if (sessions.length === 0) {

                return res.status(404).json({
                    error:
                        "Training session not found."
                });

            }

            const qrData =
                `${APP_URL}/qr-scan?session=${sessionId}`;

            const qrCode =
                await QRCode.toDataURL(
                    qrData
                );

            res.json({

                session_id:
                    sessionId,

                qr_code:
                    qrCode,

                attendance_url:
                    qrData

            });

        } catch (error) {

            console.error(
                "QR code generation error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to generate QR code."
            });

        }

    }
);


// ==========================================
// PUBLIC QR SESSION INFORMATION
// ==========================================

app.get(
    "/api/qr/session/:sessionId",
    async (req, res) => {

        try {

            const sessions =
                await dbQuery(
                    `
                    SELECT
                        id,
                        session_date,
                        session_time,
                        location,
                        session_type,
                        coach,
                        status
                    FROM sessions
                    WHERE id = ?
                    `,
                    [req.params.sessionId]
                );

            if (sessions.length === 0) {

                return res.status(404).json({
                    error:
                        "Training session not found."
                });

            }

            const players =
                await dbQuery(
                    `
                    SELECT
                        id,
                        full_name,
                        age,
                        position
                    FROM players
                    ORDER BY full_name ASC
                    `
                );

            res.json({

                session:
                    sessions[0],

                players:
                    players

            });

        } catch (error) {

            console.error(
                "QR session information error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load QR attendance information."
            });

        }

    }
);


// ==========================================
// PUBLIC QR SCANNING PAGE
// ==========================================

app.get(
    "/qr-scan",
    async (req, res) => {

        const sessionId =
            req.query.session;

        if (!sessionId) {

            return res.status(400).send(`
                <h2>Invalid QR Code</h2>
                <p>No training session was provided.</p>
            `);

        }

        try {

            const sessions =
                await dbQuery(
                    `
                    SELECT
                        id,
                        session_date,
                        session_time,
                        location,
                        session_type,
                        coach,
                        status
                    FROM sessions
                    WHERE id = ?
                    `,
                    [sessionId]
                );

            if (sessions.length === 0) {

                return res.status(404).send(`
                    <h2>Session Not Found</h2>
                    <p>
                        This QR code belongs to a
                        session that does not exist.
                    </p>
                `);

            }

            const players =
                await dbQuery(
                    `
                    SELECT
                        id,
                        full_name,
                        position
                    FROM players
                    ORDER BY full_name ASC
                    `
                );

            const trainingSession =
                sessions[0];

            const playerOptions =
                players.map(player => {

                    return `
                        <option value="${player.id}">
                            ${escapeHtml(player.full_name)}
                            -
                            ${escapeHtml(player.position)}
                        </option>
                    `;

                }).join("");


            res.send(`
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>KICKSYNC QR Attendance</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            background: #eef4fb;
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            width: 100%;
            max-width: 520px;
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow:
                0 12px 35px
                rgba(0,0,0,0.12);
        }

        .brand {
            text-align: center;
            margin-bottom: 25px;
        }

        .brand h1 {
            margin: 0;
            color: #0756a3;
            font-size: 30px;
        }

        .brand h1 span {
            color: #f5c400;
        }

        .brand p {
            color: #667085;
            font-size: 13px;
        }

        .session {
            background: #f8fafc;
            border: 1px solid #e4e7ec;
            border-radius: 10px;
            padding: 18px;
            margin-bottom: 22px;
        }

        .session h2 {
            margin-top: 0;
            color: #183b63;
            font-size: 20px;
        }

        .session p {
            margin: 8px 0;
            color: #475467;
            font-size: 14px;
        }

        label {
            display: block;
            font-weight: 700;
            color: #344054;
            margin-bottom: 8px;
        }

        select {
            width: 100%;
            padding: 13px;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            font-size: 15px;
            margin-bottom: 18px;
            background: white;
        }

        button {
            width: 100%;
            padding: 14px;
            background: #0756a3;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
        }

        button:hover {
            background: #064684;
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .message {
            margin-top: 18px;
            padding: 13px;
            border-radius: 8px;
            display: none;
            font-size: 14px;
            line-height: 1.5;
        }

        .success {
            background: #ecfdf3;
            color: #027a48;
            border: 1px solid #abefc6;
        }

        .error {
            background: #fef3f2;
            color: #b42318;
            border: 1px solid #fecdca;
        }

        .footer {
            text-align: center;
            margin-top: 22px;
            font-size: 12px;
            color: #98a2b3;
        }

    </style>

</head>

<body>

    <div class="container">

        <div class="brand">

            <h1>
                KICK<span>SYNC</span>
            </h1>

            <p>
                KCCA FC Academy Attendance
            </p>

        </div>

        <div class="session">

            <h2>
                ${escapeHtml(trainingSession.session_type)}
            </h2>

            <p>
                <strong>Date:</strong>
                ${escapeHtml(
                    String(trainingSession.session_date)
                )}
            </p>

            <p>
                <strong>Time:</strong>
                ${escapeHtml(
                    String(trainingSession.session_time)
                )}
            </p>

            <p>
                <strong>Location:</strong>
                ${escapeHtml(
                    trainingSession.location
                )}
            </p>

            <p>
                <strong>Coach:</strong>
                ${escapeHtml(
                    trainingSession.coach
                )}
            </p>

        </div>

        <form id="qrAttendanceForm">

            <label for="player">
                Select Your Name
            </label>

            <select
                id="player"
                required
            >

                <option value="">
                    -- Select trainee --
                </option>

                ${playerOptions}

            </select>

            <button
                type="submit"
                id="markButton"
            >
                Mark Me Present
            </button>

        </form>

        <div
            id="message"
            class="message"
        ></div>

        <div class="footer">
            KICKSYNC • KCCA FC Academy
        </div>

    </div>


<script>

const form =
    document.getElementById(
        "qrAttendanceForm"
    );

const player =
    document.getElementById(
        "player"
    );

const button =
    document.getElementById(
        "markButton"
    );

const message =
    document.getElementById(
        "message"
    );


form.addEventListener(
    "submit",
    async function(event) {

        event.preventDefault();

        const playerId =
            player.value;

        if (!playerId) {

            showMessage(
                "Please select your name.",
                false
            );

            return;
        }

        button.disabled = true;

        button.textContent =
            "Recording Attendance...";

        try {

            const response =
                await fetch(
                    "/api/qr-attendance",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({

                            player_id:
                                Number(playerId),

                            session_id:
                                Number(${Number(sessionId)})

                        })
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Attendance could not be recorded."
                );

            }

            showMessage(
                data.message,
                true
            );

            form.reset();

            button.textContent =
                "Attendance Recorded";

        } catch (error) {

            showMessage(
                error.message,
                false
            );

            button.disabled = false;

            button.textContent =
                "Mark Me Present";
        }

    }
);


function showMessage(
    text,
    success
) {

    message.textContent =
        text;

    message.className =
        success
            ? "message success"
            : "message error";

    message.style.display =
        "block";
}

</script>

</body>

</html>
            `);

        } catch (error) {

            console.error(
                "QR page error:",
                error
            );

            res.status(500).send(`
                <h2>QR Attendance Error</h2>
                <p>
                    Could not load the attendance page.
                </p>
            `);

        }

    }
);


// ==========================================
// QR ATTENDANCE SUBMISSION
// ==========================================

app.post(
    "/api/qr-attendance",
    async (req, res) => {

        const {
            player_id,
            session_id
        } = req.body;

        if (
            !player_id ||
            !session_id
        ) {

            return res.status(400).json({
                error:
                    "Trainee and session are required."
            });

        }

        try {

            const players =
                await dbQuery(
                    `
                    SELECT id
                    FROM players
                    WHERE id = ?
                    `,
                    [player_id]
                );

            if (players.length === 0) {

                return res.status(404).json({
                    error:
                        "Trainee not found."
                });

            }

            const sessions =
                await dbQuery(
                    `
                    SELECT
                        id,
                        session_date
                    FROM sessions
                    WHERE id = ?
                    `,
                    [session_id]
                );

            if (sessions.length === 0) {

                return res.status(404).json({
                    error:
                        "Training session not found."
                });

            }

            const existing =
                await dbQuery(
                    `
                    SELECT id
                    FROM attendance
                    WHERE player_id = ?
                    AND session_id = ?
                    `,
                    [
                        player_id,
                        session_id
                    ]
                );

            if (existing.length > 0) {

                return res.status(409).json({
                    error:
                        "Your attendance has already been recorded for this session."
                });

            }

            const sessionDate =
                sessions[0].session_date;

            const result =
                await dbQuery(
                    `
                    INSERT INTO attendance
                    (
                        player_id,
                        attendance_date,
                        status,
                        session_id
                    )
                    VALUES (?, ?, ?, ?)
                    `,
                    [
                        player_id,
                        sessionDate,
                        "Present",
                        session_id
                    ]
                );

            res.json({

                message:
                    "Attendance marked successfully.",

                attendance_id:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "QR attendance error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to record attendance."
            });

        }

    }
);


// ==========================================
// HTML ESCAPE HELPER
// ==========================================

function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// ==========================================
// 404 HANDLER
// ==========================================

app.use((req, res) => {

    if (req.path.startsWith("/api/")) {

        return res.status(404).json({
            error:
                "API endpoint not found."
        });

    }

    res.status(404).send(`
        <h2>404 - Page Not Found</h2>
        <p>
            The page you requested does not exist.
        </p>
        <a href="/">
            Return to Login
        </a>
    `);

});


// ==========================================
// START SERVER
// ==========================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Server running on ${APP_URL}`
        );

        console.log(
            "KICKSYNC backend is ready."
        );

    }
);