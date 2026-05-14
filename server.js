require('dotenv').config(); // Loads the secret .env file
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL driver
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
// Cloud hosts dynamically assign ports, so we use process.env.PORT
const PORT = process.env.PORT || 3000; 

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to Supabase PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required by most cloud databases
});

// Create Users Table if it doesn't exist (Postgres syntax)
const initDB = async () => {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )`);
        console.log("Connected to Supabase Postgres & Table Verified!");
    } catch (err) {
        console.error("Database connection error:", err);
    }
};
initDB();

// --- SIGNUP ROUTE ---
app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Required fields missing." });

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Postgres uses $1, $2 for security instead of ?, ?
        await pool.query(`INSERT INTO users (email, password) VALUES ($1, $2)`, [email, hashedPassword]);
        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        if (error.code === '23505') { // Postgres unique constraint violation code
            return res.status(400).json({ message: "Email already exists." });
        }
        res.status(500).json({ message: "Server error during signup." });
    }
});

// --- LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Required fields missing." });

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];

        if (!user) return res.status(400).json({ message: "Invalid email or password." });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid email or password." });

        res.status(200).json({ message: "Login successful! Welcome back." });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});