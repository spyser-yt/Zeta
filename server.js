require('dotenv').config(); // Loads the secret .env file
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL driver
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
// Cloud hosts dynamically assign ports
const PORT = process.env.PORT || 3000; 

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to Supabase PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

// Verify Database Connection
// (We removed the CREATE TABLE query because you already built the professional schema directly in Supabase)
const initDB = async () => {
    try {
        await pool.query('SELECT NOW()');
        console.log("Connected to Supabase Postgres securely!");
    } catch (err) {
        console.error("Database connection error:", err);
    }
};
initDB();

// Helper Function: Generate a safe 5-digit Admission Number
const generateAdmissionNumber = async () => {
    const result = await pool.query(`SELECT MAX(id) as max_id FROM users`);
    const currentMax = result.rows[0].max_id || 0; 
    const nextNumber = currentMax + 1;
    return nextNumber.toString().padStart(5, '0'); 
};

// --- UPGRADED STUDENT SIGNUP ROUTE ---
app.post('/api/signup', async (req, res) => {
    const { 
        fullName, email, password, personalPhone, 
        parentPhone, school, classGrade, dob, 
        gender, bloodGroup, address 
    } = req.body;

    // Basic validation
    if (!email || !password || !fullName || !personalPhone) {
        return res.status(400).json({ message: "Name, Email, Password, and Personal Phone are strictly required." });
    }

    try {
        const admissionNumber = await generateAdmissionNumber();
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const query = `
            INSERT INTO users (
                admission_number, full_name, email, password_hash, 
                personal_phone, parent_phone, school, class_grade, 
                dob, gender, blood_group, address
            ) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
            RETURNING admission_number, full_name, role
        `;
        
        const values = [
            admissionNumber, fullName, email, hashedPassword, 
            personalPhone, parentPhone || null, school || null, classGrade || null, 
            dob || null, gender || null, bloodGroup || null, address || null
        ];

        const result = await pool.query(query, values);
        const newUser = result.rows[0];

        res.status(201).json({ 
            message: `Admission successful! Welcome ${newUser.full_name}.`,
            admissionNumber: newUser.admission_number,
            role: newUser.role
        });

    } catch (error) {
        if (error.code === '23505') { 
            if (error.constraint === 'users_email_key') {
                return res.status(400).json({ message: "This email is already registered." });
            }
            if (error.constraint === 'users_personal_phone_key') {
                return res.status(400).json({ message: "This personal phone number is already registered." });
            }
        }
        console.error("Signup Error:", error);
        res.status(500).json({ message: "Server error during admission." });
    }
});

// --- UPGRADED LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Required fields missing." });

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];

        if (!user) return res.status(400).json({ message: "Invalid email or password." });

        // IMPORTANT FIX: We now check against 'user.password_hash' instead of 'user.password'
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ message: "Invalid email or password." });

        // Enterprise Feature: Block suspended users
        if (user.status === 'Suspended') {
            return res.status(403).json({ message: "This account is suspended. Please contact the administrator." });
        }

        // Enterprise Feature: Update the last_login timestamp automatically
        await pool.query(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`, [user.id]);

        res.status(200).json({ 
            message: `Login successful! Welcome back, ${user.full_name}.`,
            role: user.role,
            admissionNumber: user.admission_number
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});