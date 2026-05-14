require('dotenv').config();
const express = require('express');
const { Pool } = require('pg'); 
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000; 

// Increase payload limit to 5MB to handle Base64 Profile Photos
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Connect to Supabase PostgreSQL (Zeta Database)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

const initDB = async () => {
    try {
        await pool.query('SELECT NOW()');
        console.log("Connected to Zeta Postgres Database securely!");
    } catch (err) {
        console.error("Database connection error:", err);
    }
};
initDB();

// Helper: Generate Role-Based ID (e.g., ZETA-STU-00001)
const generateZetaID = async (role) => {
    const result = await pool.query(`SELECT MAX(id) as max_id FROM users`);
    const currentMax = result.rows[0].max_id || 0; 
    const nextNumber = (currentMax + 1).toString().padStart(5, '0');
    
    let prefix = 'STU';
    if (role === 'Teacher') prefix = 'TCH';
    if (role === 'Admin') prefix = 'ADM';
    
    return `ZETA-${prefix}-${nextNumber}`; 
};

// --- MULTI-STEP SIGNUP ROUTE ---
app.post('/api/signup', async (req, res) => {
    const { 
        role, email, password, personalPhone, 
        fullName, dob, gender, school, classGrade, 
        course, whatsappPhone, parentPhone, address, profilePhoto 
    } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({ message: "Core account details are missing." });
    }

    try {
        const zetaID = await generateZetaID(role);
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const query = `
            INSERT INTO users (
                admission_number, role, email, password_hash, personal_phone, 
                full_name, dob, gender, school, class_grade, 
                course_enrolled, whatsapp_phone, parent_phone, address, profile_picture
            ) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
            RETURNING admission_number, full_name, role
        `;
        
        const values = [
            zetaID, role, email, hashedPassword, personalPhone,
            fullName, dob || null, gender || null, school || 'Zeta Coaching Centre', classGrade || null, 
            course || null, whatsappPhone || null, parentPhone || null, address || null, profilePhoto || null
        ];

        const result = await pool.query(query, values);
        const newUser = result.rows[0];

        res.status(201).json({ 
            message: `Account created! Welcome to Zeta, ${newUser.full_name}.`,
            zetaID: newUser.admission_number,
            role: newUser.role,
            fullName: newUser.full_name
        });

    } catch (error) {
        if (error.code === '23505' && error.constraint === 'users_email_key') { 
            return res.status(400).json({ message: "Email already registered." });
        }
        console.error("Signup Error:", error);
        res.status(500).json({ message: "Server error during account creation." });
    }
});

// --- LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Required fields missing." });

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(400).json({ message: "Invalid credentials." });
        }

        if (user.status === 'Suspended') {
            return res.status(403).json({ message: "This account is suspended. Contact Zeta administration." });
        }

        await pool.query(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`, [user.id]);

        res.status(200).json({ 
            message: `Login successful! Welcome back, ${user.full_name}.`,
            role: user.role,
            admissionNumber: user.admission_number,
            fullName: user.full_name,
            classGrade: user.class_grade || 'Staff',
            school: user.school || 'Zeta'
        });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
});

app.listen(PORT, () => console.log(`Zeta Backend live on port ${PORT}`));