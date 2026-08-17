const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const authentifierToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Accès refusé. Token manquant." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token invalide ou expiré." });
        req.user = user;
        next();
    });
};

app.post('/api/auth/register', async (req, res) => {
    const { nom, etablissement, email, password } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: "Tous les champs sont requis." });

    try {
        const userExist = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExist.rows.length > 0) return res.status(400).json({ error: "Cet email est déjà utilisé." });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await db.query(
            'INSERT INTO users (nom, etablissement, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, nom, email, etablissement',
            [nom, etablissement || null, email, hashedPassword]
        );

        const user = newUser.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({ token, user });
    } catch (err) {
        res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ error: "Identifiants incorrects." });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: "Identifiants incorrects." });

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, etablissement: user.etablissement } });
    } catch (err) {
        res.status(500).json({ error: "Erreur serveur." });
    }
});

app.post('/api/simulations', authentifierToken, async (req, res) => {
    const { isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh } = req.body;
    try {
        const newSimu = await db.query(
            `INSERT INTO simulations (user_id, isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [req.user.id, isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh]
        );
        res.status(201).json({ message: "Simulation enregistrée", simulation: newSimu.rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Erreur lors de l'enregistrement." });
    }
});

app.listen(PORT, () => console.log(`Serveur actif sur le port ${PORT}`));
