const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// Configuration CORS permissive pour autoriser Trebedit (file://)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ==========================================
// Protection anti brute-force (basique, en mémoire)
// ==========================================
const tentativesLogin = new Map(); // email -> { count, lastAttempt }
const MAX_TENTATIVES = 5;
const FENETRE_MS = 15 * 60 * 1000; // 15 minutes

function verifierTentatives(email) {
    const entry = tentativesLogin.get(email);
    if (!entry) return true;
    if (Date.now() - entry.lastAttempt > FENETRE_MS) {
        tentativesLogin.delete(email);
        return true;
    }
    return entry.count < MAX_TENTATIVES;
}

function enregistrerTentativeEchouee(email) {
    const entry = tentativesLogin.get(email) || { count: 0, lastAttempt: Date.now() };
    entry.count += 1;
    entry.lastAttempt = Date.now();
    tentativesLogin.set(email, entry);
}

function reinitialiserTentatives(email) {
    tentativesLogin.delete(email);
}

// Middleware d'authentification par Token JWT
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

function validerMotDePasse(password) {
    const regle = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;
    return regle.test(password);
}

// Route 1 : Inscription
app.post('/api/auth/register', async (req, res) => {
    const { nom, etablissement, email, password } = req.body;
    if (!nom || !email || !password) {
        return res.status(400).json({ error: "Tous les champs sont requis." });
    }

    if (!validerMotDePasse(password)) {
        return res.status(400).json({ error: "Le mot de passe doit contenir au moins 8 caractères, avec une lettre et un chiffre." });
    }

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
        console.error('Erreur inscription:', err.message);
        res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
});

// Route 2 : Connexion (avec protection anti brute-force)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });

    if (!verifierTentatives(email)) {
        return res.status(429).json({ error: "Trop de tentatives échouées. Réessayez dans 15 minutes." });
    }

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            enregistrerTentativeEchouee(email);
            return res.status(400).json({ error: "Identifiants incorrects." });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            enregistrerTentativeEchouee(email);
            return res.status(400).json({ error: "Identifiants incorrects." });
        }

        reinitialiserTentatives(email);

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, etablissement: user.etablissement } });
    } catch (err) {
        console.error('Erreur connexion:', err.message);
        res.status(500).json({ error: "Erreur serveur lors de la connexion." });
    }
});

// Route 3 : Sauvegarde de simulation (Protégée)
app.post('/api/simulations', authentifierToken, async (req, res) => {
    const { isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh } = req.body;

    if (!isotope || isNaN(activite_mbq) || isNaN(distance_m) || isNaN(dose_msvh)) {
        return res.status(400).json({ error: "Données de simulation invalides." });
    }

    try {
        const newSimu = await db.query(
            `INSERT INTO simulations (user_id, isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [req.user.id, isotope, activite_mbq, distance_m, materiau_blindage, epaisseur_cm, dose_msvh]
        );
        res.status(201).json({ message: "Simulation enregistrée", simulation: newSimu.rows[0] });
    } catch (err) {
        console.error('Erreur simulation:', err.message);
        res.status(500).json({ error: "Erreur lors de l'enregistrement." });
    }
});

// Route 4 : Historique des simulations (Protégée)
app.get('/api/simulations', authentifierToken, async (req, res) => {
    try {
        const result = await db.query(
            'SELECT * FROM simulations WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [req.user.id]
        );
        res.json({ simulations: result.rows });
    } catch (err) {
        console.error('Erreur historique:', err.message);
        res.status(500).json({ error: "Erreur lors de la récupération de l'historique." });
    }
});

app.listen(PORT, () => console.log(`Serveur actif sur le port ${PORT}`));
