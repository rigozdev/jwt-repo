import * as dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import pkg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cors from 'cors'
import morgan from 'morgan';
const { Pool } = pkg;

import { verifyCredentialsLogin, verifyCredentialsRegister, verifyToken, requestReport } from './middlewares/middlewares.js';

const app = express();

app.use(express.json());//! 👀para los POST

app.use(cors());//! -> middleware CORS

app.use(cors());

app.use(morgan("dev"));



const pool = new Pool({
    allowExitOnIdle: true
});


app.post('/usuarios', requestReport, verifyCredentialsRegister, async (req, res) => {

    try {
        const { email, password, rol, lenguage } = req.body;
        const hashPw = await bcrypt.hash(password, 10);
        const sentencia = "INSERT INTO usuarios (email, password, rol, lenguage) values($1, $2, $3, $4) RETURNING *";
        const { rows } = await pool.query(sentencia, [email, hashPw, rol, lenguage]);
        const result = rows[0].email;
        return res.status(201).json({ ok: true, result });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: error.message });
    }
});


app.post('/login', requestReport, verifyCredentialsLogin, async (req, res) => {

    try {
        const { email, password } = req.body;
        const sentencia = "SELECT * FROM usuarios WHERE email = $1"
        const { rows: [userDB], rowCount } = await pool.query(sentencia, [email]);
        if (!rowCount) {
            throw ({ message: "No existe el usuario" });
        };
        const verifyPassword = await bcrypt.compare(password, userDB.password);
        if (!verifyPassword) {
            throw ({ message: "Contraseña incorrecta" });
        };
        if (rowCount) {
            const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1m' });
            return res.json({ token })
        };
    } catch (error) {
        console.error(error)
        return res.status(500).json({ message: error.message });
    }

});


app.get('/usuarios', requestReport, verifyToken, async (req, res) => {
    try {
        const sentencia = "SELECT*FROM usuarios WHERE email = $1"
        const { rows } = await pool.query(sentencia, [req.email]);
        const result = rows;
        // const { rows } = await pool.query("SELECT * FROM usuarios");
        return res.json({ ok: true, result });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
    }
    res.json({ ok: true, result: 'todo ok en puerto' });
});


const PORT = process.env.PORT || 3010;
app.listen(PORT, () => {
    console.log('Escuchando peticiones en http://localhost:' + PORT);
})