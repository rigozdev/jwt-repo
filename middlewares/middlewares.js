import { config } from "dotenv";
config();
import jwt from 'jsonwebtoken';


export const verifyCredentialsRegister = async (req, res, next) => {
    const { email, password, rol, lenguage } = req.body;
    try {
        if (!email || !password || !rol || !lenguage) {
            throw ({ message: "Debe ingresar todos los datos" });
        }
        if (email.length < 1 || password.length < 1 || rol.length < 1 || lenguage.length < 1) {
            throw ({ message: "Debe escribir todos los datos" });
        }
        next();
    } catch (error) {
        console.error(error)
        return res.status(500).json({ message: error.message });
    }
}

export const verifyCredentialsLogin = async (req, res, next) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            throw ({ message: "Debe ingresar todos los datos" });
        }
        if (email.length < 1 || password.length < 1) {
            throw ({ message: "Debe escribir todos los datos" });
        }
        next();
    } catch (error) {
        console.error(error)
        return res.status(500).json({ message: error.message });
    }
}

export const verifyToken = (req, res, next) => {
    try {
        const bearerHeader = req.headers.authorization;
        if (!bearerHeader) {
            throw ({ message: "Se necesita token con formato bearer" });
        }
        const token = bearerHeader.split(' ')[1];
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        // console.log(payload);
        req.email = payload.email;
        next();
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: error.message });
    }
}

export const requestReport = async (req, res, next) => {
    if (req.query) {
        const url = req.url
        console.log(`Hoy ${new Date()}, se ha recibido una consulta en la ruta ${url}`);
        next();
    } else {
        return res.status(400).json({ ok: false, message: 'request denegada por problemas en la query' });
    }
}