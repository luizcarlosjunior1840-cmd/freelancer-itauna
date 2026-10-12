const express = require("express");
const path = require("path");
const cors = require("cors");
require("dotenv").config();

const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/teste-neon", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");

    res.json({
      conectado: true,
      banco: "Neon",
      horario: result.rows[0].now
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      conectado: false,
      erro: "Não foi possível conectar ao Neon."
    });
  }
});

const bcrypt = require("bcryptjs");

// Cadastro de usuários
app.post("/cadastro", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({
        erro: "Informe nome, email, senha e tipo de usuário."
      });
    }

    const tiposPermitidos = [
      "client",
      "professional",
      "company"
    ];

    if (!tiposPermitidos.includes(role)) {
      return res.status(400).json({
        erro: "Tipo de usuário inválido."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        erro: "A senha deve ter pelo menos 8 caracteres."
      });
    }

    const emailNormalizado = email.trim().toLowerCase();

    const senhaHash = await bcrypt.hash(password, 12);

    const resultado = await pool.query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role`,
      [name.trim(), emailNormalizado, senhaHash, role]
    );

    return res.status(201).json({
      mensagem: "Cadastro realizado com sucesso.",
      usuario: resultado.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        erro: "Este email já está cadastrado."
      });
    }

    console.error("Erro no cadastro:", error);

    return res.status(500).json({
      erro: "Não foi possível realizar o cadastro."
    });
  }
});

// Login de usuários
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        erro: "Informe email e senha."
      });
    }

    const emailNormalizado = email.trim().toLowerCase();

    const resultado = await pool.query(
      `SELECT id, name, email, password_hash, role
       FROM users
       WHERE email = $1`,
      [emailNormalizado]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({
        erro: "Email ou senha inválidos."
      });
    }

    const usuario = resultado.rows[0];

    const senhaCorreta = await bcrypt.compare(
      password,
      usuario.password_hash
    );

    if (!senhaCorreta) {
      return res.status(401).json({
        erro: "Email ou senha inválidos."
      });
    }

    return res.json({
      mensagem: "Login realizado com sucesso.",
      usuario: {
        id: usuario.id,
        name: usuario.name,
        email: usuario.email,
        role: usuario.role
      }
    });
  } catch (error) {
    console.error("Erro no login:", error);

    return res.status(500).json({
      erro: "Não foi possível realizar o login."
    });
  }
});
  

app.get("/servicos", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT
        id,
        professional_id,
        category_id,
        title,
        description,
        price,
        city,
        state,
        status,
        created_at
       FROM services
       WHERE status = 'active'
       ORDER BY created_at DESC
       LIMIT 100`
    );

    return res.json({
      sucesso: true,
      total: resultado.rows.length,
      servicos: resultado.rows
    });
  } catch (error) {
    console.error("Erro ao consultar serviços:", error);

    return res.status(500).json({
      erro: "Não foi possível consultar os serviços."
    });
  }
});


app.get("/perfil-profissional", async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT
        u.id AS user_id,
        u.name,
        u.role,
        pp.id AS perfil_id,
        pp.profession,
        pp.description,
        pp.experience,
        pp.hourly_rate,
        pp.availability,
        pp.address,
        pp.rating,
        pp.total_reviews
       FROM users AS u
       JOIN professional_profiles AS pp
         ON pp.user_id = u.id
       WHERE u.name = $1
       LIMIT 1`,
      ["luizcarlosjunior"]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        sucesso: false,
        erro: "Perfil profissional não encontrado."
      });
    }

    return res.json({
      sucesso: true,
      perfil: resultado.rows[0]
    });
  } catch (error) {
    console.error("Erro ao consultar perfil profissional:", error);
    return res.status(500).json({
      sucesso: false,
      erro: "Não foi possível consultar o perfil profissional."
    });
  }
});

    const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// Backend Freelancer Itaúna
