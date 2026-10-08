const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.get("/", (req, res) => {
  res.json({
    status: "online",
    message: "Backend Freelancer Itaúna funcionando!"
  });
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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
