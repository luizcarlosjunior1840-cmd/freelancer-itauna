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
  `INSERT INTO users
   (name, email, password_hash, role, approval_status, is_active)
   VALUES ($1, $2, $3, $4, 'pending', false)
   RETURNING id, name, email, role, approval_status, is_active`,
  [name.trim(), emailNormalizado, senhaHash, role]
);

return res.status(201).json({
  mensagem: "Cadastro recebido. Aguarde a aprovação do administrador.",
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

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        erro: "Informe email e senha."
      });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        erro: "Serviço temporariamente indisponível."
      });
    }

    const resultado = await pool.query(
      `SELECT id, name, email, password_hash, role,
              approval_status, is_active
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email.trim().toLowerCase()]
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

    if (
      usuario.is_active !== true ||
      (
        usuario.role !== "admin" &&
        usuario.approval_status !== "approved"
      )
    ) {
      return res.status(403).json({
        erro: usuario.approval_status === "rejected"
          ? "Seu cadastro não foi aprovado."
          : "Seu cadastro aguarda aprovação do administrador."
      });
    }

    const token = jwt.sign(
      { id: usuario.id, role: usuario.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      mensagem: "Login realizado com sucesso.",
      usuario: {
        id: usuario.id,
        name: usuario.name,
        email: usuario.email,
        role: usuario.role,
        approval_status: usuario.approval_status
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



app.get(
  "/perfil-profissional",
  autenticarToken,
  async (req, res) => {
    try {
      // Busca o usuário autenticado no banco para validar
      // a situação atual da conta.
      const usuarioResult = await pool.query(
        `SELECT id, name, role, approval_status, is_active
         FROM users
         WHERE id = $1
         LIMIT 1`,
        [req.usuario.id]
      );

      if (usuarioResult.rows.length === 0) {
        return res.status(401).json({
          sucesso: false,
          erro: "Usuário não encontrado."
        });
      }

      const usuario = usuarioResult.rows[0];

      if (
        usuario.role !== "professional" ||
        usuario.approval_status !== "approved" ||
        usuario.is_active !== true
      ) {
        return res.status(403).json({
          sucesso: false,
          erro: "Acesso permitido somente a profissionais aprovados e ativos."
        });
      }

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
         LEFT JOIN professional_profiles AS pp
           ON pp.user_id = u.id
         WHERE u.id = $1
         LIMIT 1`,
        [usuario.id]
      );

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
  }
);
      

function autenticarToken(req, res, next) {
  const cabecalho = req.headers.authorization;

  if (!cabecalho || !cabecalho.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token de acesso não informado."
    });
  }

  const token = cabecalho.slice(7);

  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);

    return next();
  } catch (error) {
    return res.status(401).json({
      erro: "Token inválido ou expirado."
    });
  }
}

function somenteAdmin(req, res, next) {
  if (!req.usuario || req.usuario.role !== "admin") {
    return res.status(403).json({
      erro: "Acesso permitido somente ao administrador."
    });
  }

  return next();
}

// Listar cadastros pendentes
app.get(
  "/admin/usuarios-pendentes",
  autenticarToken,
  somenteAdmin,
  async (req, res) => {
    try {
      const resultado = await pool.query(
        `SELECT id, name, email, role, approval_status, is_active,
                created_at
         FROM users
         WHERE approval_status = 'pending'
           AND role <> 'admin'
         ORDER BY created_at ASC`
      );

      return res.json({
        total: resultado.rows.length,
        usuarios: resultado.rows
      });
    } catch (error) {
      console.error("Erro ao listar pendentes:", error);

      return res.status(500).json({
        erro: "Não foi possível listar os cadastros."
      });
    }
  }
);

// Aprovar ou rejeitar um cadastro
app.patch(
  "/admin/usuarios/:id/aprovacao",
  autenticarToken,
  somenteAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;
      const id = req.params.id;

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          erro: "Status deve ser approved ou rejected."
        });
      }

      const resultado = await pool.query(
        `UPDATE users
         SET approval_status = $1,
             is_active = $2,
             updated_at = NOW()
         WHERE id = $3
           AND role <> 'admin'
           AND approval_status = 'pending'
         RETURNING id, name, email, role,
                   approval_status, is_active`,
        [status, status === "approved", id]
      );

      if (resultado.rows.length === 0) {
        return res.status(404).json({
          erro: "Cadastro pendente não encontrado."
        });
      }

      return res.json({
        mensagem: status === "approved"
          ? "Cadastro aprovado com sucesso."
          : "Cadastro rejeitado.",
        usuario: resultado.rows[0]
      });
    } catch (error) {
      console.error("Erro ao atualizar aprovação:", error);

      return res.status(500).json({
        erro: "Não foi possível atualizar o cadastro."
      });
    }
  }
);
        
/* Cadastro inicial e protegido do administrador */
app.get("/configurar-admin", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta charset="UTF-8">
    <title>Criar administrador</title>
    <body style="font-family:Arial;max-width:420px;margin:30px auto;padding:16px">
      <h2>Freelancer Itaúna — Criar ADM</h2>
      <form id="form">
        <p>Chave de configuração (NEW_SECRET)</p>
        <input id="chave" type="password" required style="width:100%;padding:10px">
        <p>Nome</p>
        <input id="nome" required style="width:100%;padding:10px">
        <p>E-mail do administrador</p>
        <input id="email" type="email" required style="width:100%;padding:10px">
        <p>Senha do administrador (mínimo 8 caracteres)</p>
        <input id="senha" type="password" minlength="8" required style="width:100%;padding:10px">
        <p><button style="padding:12px">Criar administrador</button></p>
      </form>
      <pre id="resultado"></pre>
      <script>
        document.getElementById("form").onsubmit = async function(e) {
          e.preventDefault();
          const r = await fetch("/admin/bootstrap", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-bootstrap-secret": document.getElementById("chave").value
            },
            body: JSON.stringify({
              name: document.getElementById("nome").value,
              email: document.getElementById("email").value,
              password: document.getElementById("senha").value
            })
          });
          document.getElementById("resultado").textContent =
            await r.text();
        };
      </script>
    </body>
    </html>
  `);
});

app.post("/admin/bootstrap", async (req, res) => {
  try {
    if (!process.env.NEW_SECRET ||
        req.get("x-bootstrap-secret") !== process.env.NEW_SECRET) {
      return res.status(403).json({ erro: "Chave inválida." });
    }

    const existentes = await pool.query(
      "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    );
    if (existentes.rows.length > 0) {
      return res.status(409).json({
        erro: "Já existe um administrador. Cadastro inicial bloqueado."
      });
    }

    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({
        erro: "Informe nome, e-mail e senha com pelo menos 8 caracteres."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const resultado = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, is_active)
       VALUES ($1, $2, $3, 'admin', true)
       RETURNING id, name, email, role`,
      [name.trim(), email.trim().toLowerCase(), hash]
    );

    return res.status(201).json({
      mensagem: "Administrador criado com sucesso.",
      usuario: resultado.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ erro: "Este e-mail já está cadastrado." });
    }
    console.error("Erro ao criar administrador:", error);
    return res.status(500).json({
      erro: "Não foi possível criar o administrador."
    });
  }
});
    
/* Recuperação temporária da senha do administrador */
app.post("/admin/redefinir-senha", async (req, res) => {
  try {
    if (
      !process.env.NEW_SECRET ||
      req.get("x-bootstrap-secret") !== process.env.NEW_SECRET
    ) {
      return res.status(403).json({ erro: "Chave inválida." });
    }

    const { email, password } = req.body;

    if (!email || !password || password.length < 8) {
      return res.status(400).json({
        erro: "Informe o e-mail e uma senha com pelo menos 8 caracteres."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const resultado = await pool.query(
      `UPDATE users
       SET password_hash = $1
       WHERE email = $2 AND role = 'admin'
       RETURNING id, name, email, role`,
      [hash, email.trim().toLowerCase()]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Conta administradora não encontrada."
      });
    }

    return res.json({
      mensagem: "Senha do administrador redefinida com sucesso.",
      usuario: resultado.rows[0]
    });
  } catch (error) {
    console.error("Erro ao redefinir senha:", error);
    return res.status(500).json({
      erro: "Não foi possível redefinir a senha."
    });
  }
});

    const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// Backend Freelancer Itaúna
