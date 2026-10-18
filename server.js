
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const NEW_SECRET = process.env.NEW_SECRET;

if (!DATABASE_URL) {
  console.error("ERRO: configure a variável DATABASE_URL.");
}

if (!JWT_SECRET) {
  console.error("ERRO: configure a variável JWT_SECRET.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !/localhost|127\.0\.0\.1/i.test(DATABASE_URL)
    ? { rejectUnauthorized: false }
    : false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

function erro(res, status, mensagem) {
  return res.status(status).json({ sucesso: false, mensagem });
}

function texto(valor) {
  return typeof valor === "string" ? valor.trim() : "";
}

function emailValido(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function criarToken(usuario) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET não configurado.");
  }

  return jwt.sign(
    { id: usuario.id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function autenticarToken(req, res, next) {
  const cabecalho = req.headers.authorization || "";
  const partes = cabecalho.split(" ");

  if (partes.length !== 2 || partes[0] !== "Bearer") {
    return erro(res, 401, "Token não informado.");
  }

  if (!JWT_SECRET) {
    return erro(res, 500, "JWT_SECRET não configurado.");
  }

  try {
    req.token = jwt.verify(partes[1], JWT_SECRET);
    next();
  } catch {
    return erro(res, 401, "Token inválido ou expirado.");
  }
}

async function buscarUsuarioAutenticado(req, res, next) {
  try {
    const resultado = await pool.query(
      `SELECT id, name, email, role, approval_status, is_active
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.token.id]
    );

    if (resultado.rows.length === 0) {
      return erro(res, 401, "Usuário não encontrado.");
    }

    const usuario = resultado.rows[0];

    if (usuario.is_active === false) {
      return erro(res, 403, "Esta conta está desativada.");
    }

    if (
      usuario.role !== "admin" &&
      usuario.approval_status !== "approved"
    ) {
      return erro(res, 403, "Sua conta ainda não foi aprovada.");
    }

    req.usuario = usuario;
    next();
  } catch (e) {
    next(e);
  }
}

function somenteAdmin(req, res, next) {
  if (!req.usuario || req.usuario.role !== "admin") {
    return erro(res, 403, "Acesso permitido somente ao administrador.");
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    sucesso: true,
    mensagem: "API Freelancer Itaúna funcionando.",
  });
});

app.get("/saude", (req, res) => {
  res.json({ sucesso: true, status: "online" });
});

app.get("/teste-neon", async (req, res, next) => {
  try {
    const resultado = await pool.query(
      "SELECT NOW() AS horario"
    );

    res.json({
      sucesso: true,
      mensagem: "Conexão com Neon funcionando.",
      horario: resultado.rows[0].horario,
    });
  } catch (e) {
    next(e);
  }
});

// CADASTRO
app.post("/cadastro", async (req, res, next) => {
  try {
    const nome = texto(req.body.name || req.body.nome);
    const email = texto(req.body.email).toLowerCase();
    const senha = req.body.password || req.body.senha;
    const papel = texto(req.body.role || req.body.tipo || "client");

    const papeisPermitidos = ["client", "professional", "company"];

    if (nome.length < 2) {
      return erro(res, 400, "Informe seu nome completo.");
    }

    if (!emailValido(email)) {
      return erro(res, 400, "Informe um e-mail válido.");
    }

    if (typeof senha !== "string" || senha.length < 8) {
      return erro(res, 400, "A senha deve ter pelo menos 8 caracteres.");
    }

    if (!papeisPermitidos.includes(papel)) {
      return erro(res, 400, "Tipo de conta inválido.");
    }

    const existente = await pool.query(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (existente.rows.length > 0) {
      return erro(res, 409, "Este e-mail já está cadastrado.");
    }

    const senhaHash = await bcrypt.hash(senha, 12);

    const resultado = await pool.query(
      `INSERT INTO users
       (name, email, password_hash, role, approval_status, is_active)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, role, approval_status, is_active, created_at`,
      [nome, email, senhaHash, papel, "pending", true]
    );

    const usuario = resultado.rows[0];

    res.status(201).json({
      sucesso: true,
      mensagem: "Cadastro realizado. Aguarde a aprovação da conta.",
      usuario,
    });
  } catch (e) {
    if (e.code === "23505") {
      return erro(res, 409, "Este e-mail já está cadastrado.");
    }
    next(e);
  }
});

// LOGIN
app.post("/login", async (req, res, next) => {
  try {
    const email = texto(req.body.email).toLowerCase();
    const senha = req.body.password || req.body.senha;

    if (!emailValido(email) || typeof senha !== "string") {
      return erro(res, 400, "Informe o e-mail e a senha.");
    }

    const resultado = await pool.query(
      `SELECT id, name, email, password_hash, role,
              approval_status, is_active
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    if (resultado.rows.length === 0) {
      return erro(res, 401, "E-mail ou senha incorretos.");
    }

    const usuario = resultado.rows[0];
    const senhaCorreta = await bcrypt.compare(
      senha,
      usuario.password_hash
    );

    if (!senhaCorreta) {
      return erro(res, 401, "E-mail ou senha incorretos.");
    }

    if (usuario.is_active === false) {
      return erro(res, 403, "Sua conta está desativada.");
    }

    if (
      usuario.role !== "admin" &&
      usuario.approval_status !== "approved"
    ) {
      return res.status(403).json({
        sucesso: false,
        mensagem: "Sua conta ainda não foi aprovada.",
        status: usuario.approval_status,
      });
    }

    const token = criarToken(usuario);

    res.json({
      sucesso: true,
      mensagem: "Login realizado com sucesso.",
      token,
      usuario: {
        id: usuario.id,
        name: usuario.name,
        email: usuario.email,
        role: usuario.role,
        approval_status: usuario.approval_status,
      },
    });
  } catch (e) {
    next(e);
  }
});

// LISTAR SERVIÇOS
app.get("/servicos", async (req, res, next) => {
  try {
    const cidade = texto(req.query.city || req.query.cidade);
    const categoriaId = texto(req.query.category_id);
    const valores = [];
    const filtros = ["s.status = 'active'"];

    if (cidade) {
      valores.push(`%${cidade}%`);
      filtros.push(
        `LOWER(s.city) LIKE LOWER($${valores.length})`
      );
    }

    if (categoriaId) {
      const id = Number(categoriaId);

      if (!Number.isInteger(id) || id <= 0) {
        return erro(res, 400, "Categoria inválida.");
      }

      valores.push(id);
      filtros.push(`s.category_id = $${valores.length}`);
    }

    const resultado = await pool.query(
      `SELECT s.id, s.professional_id, s.category_id,
              s.title, s.description, s.price, s.city, s.state,
              s.status, s.created_at,
              u.name AS professional_name
       FROM services s
       JOIN users u ON u.id = s.professional_id
       WHERE ${filtros.join(" AND ")}
         AND u.is_active = TRUE
         AND u.approval_status = 'approved'
       ORDER BY s.created_at DESC
       LIMIT 100`,
      valores
    );

    res.json({
      sucesso: true,
      total: resultado.rows.length,
      servicos: resultado.rows,
    });
  } catch (e) {
    next(e);
  }
});

// CADASTRAR UM SERVIÇO
app.post(
  "/servicos",
  autenticarToken,
  buscarUsuarioAutenticado,
  async (req, res, next) => {
    try {
      if (
        !["professional", "company", "admin"].includes(req.usuario.role)
      ) {
        return erro(
          res,
          403,
          "Somente profissionais ou empresas podem cadastrar serviços."
        );
      }

      const titulo = texto(req.body.title || req.body.titulo);
      const descricao = texto(
        req.body.description || req.body.descricao
      );
      const cidade = texto(req.body.city || req.body.cidade);
      const estado = texto(req.body.state || req.body.estado);
      const categoriaId = Number(
        req.body.category_id || req.body.categoria_id
      );
      const preco = Number(req.body.price || req.body.preco);

      if (titulo.length < 3) {
        return erro(res, 400, "Informe o título do serviço.");
      }

      if (!descricao) {
        return erro(res, 400, "Informe a descrição do serviço.");
      }

      if (!cidade || !estado) {
        return erro(res, 400, "Informe cidade e estado.");
      }

      if (!Number.isInteger(categoriaId) || categoriaId <= 0) {
        return erro(res, 400, "Informe uma categoria válida.");
      }

      if (!Number.isFinite(preco) || preco < 0) {
        return erro(res, 400, "Informe um preço válido.");
      }

      const resultado = await pool.query(
        `INSERT INTO services
         (professional_id, category_id, title, description,
          price, city, state, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          req.usuario.id,
          categoriaId,
          titulo,
          descricao,
          preco,
          cidade,
          estado,
          "active",
        ]
      );

      res.status(201).json({
        sucesso: true,
        mensagem: "Serviço cadastrado com sucesso.",
        servico: resultado.rows[0],
      });
    } catch (e) {
      next(e);
    }
  }
);

// PERFIL PROFISSIONAL
app.get(
  "/perfil-profissional/:id?",
  autenticarToken,
  buscarUsuarioAutenticado,
  async (req, res, next) => {
    try {
      const idSolicitado = req.params.id
        ? Number(req.params.id)
        : Number(req.usuario.id);

      if (!Number.isInteger(idSolicitado) || idSolicitado <= 0) {
        return erro(res, 400, "ID de usuário inválido.");
      }

      if (
        idSolicitado !== Number(req.usuario.id) &&
        req.usuario.role !== "admin"
      ) {
        return erro(
          res,
          403,
          "Você só pode consultar seu próprio perfil."
        );
      }

      const resultado = await pool.query(
        `SELECT user_id, profession, description, experience,
                hourly_rate, availability, address, rating, total_reviews
         FROM professional_profiles
         WHERE user_id = $1
         LIMIT 1`,
        [idSolicitado]
      );

      if (resultado.rows.length === 0) {
        return res.json({
          sucesso: true,
          mensagem: "Perfil profissional ainda não cadastrado.",
          perfil: null,
        });
      }

      res.json({
        sucesso: true,
        perfil: resultado.rows[0],
      });
    } catch (e) {
      next(e);
    }
  }
);

app.put(
  "/perfil-profissional",
  autenticarToken,
  buscarUsuarioAutenticado,
  async (req, res, next) => {
    try {
      if (
        !["professional", "company", "admin"].includes(req.usuario.role)
      ) {
        return erro(
          res,
          403,
          "Esta conta não pode editar perfil profissional."
        );
      }

      const profissao = texto(
        req.body.profession || req.body.profissao
      );
      const descricao = texto(
        req.body.description || req.body.descricao
      );
      const experiencia = texto(
        req.body.experience || req.body.experiencia
      );
      const disponibilidade = texto(req.body.availability);
      const endereco = texto(req.body.address);
      const valorHora = req.body.hourly_rate == null
        ? null
        : Number(req.body.hourly_rate);

      if (!profissao) {
        return erro(res, 400, "Informe sua profissão.");
      }

      if (
        valorHora !== null &&
        (!Number.isFinite(valorHora) || valorHora < 0)
      ) {
        return erro(res, 400, "Valor por hora inválido.");
      }

      const resultado = await pool.query(
        `INSERT INTO professional_profiles
         (user_id, profession, description, experience,
          hourly_rate, availability, address)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (user_id)
         DO UPDATE SET
           profession = EXCLUDED.profession,
           description = EXCLUDED.description,
           experience = EXCLUDED.experience,
           hourly_rate = EXCLUDED.hourly_rate,
           availability = EXCLUDED.availability,
           address = EXCLUDED.address
         RETURNING *`,
        [
          req.usuario.id,
          profissao,
          descricao,
          experiencia,
          valorHora,
          disponibilidade,
          endereco,
        ]
      );

      res.json({
        sucesso: true,
        mensagem: "Perfil profissional atualizado.",
        perfil: resultado.rows[0],
      });
    } catch (e) {
      next(e);
    }
  }
);

// ADMIN: LISTAR USUÁRIOS PENDENTES
app.get(
  "/admin/usuarios-pendentes",
  autenticarToken,
  buscarUsuarioAutenticado,
  somenteAdmin,
  async (req, res, next) => {
    try {
      const resultado = await pool.query(
        `SELECT id, name, email, role, approval_status,
                is_active, created_at
         FROM users
         WHERE approval_status = 'pending'
         ORDER BY created_at ASC`
      );

      res.json({
        sucesso: true,
        total: resultado.rows.length,
        usuarios: resultado.rows,
      });
    } catch (e) {
      next(e);
    }
  }
);

// ADMIN: APROVAR OU REJEITAR USUÁRIO
app.patch(
  "/admin/usuarios/:id/aprovacao",
  autenticarToken,
  buscarUsuarioAutenticado,
  somenteAdmin,
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const status = texto(
        req.body.approval_status || req.body.status
      );

      if (!Number.isInteger(id) || id <= 0) {
        return erro(res, 400, "ID de usuário inválido.");
      }

      if (!["approved", "rejected", "pending"].includes(status)) {
        return erro(
          res,
          400,
          "Status deve ser approved, rejected ou pending."
        );
      }

      const resultado = await pool.query(
        `UPDATE users
         SET approval_status = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, name, email, role, approval_status, is_active`,
        [status, id]
      );

      if (resultado.rows.length === 0) {
        return erro(res, 404, "Usuário não encontrado.");
      }

      res.json({
        sucesso: true,
        mensagem: "Status do usuário atualizado.",
        usuario: resultado.rows[0],
      });
    } catch (e) {
      next(e);
    }
  }
);

// CONFIGURAR ADMINISTRADOR INICIAL
app.post("/configurar-admin", async (req, res, next) => {
  try {
    if (!NEW_SECRET) {
      return erro(
        res,
        503,
        "Configure a variável NEW_SECRET no Render antes de continuar."
      );
    }

    const chave = texto(
      req.headers["x-setup-secret"] || req.body.setup_secret
    );

    if (chave !== NEW_SECRET) {
      return erro(res, 403, "Chave de configuração inválida.");
    }

    const nome = texto(req.body.name || req.body.nome);
    const email = texto(req.body.email).toLowerCase();
    const senha = req.body.password || req.body.senha;

    if (nome.length < 2 || !emailValido(email)) {
      return erro(res, 400, "Informe nome e e-mail válidos.");
    }

    if (typeof senha !== "string" || senha.length < 8) {
      return erro(res, 400, "A senha deve ter pelo menos 8 caracteres.");
    }

    const conexao = await pool.connect();

    try {
      await conexao.query("BEGIN");
      await conexao.query(
        "SELECT pg_advisory_xact_lock($1)",
        [728491]
      );

      const jaExiste = await conexao.query(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
      );

      if (jaExiste.rows.length > 0) {
        await conexao.query("ROLLBACK");
        return erro(
          res,
          409,
          "Já existe um administrador. Use a recuperação de senha."
        );
      }

      const senhaHash = await bcrypt.hash(senha, 12);

      const resultado = await conexao.query(
        `INSERT INTO users
         (name, email, password_hash, role, approval_status, is_active)
         VALUES ($1, $2, $3, 'admin', 'approved', TRUE)
         RETURNING id, name, email, role, approval_status, is_active`,
        [nome, email, senhaHash]
      );

      await conexao.query("COMMIT");

      res.status(201).json({
        sucesso: true,
        mensagem: "Administrador inicial criado.",
        usuario: resultado.rows[0],
      });
    } catch (e) {
      await conexao.query("ROLLBACK");
      throw e;
    } finally {
      conexao.release();
    }
  } catch (e) {
    if (e.code === "23505") {
      return erro(res, 409, "Este e-mail já está cadastrado.");
    }
    next(e);
  }
});

// ADMIN: CRIAR OU RECUPERAR ACESSO DE ADMINISTRADOR
app.post("/admin/bootstrap", async (req, res, next) => {
  try {
    if (!NEW_SECRET) {
      return erro(res, 503, "NEW_SECRET não está configurado.");
    }

    const chave = texto(
      req.headers["x-setup-secret"] || req.body.setup_secret
    );

    if (chave !== NEW_SECRET) {
      return erro(res, 403, "Chave de configuração inválida.");
    }

    const email = texto(req.body.email).toLowerCase();
    const senha = req.body.password || req.body.senha;

    if (!emailValido(email)) {
      return erro(res, 400, "Informe um e-mail válido.");
    }

    if (typeof senha !== "string" || senha.length < 8) {
      return erro(res, 400, "A senha deve ter pelo menos 8 caracteres.");
    }

    const senhaHash = await bcrypt.hash(senha, 12);
    const resultado = await pool.query(
      `UPDATE users
       SET password_hash = $1,
           role = 'admin',
           approval_status = 'approved',
           is_active = TRUE,
           updated_at = NOW()
       WHERE email = $2
       RETURNING id, name, email, role, approval_status, is_active`,
      [senhaHash, email]
    );

    if (resultado.rows.length === 0) {
      return erro(
        res,
        404,
        "E-mail não encontrado. Use /configurar-admin para criar o primeiro administrador."
      );
    }

    res.json({
      sucesso: true,
      mensagem: "Acesso de administrador atualizado.",
      usuario: resultado.rows[0],
    });
  } catch (e) {
    next(e);
  }
});

// ADMIN: REDEFINIR SENHA DE USUÁRIO
app.post(
  "/admin/redefinir-senha",
  autenticarToken,
  buscarUsuarioAutenticado,
  somenteAdmin,
  async (req, res, next) => {
    try {
      const id = Number(req.body.id);
      const senha = req.body.password || req.body.senha;

      if (!Number.isInteger(id) || id <= 0) {
        return erro(res, 400, "Informe um ID de usuário válido.");
      }

      if (typeof senha !== "string" || senha.length < 8) {
        return erro(res, 400, "A nova senha deve ter pelo menos 8 caracteres.");
      }

      const senhaHash = await bcrypt.hash(senha, 12);

      const resultado = await pool.query(
        `UPDATE users
         SET password_hash = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, name, email, role`,
        [senhaHash, id]
      );

      if (resultado.rows.length === 0) {
        return erro(res, 404, "Usuário não encontrado.");
      }

      res.json({
        sucesso: true,
        mensagem: "Senha redefinida com sucesso.",
        usuario: resultado.rows[0],
      });
    } catch (e) {
      next(e);
    }
  }
);

// ROTA NÃO ENCONTRADA
app.use((req, res) => {
  res.status(404).json({
    sucesso: false,
    mensagem: "Rota não encontrada.",
    caminho: req.path,
  });
});

// TRATAMENTO DE ERROS
app.use((err, req, res, next) => {
  console.error("Erro na API:", err.message);

  if (err.code === "23503") {
    return erro(
      res,
      400,
      "Referência inválida: confira a categoria ou o usuário informado."
    );
  }

  if (err.code === "42P01" || err.code === "42703") {
    return erro(
      res,
      500,
      "Tabela ou coluna não encontrada no banco. Precisamos conferir o esquema do Neon."
    );
  }

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    sucesso: false,
    mensagem: "Erro interno do servidor.",
  });
});

const servidor = app.listen(PORT, () => {
  console.log(`API Freelancer Itaúna iniciada na porta ${PORT}`);
});

servidor.on("error", (err) => {
  console.error("Erro ao iniciar servidor:", err.message);
});

async function encerrar() {
  console.log("Encerrando servidor...");
  servidor.close(async () => {
    try {
      await pool.end();
    } catch (e) {
      console.error("Erro ao fechar banco:", e.message);
    }
    process.exit(0);
  });
}

process.on("SIGTERM", encerrar);
process.on("SIGINT", encerrar);
