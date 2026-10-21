
"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const NEW_SECRET = process.env.NEW_SECRET;

if (!DATABASE_URL) {
  console.error("ERRO: variável DATABASE_URL não configurada.");
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERRO: configure JWT_SECRET com pelo menos 32 caracteres.");
}

if (!NEW_SECRET || NEW_SECRET.length < 24) {
  console.error("ERRO: configure NEW_SECRET com pelo menos 24 caracteres.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL
    ? { rejectUnauthorized: false }
    : undefined
});

app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: "1mb" }));

function txt(value) {
  return typeof value === "string" ? value.trim() : "";
}

function fail(res, status, mensagem) {
  return res.status(status).json({
    sucesso: false,
    mensagem
  });
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || "")
  );
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return fail(res, 401, "Faça login para continuar.");
  }

  if (!JWT_SECRET) {
    return fail(res, 500, "Autenticação não configurada.");
  }

  try {
    req.tokenPayload = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch (error) {
    return fail(res, 401, "Sessão inválida. Entre novamente.");
  }
}

async function currentUser(req, res, next) {
  try {
    const id = req.tokenPayload?.id;

    if (!validUUID(id)) {
      return fail(res, 401, "Token inválido.");
    }

    const result = await pool.query(
      `SELECT id, name, email, role, phone, city, state,
              approval_status, is_active
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [id]
    );

    if (!result.rowCount) {
      return fail(res, 401, "Usuário não encontrado.");
    }

    const user = result.rows[0];

    if (user.is_active !== true) {
      return fail(res, 403, "Sua conta está inativa.");
    }

    if (
      user.role !== "admin" &&
      user.approval_status !== "approved"
    ) {
      return fail(
        res,
        403,
        "Sua conta ainda aguarda aprovação do administrador."
      );
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return fail(res, 403, "Acesso permitido somente ao administrador.");
  }

  next();
}

function onlyRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return fail(res, 403, "Você não tem permissão para esta operação.");
    }

    next();
  };
}

function normalizarStatusUsuario(status) {
  if (status === "approved") return "approved";
  if (status === "rejected") return "rejected";
  return null;
}

function normalizarStatusVaga(status) {
  if (status === "approved" || status === "active") return "active";
  if (status === "rejected" || status === "inactive") return "inactive";
  return null;
}

function dataValida(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ""));
}

/* =====================================================
   INÍCIO E TESTES
===================================================== */


app.get("/", (req, res) => {
  res.sendFile(
    require("path").join(__dirname, "index.html")
  );
});


app.get("/saude", (req, res) => {
  res.json({
    sucesso: true,
    mensagem: "Servidor Freelancer Itaúna online."
  });
});

app.get("/teste-neon", async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT NOW() AS horario, current_database() AS banco"
    );

    res.json({
      sucesso: true,
      mensagem: "Conexão com Neon funcionando.",
      banco: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

/* =====================================================
   SESSÃO DO USUÁRIO
===================================================== */

app.get("/me", auth, currentUser, (req, res) => {
  res.json({
    sucesso: true,
    usuario: req.user
  });
});

/* =====================================================
   CADASTRO
===================================================== */

app.post("/cadastro", async (req, res, next) => {
  try {
    const name = txt(req.body.name || req.body.nome);
    const email = txt(req.body.email).toLowerCase();
    const password = String(req.body.password || req.body.senha || "");
    const phone = txt(req.body.phone || req.body.telefone);
    const city = txt(req.body.city || req.body.cidade) || "Itaúna";
    const state = (
      txt(req.body.state || req.body.estado) || "MG"
    ).toUpperCase();

    const role = txt(req.body.role || req.body.tipo);

    const roles = ["client", "professional", "company"];

    if (name.length < 3) {
      return fail(res, 400, "Informe seu nome completo.");
    }

    if (!validEmail(email)) {
      return fail(res, 400, "Informe um e-mail válido.");
    }

    if (password.length < 8) {
      return fail(res, 400, "A senha deve ter pelo menos 8 caracteres.");
    }

    if (!roles.includes(role)) {
      return fail(res, 400, "Selecione um tipo de conta válido.");
    }

    if (phone.length < 8) {
      return fail(res, 400, "Informe um telefone válido.");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
        (name, email, password_hash, role, phone, city, state,
         approval_status, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', FALSE)
       RETURNING id, name, email, role, approval_status`,
      [name, email, passwordHash, role, phone, city, state]
    );

    return res.status(201).json({
      sucesso: true,
      mensagem: "Cadastro recebido. Aguarde a aprovação do administrador.",
      usuario: result.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return fail(res, 409, "Este e-mail já está cadastrado.");
    }

    next(error);
  }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/login", async (req, res, next) => {
  try {
    const email = txt(req.body.email).toLowerCase();
    const password = String(req.body.password || req.body.senha || "");

    if (!validEmail(email) || !password) {
      return fail(res, 400, "Informe e-mail e senha.");
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role, phone,
              city, state, approval_status, is_active
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    if (!result.rowCount) {
      return fail(res, 401, "E-mail ou senha incorretos.");
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return fail(res, 401, "E-mail ou senha incorretos.");
    }

    if (user.is_active !== true) {
      return fail(
        res,
        403,
        "Sua conta está aguardando aprovação ou está inativa."
      );
    }

    if (
      user.role !== "admin" &&
      user.approval_status !== "approved"
    ) {
      return fail(
        res,
        403,
        "Sua conta ainda aguarda aprovação do administrador."
      );
    }

    if (!JWT_SECRET || JWT_SECRET.length < 32) {
      return fail(res, 500, "Autenticação não configurada corretamente.");
    }

    const token = jwt.sign(
      { id: user.id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    delete user.password_hash;

    return res.json({
      sucesso: true,
      mensagem: "Login realizado com sucesso.",
      token,
      usuario: user
    });
  } catch (error) {
    next(error);
  }
});

/* =====================================================
   CATEGORIAS
===================================================== */

app.get("/categorias", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, name, description
       FROM categories
       ORDER BY name ASC`
    );

    res.json({
      sucesso: true,
      categorias: result.rows
    });
  } catch (error) {
    next(error);
  }
});

/* =====================================================
   CONSULTA DE VAGAS

   Público: nome, data, horário e valor.
   Freelancer aprovado/admin: detalhes completos.
===================================================== */

app.get("/servicos", async (req, res, next) => {
  try {
    const city = txt(req.query.city || req.query.cidade);
    const category = txt(req.query.category_id);

    const values = [];
    const where = [
  "s.status = 'active'",
  "u.is_active = TRUE",
  "u.approval_status = 'approved'",
  "(s.expires_at IS NULL OR s.expires_at > NOW())"
];

    if (city) {
      values.push("%" + city + "%");
      where.push(
        `LOWER(s.city) LIKE LOWER($${values.length})`
      );
    }

    if (category) {
      if (!validUUID(category)) {
        return fail(res, 400, "Categoria inválida.");
      }

      values.push(category);
      where.push(`s.category_id = $${values.length}`);
    }

    let user = null;
    const authorization = req.headers.authorization;

    if (authorization) {
      if (!authorization.startsWith("Bearer ")) {
        return fail(res, 401, "Token inválido.");
      }

      if (!JWT_SECRET) {
        return fail(res, 500, "Autenticação não configurada.");
      }

      let payload;

      try {
        payload = jwt.verify(authorization.slice(7), JWT_SECRET);
      } catch (error) {
        return fail(res, 401, "Sessão inválida. Entre novamente.");
      }

      const userResult = await pool.query(
        `SELECT id, role, approval_status, is_active
         FROM users
         WHERE id = $1
         LIMIT 1`,
        [payload.id]
      );

      user = userResult.rows[0] || null;

      if (!user || user.is_active !== true) {
        return fail(res, 403, "Sua conta está inativa.");
      }

      if (
        user.role !== "admin" &&
        user.approval_status !== "approved"
      ) {
        return fail(res, 403, "Sua conta ainda não foi aprovada.");
      }
    }

    const fullDetails =
      user && ["client", "admin"].includes(user.role);

    const publicFields = `
      s.id,
      s.title,
      s.work_date,
      s.work_hours,
      s.price
    `;

    const completeFields = `
      s.id,
      s.professional_id,
      s.category_id,
      s.title,
      s.description,
      s.price,
      s.city,
      s.state,
      s.establishment_name,
      s.neighborhood,
      s.job_address,
      s.work_date,
      s.work_hours,
      s.vacancies_count,
      s.created_at,
      c.name AS category_name
    `;

    const result = await pool.query(
      `SELECT ${fullDetails ? completeFields : publicFields}
       FROM services s
       JOIN users u ON u.id = s.professional_id
       LEFT JOIN categories c ON c.id = s.category_id
       WHERE ${where.join(" AND ")}
       ORDER BY s.created_at DESC
       LIMIT 100`,
      values
    );

    res.json({
      sucesso: true,
      total: result.rowCount,
      servicos: result.rows
    });
  } catch (error) {
    next(error);
  }
});

/* =====================================================
   CADASTRO DE VAGAS
===================================================== */

app.post(
  "/servicos",
  auth,
  currentUser,
  onlyRoles("professional", "company", "admin"),
  async (req, res, next) => {
    try {
      const title = txt(req.body.title || req.body.titulo);
      const description = txt(req.body.description || req.body.descricao);
      const category = txt(req.body.category_id || req.body.categoria_id);

      const establishment = txt(
        req.body.establishment_name || req.body.estabelecimento
      );
      const neighborhood = txt(
        req.body.neighborhood || req.body.bairro
      );
      const address = txt(
        req.body.job_address || req.body.endereco
      );

      const city = txt(req.body.city || req.body.cidade) || "Itaúna";
      const state = (
        txt(req.body.state || req.body.estado) || "MG"
      ).toUpperCase();

      const workDate = txt(req.body.work_date || req.body.data_trabalho);
      const workHours = txt(req.body.work_hours || req.body.horario);

      const rawPrice = req.body.price ?? req.body.preco;
      const price = Number(rawPrice);

      const rawQuantity =
        req.body.vacancies_count ?? req.body.quantidade_vagas ?? 1;
      const quantity = Number(rawQuantity);

      if (title.length < 3) {
        return fail(res, 400, "Informe o nome da vaga.");
      }

      if (description.length < 5) {
        return fail(res, 400, "Descreva as tarefas da vaga.");
      }

      if (
        !establishment ||
        !neighborhood ||
        !address ||
        !city ||
        !state
      ) {
        return fail(
          res,
          400,
          "Preencha estabelecimento, bairro, endereço e cidade."
        );
      }

      if (!validUUID(category)) {
        return fail(res, 400, "Selecione uma categoria válida.");
      }

      if (!dataValida(workDate)) {
        return fail(res, 400, "Informe a data do trabalho.");
      }

      if (!workHours) {
        return fail(res, 400, "Informe o horário do trabalho.");
      }

      if (
        rawPrice === undefined ||
        rawPrice === "" ||
        !Number.isFinite(price) ||
        price < 0
      ) {
        return fail(res, 400, "Informe um valor válido para a vaga.");
      }

      if (
        !Number.isInteger(quantity) ||
        quantity < 1 ||
        quantity > 500
      ) {
        return fail(res, 400, "A quantidade de freelancers deve ser de 1 a 500.");
      }

      const result = await pool.query(
        `INSERT INTO services
          (professional_id, category_id, title, description, price,
           city, state, status, establishment_name, neighborhood,
           job_address, work_date, work_hours, vacancies_count)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, 'pending',
           $8, $9, $10, $11, $12, $13)
         RETURNING id, title, price, work_date, work_hours,
                   vacancies_count, status, created_at`,
        [
          req.user.id,
          category,
          title,
          description,
          price,
          city,
          state,
          establishment,
          neighborhood,
          address,
          workDate,
          workHours,
          quantity
        ]
      );

      res.status(201).json({
        sucesso: true,
        mensagem: "Vaga enviada para aprovação do administrador.",
        servico: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   ADMINISTRAÇÃO DE USUÁRIOS
===================================================== */

app.get(
  "/admin/usuarios-pendentes",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT id, name, email, role, phone, city, state,
                approval_status, is_active, created_at
         FROM users
         WHERE role <> 'admin'
           AND approval_status = 'pending'
         ORDER BY created_at ASC`
      );

      res.json({
        sucesso: true,
        usuarios: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   RESUMO DO PAINEL ADMINISTRATIVO
===================================================== */

app.get(
  "/admin/resumo",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT
          (SELECT COUNT(*)::int
           FROM users
           WHERE role <> 'admin') AS total_usuarios,

          (SELECT COUNT(*)::int
           FROM users
           WHERE role = 'client') AS total_freelancers,

          (SELECT COUNT(*)::int
           FROM users
           WHERE role = 'professional') AS total_contratantes,

          (SELECT COUNT(*)::int
           FROM users
           WHERE role = 'company') AS total_empresas,

          (SELECT COUNT(*)::int
           FROM services
           WHERE status = 'pending') AS vagas_pendentes,

          (SELECT COUNT(*)::int
           FROM hiring_requests
           WHERE status = 'pending') AS candidaturas_pendentes,

          (SELECT COUNT(*)::int
           FROM hiring_requests
           WHERE status = 'assigned') AS servicos_em_andamento,

          (SELECT COUNT(*)::int
           FROM hiring_requests
           WHERE status = 'completed') AS servicos_concluidos
      `);

      return res.json({
        sucesso: true,
        resumo: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/admin/usuarios",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT id, name, email, role, phone, city, state,
                approval_status, is_active, created_at
         FROM users
         WHERE role <> 'admin'
         ORDER BY created_at DESC
         LIMIT 500`
      );

      res.json({
        sucesso: true,
        usuarios: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/admin/usuarios/:id/aprovacao",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const status = normalizarStatusUsuario(
        txt(req.body.status || req.body.approval_status)
      );

      if (!validUUID(id)) {
        return fail(res, 400, "ID de usuário inválido.");
      }

      if (!status) {
        return fail(res, 400, "Use approved ou rejected.");
      }

      const result = await pool.query(
        `UPDATE users
         SET approval_status = $1,
             is_active = $2,
             updated_at = NOW()
         WHERE id = $3
           AND role <> 'admin'
         RETURNING id, name, email, role, approval_status, is_active`,
        [status, status === "approved", id]
      );

      if (!result.rowCount) {
        return fail(res, 404, "Usuário não encontrado.");
      }

      res.json({
        sucesso: true,
        mensagem: status === "approved"
          ? "Cadastro aprovado."
          : "Cadastro rejeitado.",
        usuario: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   ADMINISTRAÇÃO DE VAGAS
===================================================== */

app.get(
  "/admin/servicos-pendentes",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT s.id, s.professional_id, s.category_id,
                s.title, s.description, s.price, s.city, s.state,
                s.establishment_name, s.neighborhood, s.job_address,
                s.work_date, s.work_hours, s.vacancies_count,
                s.status, s.created_at,
                u.name AS professional_name,
                u.email AS professional_email,
                u.phone AS professional_phone,
                c.name AS category_name
         FROM services s
         JOIN users u ON u.id = s.professional_id
         LEFT JOIN categories c ON c.id = s.category_id
         WHERE s.status = 'pending'
         ORDER BY s.created_at ASC`
      );

      res.json({
        sucesso: true,
        servicos: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/admin/servicos/:id/aprovacao",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const status = normalizarStatusVaga(
        txt(req.body.status || req.body.approval_status)
      );

      if (!validUUID(id)) {
        return fail(res, 400, "ID de vaga inválido.");
      }

      if (!status) {
        return fail(res, 400, "Use approved ou rejected.");
      }

      const result = await pool.query(
        `UPDATE services
         SET status = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, title, status`,
        [status, id]
      );

      if (!result.rowCount) {
        return fail(res, 404, "Vaga não encontrada.");
      }

      res.json({
        sucesso: true,
        mensagem: status === "active"
          ? "Vaga aprovada e publicada."
          : "Vaga rejeitada e retirada da publicação.",
        servico: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   CANDIDATURAS ÀS VAGAS
===================================================== */

app.post(
  "/contratacoes",
  auth,
  currentUser,
  onlyRoles("client"),
  async (req, res, next) => {
    const serviceId = txt(req.body.service_id || req.body.servico_id);
    const details = txt(req.body.details || req.body.detalhes) ||
      "Tenho interesse nesta vaga.";

    if (!validUUID(serviceId)) {
      return fail(res, 400, "Vaga inválida.");
    }

    if (details.length < 5) {
      return fail(res, 400, "Informe seu interesse pela vaga.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const jobResult = await client.query(
        `SELECT id, vacancies_count
         FROM services
         WHERE id = $1 AND status = 'active'
         FOR UPDATE`,
        [serviceId]
      );

      if (!jobResult.rowCount) {
        await client.query("ROLLBACK");
        return fail(res, 404, "Esta vaga não está disponível.");
      }

      const existing = await client.query(
        `SELECT id
         FROM hiring_requests
         WHERE service_id = $1 AND client_id = $2
           AND status <> 'rejected'
         LIMIT 1`,
        [serviceId, req.user.id]
      );

      if (existing.rowCount) {
        await client.query("ROLLBACK");
        return fail(res, 409, "Você já se candidatou a esta vaga.");
      }

      const inserted = await client.query(
        `INSERT INTO hiring_requests
          (client_id, service_id, details, status)
         VALUES ($1, $2, $3, 'pending')
         RETURNING id, client_id, service_id, details, status, created_at`,
        [req.user.id, serviceId, details]
      );

      await client.query("COMMIT");

      res.status(201).json({
        sucesso: true,
        mensagem: "Candidatura enviada para análise do administrador.",
        contratacao: inserted.rows[0]
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}

      next(error);
    } finally {
      client.release();
    }
  }
);

/* =====================================================
   MINHAS CANDIDATURAS — FREELANCER
===================================================== */

app.get(
  "/minhas-contratacoes",
  auth,
  currentUser,
  onlyRoles("client"),
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT h.id, h.service_id, h.details, h.status,
                h.created_at, h.updated_at,
                s.title AS service_title,
                s.work_date, s.work_hours, s.price
         FROM hiring_requests h
         JOIN services s ON s.id = h.service_id
         WHERE h.client_id = $1
         ORDER BY h.created_at DESC`,
        [req.user.id]
      );

      res.json({
        sucesso: true,
        contratacoes: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   SOLICITAÇÕES — ADMINISTRADOR

   Dados privados dos candidatos ficam restritos a esta rota.
===================================================== */

app.get(
  "/configuracao/solicitacoes",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT
           h.id,
           h.client_id,
           h.service_id,
           h.details,
           h.status,
           h.assigned_professional_id,
           h.created_at,
           h.updated_at,
           s.title AS service_title,
           s.vacancies_count,
           s.work_date,
           s.work_hours,
           s.price,
           candidate.name AS freelancer_name,
           candidate.email AS freelancer_email,
           candidate.phone AS freelancer_phone,
           assigned.name AS assigned_freelancer_name
         FROM hiring_requests h
         JOIN services s ON s.id = h.service_id
         JOIN users candidate ON candidate.id = h.client_id
         LEFT JOIN users assigned
           ON assigned.id = h.assigned_professional_id
         ORDER BY
           CASE WHEN h.status = 'pending' THEN 0 ELSE 1 END,
           h.created_at ASC
         LIMIT 500`
      );

      res.json({
        sucesso: true,
        solicitacoes: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   APROVAR, REJEITAR E ATRIBUIR FREELANCER

   A atribuição respeita a quantidade de pessoas da vaga.
===================================================== */

app.patch(
  "/admin/contratacoes/:id",
  auth,
  currentUser,
  adminOnly,
  async (req, res, next) => {
    const requestId = req.params.id;
    const status = txt(req.body.status);
    const assignedId = txt(
      req.body.assigned_professional_id ||
      req.body.freelancer_id ||
      req.body.client_id
    );

    const allowedStatuses = [
      "pending",
      "reviewing",
      "assigned",
      "completed",
      "rejected"
    ];

    if (!validUUID(requestId)) {
      return fail(res, 400, "ID de candidatura inválido.");
    }

    if (!allowedStatuses.includes(status)) {
      return fail(res, 400, "Status de candidatura inválido.");
    }

    if (status === "assigned" && !validUUID(assignedId)) {
      return fail(
        res,
        400,
        "Informe o ID válido do freelancer a ser atribuído."
      );
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const requestResult = await client.query(
        `SELECT id, client_id, service_id, status
         FROM hiring_requests
         WHERE id = $1
         FOR UPDATE`,
        [requestId]
      );

      if (!requestResult.rowCount) {
        await client.query("ROLLBACK");
        return fail(res, 404, "Candidatura não encontrada.");
      }

      const request = requestResult.rows[0];

      const jobResult = await client.query(
        `SELECT id, vacancies_count, status
         FROM services
         WHERE id = $1
         FOR UPDATE`,
        [request.service_id]
      );

      if (!jobResult.rowCount) {
        await client.query("ROLLBACK");
        return fail(res, 404, "Vaga não encontrada.");
      }

      const job = jobResult.rows[0];

      if (status === "assigned") {
        if (job.status !== "active") {
          await client.query("ROLLBACK");
          return fail(res, 400, "A vaga não está ativa.");
        }

        const candidateResult = await client.query(
                  `SELECT id, role, approval_status, is_active
           FROM users
           WHERE id = $1
           LIMIT 1
           FOR UPDATE`,
          [assignedId]
        );

        if (!candidateResult.rowCount) {
          await client.query("ROLLBACK");
          return fail(res, 404, "Freelancer não encontrado.");
        }

        const candidate = candidateResult.rows[0];

        if (
          candidate.role !== "client" ||
          candidate.approval_status !== "approved" ||
          candidate.is_active !== true
        ) {
          await client.query("ROLLBACK");
          return fail(
            res,
            400,
            "O usuário escolhido não é um freelancer aprovado e ativo."
          );
        }

        const activeAssignmentResult = await client.query(
          `SELECT id
           FROM hiring_requests
           WHERE assigned_professional_id = $1
             AND status = 'assigned'
             AND id <> $2
           LIMIT 1`,
          [assignedId, requestId]
        );

        if (activeAssignmentResult.rowCount > 0) {
          await client.query("ROLLBACK");
          return fail(
            res,
            409,
            "Este freelancer já possui uma vaga atribuída. Ele só poderá receber outra após a conclusão ou liberação da vaga atual."
          );
}

        const applicationResult = await client.query(
          `SELECT id, status
           FROM hiring_requests
           WHERE service_id = $1
             AND client_id = $2
             AND status <> 'rejected'
           LIMIT 1`,
          [request.service_id, assignedId]
        );

        if (!applicationResult.rowCount) {
          await client.query("ROLLBACK");
          return fail(
            res,
            400,
            "O freelancer precisa ter uma candidatura para esta vaga."
          );
        }

        const countResult = await client.query(
          `SELECT COUNT(*)::int AS total
           FROM hiring_requests
           WHERE service_id = $1
             AND status = 'assigned'
             AND assigned_professional_id IS NOT NULL
             AND id <> $2`,
          [request.service_id, requestId]
        );

        const assignedCount = countResult.rows[0].total;
        const maxCount = Number(job.vacancies_count || 1);

        if (assignedCount >= maxCount) {
          await client.query("ROLLBACK");
          return fail(
            res,
            409,
            "A quantidade de freelancers necessária para esta vaga já foi preenchida."
          );
        }

        await client.query(
          `UPDATE hiring_requests
           SET status = 'assigned',
               assigned_professional_id = $1,
               updated_at = NOW()
           WHERE id = $2`,
          [assignedId, requestId]
        );

        await client.query("COMMIT");

        return res.json({
          sucesso: true,
          mensagem: "Freelancer atribuído à vaga com sucesso."
        });
      }

      await client.query(
  `UPDATE hiring_requests
   SET status = $1::varchar,
       assigned_professional_id = CASE
         WHEN $1::varchar = 'rejected' THEN NULL
         ELSE assigned_professional_id
       END,
       updated_at = NOW()
   WHERE id = $2`,
  [status, requestId]
);

      await client.query("COMMIT");

      return res.json({
        sucesso: true,
        mensagem: "Candidatura atualizada."
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}

      next(error);
    } finally {
      client.release();
    }
  }
);

/* =====================================================
   MINHAS OPORTUNIDADES — FREELANCER ATRIBUÍDO
===================================================== */

app.get(
  "/minhas-oportunidades",
  auth,
  currentUser,
  onlyRoles("client"),
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT h.id, h.status, h.created_at,
                s.id AS service_id,
                s.title, s.description, s.price,
                s.city, s.state, s.establishment_name,
                s.neighborhood, s.job_address,
                s.work_date, s.work_hours
         FROM hiring_requests h
         JOIN services s ON s.id = h.service_id
         WHERE h.assigned_professional_id = $1
           AND h.status = 'assigned'
         ORDER BY s.work_date ASC NULLS LAST`,
        [req.user.id]
      );

      res.json({
        sucesso: true,
        oportunidades: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =====================================================
   CONFIGURAÇÃO INICIAL DO ADMINISTRADOR

   Use NEW_SECRET apenas no cabeçalho.
===================================================== */

app.get("/configurar-admin", (req, res) => {
  res.type("html").send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Configuração administrativa</title>
    </head>
    <body style="font-family:Arial;max-width:420px;margin:40px auto;padding:20px">
      <h2>Configurar administrador</h2>
      <p>Use somente para criar o primeiro administrador.</p>
      <form id="form">
        <p><label>Nome<br><input id="name" required></label></p>
        <p><label>E-mail<br><input id="email" type="email" required></label></p>
        <p><label>Senha (mínimo 8 caracteres)<br><input id="password" type="password" minlength="8" required></label></p>
        <p><label>Chave NEW_SECRET<br><input id="secret" type="password" required></label></p>
        <button type="submit">Criar administrador</button>
      </form>
      <pre id="result"></pre>
      <script>
        document.getElementById("form").addEventListener("submit", async (e) => {
          e.preventDefault();
          const result = document.getElementById("result");
          result.textContent = "Processando...";
          try {
            const response = await fetch("/admin/bootstrap", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "x-bootstrap-secret": document.getElementById("secret").value
              },
              body: JSON.stringify({
                name: document.getElementById("name").value,
                email: document.getElementById("email").value,
                password: document.getElementById("password").value
              })
            });
            const data = await response.json();
            result.textContent = data.mensagem || data.message || "Solicitação concluída.";
          } catch (error) {
            result.textContent = "Não foi possível conectar ao servidor.";
          }
        });
      </script>
    </body>
    </html>
  `);
});

app.post("/admin/bootstrap", async (req, res, next) => {
  try {
    const secret = req.headers["x-bootstrap-secret"];

    if (!NEW_SECRET || NEW_SECRET.length < 24) {
      return fail(res, 500, "NEW_SECRET não está configurada corretamente.");
    }

    if (!secret || secret !== NEW_SECRET) {
      return fail(res, 403, "Chave de configuração incorreta.");
    }

    const name = txt(req.body.name || req.body.nome);
    const email = txt(req.body.email).toLowerCase();
    const password = String(req.body.password || req.body.senha || "");

    if (name.length < 3 || !validEmail(email) || password.length < 8) {
      return fail(
        res,
        400,
        "Informe nome, e-mail válido e senha com pelo menos 8 caracteres."
      );
    }

    const existingAdmin = await pool.query(
      "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    );

    if (existingAdmin.rowCount) {
      return fail(
        res,
        409,
        "Já existe um administrador. A criação inicial foi bloqueada."
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
        (name, email, password_hash, role, approval_status, is_active)
       VALUES ($1, $2, $3, 'admin', 'approved', TRUE)
       RETURNING id, name, email, role`,
      [name, email, passwordHash]
    );

    res.status(201).json({
      sucesso: true,
      mensagem: "Administrador criado com sucesso.",
      usuario: result.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return fail(res, 409, "Este e-mail já está cadastrado.");
    }

    next(error);
  }
});

/* =====================================================
   ERROS E INICIALIZAÇÃO
===================================================== */

app.use((req, res) => {
  res.status(404).json({
    sucesso: false,
    mensagem: "Rota não encontrada."
  });
});

app.use((error, req, res, next) => {
  console.error("Erro na aplicação:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    sucesso: false,
    mensagem: "Ocorreu um erro interno. Tente novamente."
  });
});

async function iniciar() {
  try {
    await pool.query("SELECT 1");
    console.log("Conexão com o Neon confirmada.");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Servidor iniciado na porta ${PORT}.`);
    });
  } catch (error) {
    console.error("Não foi possível conectar ao banco:", error.message);
    process.exit(1);
  }
}

iniciar();
