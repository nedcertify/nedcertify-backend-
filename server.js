const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const { v4: uuidv4 } = require("uuid");
const { Pool } = require("pg");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-now";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL || "https://nedcertify.com";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(express.json({ limit: "2mb" }));
app.use(morgan("dev"));
app.use(
  cors({
    origin:
      CORS_ORIGIN === "*"
        ? true
        : CORS_ORIGIN.split(",").map((s) => s.trim()),
    credentials: true,
  })
);

async function query(text, params = []) {
  return pool.query(text, params);
}

async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      institution_id TEXT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS institutions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      country TEXT,
      city TEXT,
      type TEXT,
      status TEXT,
      contact_email TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS diplomas (
      id TEXT PRIMARY KEY,
      diploma_number TEXT UNIQUE NOT NULL,
      student_name TEXT,
      student_id TEXT,
      date_of_birth TEXT,
      degree TEXT,
      field TEXT,
      graduation_date TEXT,
      institution_id TEXT NULL,
      status TEXT,
      blockchain_status TEXT,
      blockchain_hash TEXT NULL,
      certified_at TEXT NULL,
      verification_url TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      action TEXT,
      entity TEXT,
      entity_id TEXT,
      details TEXT,
      user_id TEXT NULL,
      user_name TEXT NULL,
      user_email TEXT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await seedData();
}

async function seedData() {
  await query(
    `INSERT INTO users (id, email, password, name, role, institution_id)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (email) DO NOTHING`,
    ["user-admin", "admin@nedcertify.com", "admin123", "Admin NedCertify", "SUPER_ADMIN", null]
  );

  await query(
    `INSERT INTO users (id, email, password, name, role, institution_id)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (email) DO NOTHING`,
    ["user-ministry", "ministry@nedcertify.com", "ministry123", "Admin Ministère", "MINISTRY_ADMIN", null]
  );

  await query(
    `INSERT INTO users (id, email, password, name, role, institution_id)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (email) DO NOTHING`,
    ["user-auditor", "auditor@nedcertify.com", "auditor123", "Auditeur NedCertify", "AUDITOR", null]
  );

  await query(
    `INSERT INTO institutions (id, name, country, city, type, status, contact_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (id) DO NOTHING`,
    ["inst-uac", "Université d'Abomey-Calavi", "Bénin", "Abomey-Calavi", "UNIVERSITY", "ACTIVE", "rectorat@uac.bj"]
  );

  await query(
    `INSERT INTO institutions (id, name, country, city, type, status, contact_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (id) DO NOTHING`,
    ["inst-ugb", "Université Gaston Berger de Saint-Louis", "Sénégal", "Saint-Louis", "UNIVERSITY", "ACTIVE", "rectorat@ugb.edu.sn"]
  );

  await query(
    `INSERT INTO institutions (id, name, country, city, type, status, contact_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (id) DO NOTHING`,
    ["inst-estloko", "E.S.T Loko", "Côte d'Ivoire", "Abidjan", "SCHOOL", "ACTIVE", "contact@estloko.com"]
  );
}

async function addAudit({ action, entity, entityId, details, user }) {
  await query(
    `INSERT INTO audit_logs (id, action, entity, entity_id, details, user_id, user_name, user_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      uuidv4(),
      action,
      entity,
      entityId,
      details,
      user?.id || null,
      user?.name || null,
      user?.email || null,
    ]
  );
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      institutionId: user.institution_id || null,
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Authorization required" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await query(`SELECT * FROM users WHERE id = $1`, [payload.sub]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ message: "Invalid token user" });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "NedCertify PostgreSQL Backend", status: "running" });
});

app.get("/health", async (req, res) => {
  await query("SELECT 1");
  res.json({ ok: true, status: "healthy", time: new Date().toISOString() });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const result = await query(
    `SELECT * FROM users WHERE lower(email) = lower($1) AND password = $2`,
    [email || "", password || ""]
  );
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  await addAudit({
    action: "LOGIN",
    entity: "User",
    entityId: user.id,
    details: `Connexion utilisateur: ${user.email}`,
    user,
  });

  const token = signToken(user);
  return res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      institutionId: user.institution_id,
    },
  });
});

app.post("/auth/signup", async (req, res) => {
  const { email, password, name } = req.body || {};

  if (!email || !password || !name) {
    return res.status(400).json({ message: "Nom, email et mot de passe requis" });
  }

  const exists = await query(`SELECT id FROM users WHERE lower(email) = lower($1)`, [email]);
  if (exists.rows[0]) {
    return res.status(409).json({ message: "Cet email existe déjà" });
  }

  const id = uuidv4();
  await query(
    `INSERT INTO users (id, email, password, name, role, institution_id)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, email, password, name, "INSTITUTION_ADMIN", null]
  );

  const user = { id, email, password, name, role: "INSTITUTION_ADMIN", institution_id: null };

  await addAudit({
    action: "SIGNUP",
    entity: "User",
    entityId: id,
    details: `Création compte: ${email}`,
    user,
  });

  const token = signToken(user);
  res.status(201).json({
    token,
    user: { id, email, name, role: "INSTITUTION_ADMIN", institutionId: null },
  });
});

app.get("/auth/me", authRequired, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    institutionId: u.institution_id,
  });
});

app.get("/dashboard", authRequired, async (req, res) => {
  const totalDiplomas = Number((await query(`SELECT COUNT(*)::int AS count FROM diplomas`)).rows[0].count);
  const certifiedDiplomas = Number((await query(`SELECT COUNT(*)::int AS count FROM diplomas WHERE status='CERTIFIED'`)).rows[0].count);
  const revokedDiplomas = Number((await query(`SELECT COUNT(*)::int AS count FROM diplomas WHERE status='REVOKED'`)).rows[0].count);
  const totalInstitutions = Number((await query(`SELECT COUNT(*)::int AS count FROM institutions`)).rows[0].count);

  const recentActivity = (
    await query(
      `SELECT id, action, entity, details, created_at, user_name, user_email
       FROM audit_logs
       ORDER BY created_at DESC
       LIMIT 10`
    )
  ).rows.map((a) => ({
    id: a.id,
    action: a.action,
    entity: a.entity,
    details: a.details,
    createdAt: a.created_at,
    user: a.user_name ? { name: a.user_name, email: a.user_email } : null,
  }));

  res.json({
    totalDiplomas,
    certifiedDiplomas,
    revokedDiplomas,
    totalInstitutions,
    recentActivity,
  });
});

app.get("/institutions", authRequired, async (req, res) => {
  const result = await query(`SELECT * FROM institutions ORDER BY created_at DESC`);
  res.json(
    result.rows.map((i) => ({
      id: i.id,
      name: i.name,
      country: i.country,
      city: i.city,
      type: i.type,
      status: i.status,
      contactEmail: i.contact_email,
      createdAt: i.created_at,
      updatedAt: i.updated_at,
    }))
  );
});

app.post("/institutions", authRequired, async (req, res) => {
  const id = uuidv4();
  const now = new Date().toISOString();

  await query(
    `INSERT INTO institutions (id, name, country, city, type, status, contact_email, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      id,
      req.body.name,
      req.body.country || "",
      req.body.city || "",
      req.body.type || "UNIVERSITY",
      req.body.status || "ACTIVE",
      req.body.contactEmail || "",
      now,
      now,
    ]
  );

  await addAudit({
    action: "CREATE",
    entity: "Institution",
    entityId: id,
    details: `Création institution: ${req.body.name}`,
    user: req.user,
  });

  res.status(201).json({
    id,
    name: req.body.name,
    country: req.body.country || "",
    city: req.body.city || "",
    type: req.body.type || "UNIVERSITY",
    status: req.body.status || "ACTIVE",
    contactEmail: req.body.contactEmail || "",
    createdAt: now,
    updatedAt: now,
  });
});

app.patch("/institutions/:id", authRequired, async (req, res) => {
  const check = await query(`SELECT * FROM institutions WHERE id = $1`, [req.params.id]);
  if (!check.rows[0]) {
    return res.status(404).json({ message: "Institution not found" });
  }

  const current = check.rows[0];
  const updated = {
    name: req.body.name ?? current.name,
    country: req.body.country ?? current.country,
    city: req.body.city ?? current.city,
    type: req.body.type ?? current.type,
    status: req.body.status ?? current.status,
    contact_email: req.body.contactEmail ?? current.contact_email,
    updated_at: new Date().toISOString(),
  };

  await query(
    `UPDATE institutions
     SET name=$1, country=$2, city=$3, type=$4, status=$5, contact_email=$6, updated_at=$7
     WHERE id=$8`,
    [
      updated.name,
      updated.country,
      updated.city,
      updated.type,
      updated.status,
      updated.contact_email,
      updated.updated_at,
      req.params.id,
    ]
  );

  await addAudit({
    action: "UPDATE",
    entity: "Institution",
    entityId: req.params.id,
    details: `Mise à jour institution: ${updated.name}`,
    user: req.user,
  });

  res.json({
    id: req.params.id,
    name: updated.name,
    country: updated.country,
    city: updated.city,
    type: updated.type,
    status: updated.status,
    contactEmail: updated.contact_email,
    createdAt: current.created_at,
    updatedAt: updated.updated_at,
  });
});

app.get("/diplomas", authRequired, async (req, res) => {
  const result = await query(`
    SELECT d.*, i.name AS institution_name
    FROM diplomas d
    LEFT JOIN institutions i ON i.id = d.institution_id
    ORDER BY d.created_at DESC
  `);

  res.json(
    result.rows.map((d) => ({
      id: d.id,
      diplomaNumber: d.diploma_number,
      studentName: d.student_name,
      studentId: d.student_id,
      dateOfBirth: d.date_of_birth,
      degree: d.degree,
      field: d.field,
      graduationDate: d.graduation_date,
      institutionId: d.institution_id,
      status: d.status,
      blockchainStatus: d.blockchain_status,
      blockchainHash: d.blockchain_hash,
      certifiedAt: d.certified_at,
      verificationUrl: d.verification_url,
      createdAt: d.created_at,
      updatedAt: d.updated_at,
      institution: d.institution_id
        ? { id: d.institution_id, name: d.institution_name }
        : null,
    }))
  );
});

app.post("/diplomas", authRequired, async (req, res) => {
  const id = uuidv4();
  const body = req.body || {};
  const now = new Date().toISOString();

  const diplomaNumber =
    body.diplomaNumber ||
    `NC-${new Date().getFullYear()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;

  const verificationUrl = `${PUBLIC_APP_URL}/verify/${encodeURIComponent(diplomaNumber)}`;

  await query(
    `INSERT INTO diplomas (
      id, diploma_number, student_name, student_id, date_of_birth, degree, field,
      graduation_date, institution_id, status, blockchain_status, blockchain_hash,
      certified_at, verification_url, created_at, updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      id,
      diplomaNumber,
      body.studentName || "",
      body.studentId || "",
      body.dateOfBirth || null,
      body.degree || "",
      body.field || "",
      body.graduationDate || new Date().toISOString().slice(0, 10),
      body.institutionId || null,
      "DRAFT",
      "PENDING",
      null,
      null,
      verificationUrl,
      now,
      now,
    ]
  );

  await addAudit({
    action: "CREATE",
    entity: "Diploma",
    entityId: id,
    details: `Création diplôme: ${body.studentName || ""} - ${body.degree || ""}`,
    user: req.user,
  });

  res.status(201).json({
    id,
    diplomaNumber,
    studentName: body.studentName || "",
    studentId: body.studentId || "",
    dateOfBirth: body.dateOfBirth || null,
    degree: body.degree || "",
    field: body.field || "",
    graduationDate: body.graduationDate || new Date().toISOString().slice(0, 10),
    institutionId: body.institutionId || null,
    status: "DRAFT",
    blockchainStatus: "PENDING",
    blockchainHash: null,
    certifiedAt: null,
    verificationUrl,
    createdAt: now,
    updatedAt: now,
  });
});

app.patch("/diplomas/:id", authRequired, async (req, res) => {
  const check = await query(`SELECT * FROM diplomas WHERE id = $1`, [req.params.id]);
  if (!check.rows[0]) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  const current = check.rows[0];
  const updated = {
    student_name: req.body.studentName ?? current.student_name,
    student_id: req.body.studentId ?? current.student_id,
    date_of_birth: req.body.dateOfBirth ?? current.date_of_birth,
    degree: req.body.degree ?? current.degree,
    field: req.body.field ?? current.field,
    graduation_date: req.body.graduationDate ?? current.graduation_date,
    institution_id: req.body.institutionId ?? current.institution_id,
    updated_at: new Date().toISOString(),
  };

  await query(
    `UPDATE diplomas
     SET student_name=$1, student_id=$2, date_of_birth=$3, degree=$4, field=$5,
         graduation_date=$6, institution_id=$7, updated_at=$8
     WHERE id=$9`,
    [
      updated.student_name,
      updated.student_id,
      updated.date_of_birth,
      updated.degree,
      updated.field,
      updated.graduation_date,
      updated.institution_id,
      updated.updated_at,
      req.params.id,
    ]
  );

  await addAudit({
    action: "UPDATE",
    entity: "Diploma",
    entityId: req.params.id,
    details: `Mise à jour diplôme: ${current.diploma_number}`,
    user: req.user,
  });

  res.json({
    id: req.params.id,
    diplomaNumber: current.diploma_number,
    studentName: updated.student_name,
    studentId: updated.student_id,
    dateOfBirth: updated.date_of_birth,
    degree: updated.degree,
    field: updated.field,
    graduationDate: updated.graduation_date,
    institutionId: updated.institution_id,
    status: current.status,
    blockchainStatus: current.blockchain_status,
    blockchainHash: current.blockchain_hash,
    certifiedAt: current.certified_at,
    verificationUrl: current.verification_url,
    createdAt: current.created_at,
    updatedAt: updated.updated_at,
  });
});

app.post("/diplomas/:id/certify", authRequired, async (req, res) => {
  const check = await query(`SELECT * FROM diplomas WHERE id = $1`, [req.params.id]);
  if (!check.rows[0]) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  const current = check.rows[0];
  const blockchainHash =
    "0x" + uuidv4().replace(/-/g, "") + uuidv4().replace(/-/g, "").slice(0, 8);
  const certifiedAt = new Date().toISOString();
  const updatedAt = certifiedAt;

  await query(
    `UPDATE diplomas
     SET status='CERTIFIED', blockchain_status='ANCHORED', blockchain_hash=$1,
         certified_at=$2, updated_at=$3
     WHERE id=$4`,
    [blockchainHash, certifiedAt, updatedAt, req.params.id]
  );

  await addAudit({
    action: "CERTIFICATION",
    entity: "Diploma",
    entityId: req.params.id,
    details: `Diplôme certifié: ${current.diploma_number}`,
    user: req.user,
  });

  res.json({
    id: current.id,
    diplomaNumber: current.diploma_number,
    studentName: current.student_name,
    studentId: current.student_id,
    degree: current.degree,
    field: current.field,
    graduationDate: current.graduation_date,
    institutionId: current.institution_id,
    status: "CERTIFIED",
    blockchainStatus: "ANCHORED",
    blockchainHash,
    certifiedAt,
    verificationUrl: current.verification_url,
    createdAt: current.created_at,
    updatedAt,
  });
});

app.post("/diplomas/:id/revoke", authRequired, async (req, res) => {
  const check = await query(`SELECT * FROM diplomas WHERE id = $1`, [req.params.id]);
  if (!check.rows[0]) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  const current = check.rows[0];
  const updatedAt = new Date().toISOString();

  await query(
    `UPDATE diplomas SET status='REVOKED', updated_at=$1 WHERE id=$2`,
    [updatedAt, req.params.id]
  );

  await addAudit({
    action: "REVOCATION",
    entity: "Diploma",
    entityId: req.params.id,
    details: `Diplôme révoqué: ${current.diploma_number}`,
    user: req.user,
  });

  res.json({
    id: current.id,
    diplomaNumber: current.diploma_number,
    studentName: current.student_name,
    studentId: current.student_id,
    degree: current.degree,
    field: current.field,
    graduationDate: current.graduation_date,
    institutionId: current.institution_id,
    status: "REVOKED",
    blockchainStatus: current.blockchain_status,
    blockchainHash: current.blockchain_hash,
    certifiedAt: current.certified_at,
    verificationUrl: current.verification_url,
    createdAt: current.created_at,
    updatedAt,
  });
});

app.get("/audit", authRequired, async (req, res) => {
  const { search = "", action = "", entity = "", page = 1, limit = 30 } = req.query;
  let where = [];
  let params = [];
  let idx = 1;

  if (search) {
    where.push(`LOWER(details) LIKE LOWER($${idx++})`);
    params.push(`%${search}%`);
  }
  if (action) {
    where.push(`action = $${idx++}`);
    params.push(action);
  }
  if (entity) {
    where.push(`entity = $${idx++}`);
    params.push(entity);
  }

  const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const countResult = await query(`SELECT COUNT(*)::int AS count FROM audit_logs ${whereClause}`, params);
  const total = countResult.rows[0].count;

  const pageNum = Number(page) || 1;
  const limitNum = Number(limit) || 30;
  const offset = (pageNum - 1) * limitNum;

  const logsResult = await query(
    `SELECT * FROM audit_logs ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${idx++} OFFSET $${idx++}`,
    [...params, limitNum, offset]
  );

  res.json({
    logs: logsResult.rows.map((a) => ({
      id: a.id,
      action: a.action,
      entity: a.entity,
      entityId: a.entity_id,
      details: a.details,
      userId: a.user_id,
      user: a.user_name ? { name: a.user_name, email: a.user_email } : null,
      createdAt: a.created_at,
    })),
    total,
    page: pageNum,
    limit: limitNum,
  });
});

app.get("/verify/:id", async (req, res) => {
  const id = decodeURIComponent(req.params.id);

  const result = await query(
    `SELECT d.*, i.name AS institution_name, i.country AS institution_country, i.city AS institution_city, i.type AS institution_type
     FROM diplomas d
     LEFT JOIN institutions i ON i.id = d.institution_id
     WHERE d.diploma_number = $1 OR d.id = $1
     LIMIT 1`,
    [id]
  );

  const diploma = result.rows[0];

  if (!diploma) {
    return res.status(404).json({
      valid: false,
      blockchainConfirmed: false,
      verifiedAt: new Date().toISOString(),
      message: "Aucun diplôme trouvé avec cet identifiant.",
    });
  }

  const institution = diploma.institution_id
    ? {
        id: diploma.institution_id,
        name: diploma.institution_name,
        country: diploma.institution_country,
        city: diploma.institution_city,
        type: diploma.institution_type,
      }
    : null;

  if (diploma.status === "REVOKED") {
    return res.json({
      valid: false,
      diploma: {
        diplomaNumber: diploma.diploma_number,
        studentName: diploma.student_name,
        degree: diploma.degree,
        field: diploma.field,
        graduationDate: diploma.graduation_date,
        status: "REVOKED",
        institution,
      },
      blockchainConfirmed: false,
      verifiedAt: new Date().toISOString(),
      message: "Ce diplôme a été révoqué.",
    });
  }

  if (diploma.status !== "CERTIFIED") {
    return res.json({
      valid: false,
      diploma: {
        diplomaNumber: diploma.diploma_number,
        studentName: diploma.student_name,
        degree: diploma.degree,
        field: diploma.field,
        graduationDate: diploma.graduation_date,
        status: diploma.status,
        institution,
      },
      blockchainConfirmed: false,
      verifiedAt: new Date().toISOString(),
      message: "Ce diplôme n'est pas encore certifié.",
    });
  }

  return res.json({
    valid: true,
    diploma: {
      diplomaNumber: diploma.diploma_number,
      studentName: diploma.student_name,
      degree: diploma.degree,
      field: diploma.field,
      graduationDate: diploma.graduation_date,
      status: "CERTIFIED",
      blockchainHash: diploma.blockchain_hash,
      blockchainStatus: diploma.blockchain_status,
      certifiedAt: diploma.certified_at,
      institution,
    },
    blockchainConfirmed: diploma.blockchain_status === "ANCHORED",
    verifiedAt: new Date().toISOString(),
    message: "Ce diplôme est authentique et certifié.",
  });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`NedCertify PostgreSQL backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database init failed:", err);
    process.exit(1);
  });
