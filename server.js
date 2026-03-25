const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const { v4: uuidv4 } = require("uuid");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-now";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL || "https://nedcertify.com";

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

function seedData() {
  const now = new Date().toISOString();

  const institutions = [
    {
      id: uuidv4(),
      name: "Université d'Abomey-Calavi",
      country: "Bénin",
      city: "Abomey-Calavi",
      type: "UNIVERSITY",
      status: "ACTIVE",
      contactEmail: "rectorat@uac.bj",
      createdAt: now,
      updatedAt: now,
    },
    {
      id: uuidv4(),
      name: "Université Gaston Berger de Saint-Louis",
      country: "Sénégal",
      city: "Saint-Louis",
      type: "UNIVERSITY",
      status: "ACTIVE",
      contactEmail: "rectorat@ugb.edu.sn",
      createdAt: now,
      updatedAt: now,
    },
    {
      id: uuidv4(),
      name: "E.S.T Loko",
      country: "Côte d'Ivoire",
      city: "Abidjan",
      type: "SCHOOL",
      status: "ACTIVE",
      contactEmail: "contact@estloko.com",
      createdAt: now,
      updatedAt: now,
    },
  ];

  const users = [
    {
      id: uuidv4(),
      email: "admin@nedcertify.com",
      password: "admin123",
      name: "Admin NedCertify",
      role: "SUPER_ADMIN",
      institutionId: null,
    },
    {
      id: uuidv4(),
      email: "ministry@nedcertify.com",
      password: "ministry123",
      name: "Admin Ministère",
      role: "MINISTRY_ADMIN",
      institutionId: null,
    },
    {
      id: uuidv4(),
      email: "auditor@nedcertify.com",
      password: "auditor123",
      name: "Auditeur NedCertify",
      role: "AUDITOR",
      institutionId: null,
    },
  ];

  return {
    users,
    institutions,
    diplomas: [],
    audit: [],
  };
}

let db = seedData();

function addAudit({ action, entity, entityId, details, user }) {
  db.audit.unshift({
    id: uuidv4(),
    action,
    entity,
    entityId,
    details,
    userId: user?.id || null,
    user: user ? { name: user.name, email: user.email } : null,
    createdAt: new Date().toISOString(),
  });
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      institutionId: user.institutionId || null,
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Authorization required" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.users.find((u) => u.id === payload.sub);
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
  res.json({
    ok: true,
    service: "NedCertify Simple Backend",
    status: "running",
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    time: new Date().toISOString(),
  });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = db.users.find(
    (u) =>
      u.email.toLowerCase() === String(email || "").toLowerCase() &&
      u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  addAudit({
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
      institutionId: user.institutionId,
    },
  });
});

app.post("/auth/signup", (req, res) => {
  const { email, password, name } = req.body || {};

  if (!email || !password || !name) {
    return res.status(400).json({
      message: "Nom, email et mot de passe requis",
    });
  }

  const exists = db.users.some(
    (u) => u.email.toLowerCase() === String(email).toLowerCase()
  );
  if (exists) {
    return res.status(409).json({ message: "Cet email existe déjà" });
  }

  const user = {
    id: uuidv4(),
    email,
    password,
    name,
    role: "INSTITUTION_ADMIN",
    institutionId: null,
  };

  db.users.push(user);
  addAudit({
    action: "SIGNUP",
    entity: "User",
    entityId: user.id,
    details: `Création compte: ${user.email}`,
    user,
  });

  const token = signToken(user);
  res.status(201).json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      institutionId: null,
    },
  });
});

app.get("/auth/me", authRequired, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    institutionId: u.institutionId,
  });
});

app.get("/dashboard", authRequired, (req, res) => {
  const totalDiplomas = db.diplomas.length;
  const certifiedDiplomas = db.diplomas.filter(
    (d) => d.status === "CERTIFIED"
  ).length;
  const revokedDiplomas = db.diplomas.filter(
    (d) => d.status === "REVOKED"
  ).length;
  const totalInstitutions = db.institutions.length;

  const recentActivity = db.audit.slice(0, 10).map((a) => ({
    id: a.id,
    action: a.action,
    entity: a.entity,
    details: a.details,
    createdAt: a.createdAt,
    user: a.user,
  }));

  res.json({
    totalDiplomas,
    certifiedDiplomas,
    revokedDiplomas,
    totalInstitutions,
    recentActivity,
  });
});

app.get("/institutions", authRequired, (req, res) => {
  res.json(db.institutions);
});

app.post("/institutions", authRequired, (req, res) => {
  const now = new Date().toISOString();

  const institution = {
    id: uuidv4(),
    name: req.body.name,
    country: req.body.country || "",
    city: req.body.city || "",
    type: req.body.type || "UNIVERSITY",
    status: req.body.status || "ACTIVE",
    contactEmail: req.body.contactEmail || "",
    createdAt: now,
    updatedAt: now,
  };

  db.institutions.push(institution);
  addAudit({
    action: "CREATE",
    entity: "Institution",
    entityId: institution.id,
    details: `Création institution: ${institution.name}`,
    user: req.user,
  });

  res.status(201).json(institution);
});

app.patch("/institutions/:id", authRequired, (req, res) => {
  const institution = db.institutions.find((i) => i.id === req.params.id);
  if (!institution) {
    return res.status(404).json({ message: "Institution not found" });
  }

  Object.assign(institution, req.body, {
    updatedAt: new Date().toISOString(),
  });

  addAudit({
    action: "UPDATE",
    entity: "Institution",
    entityId: institution.id,
    details: `Mise à jour institution: ${institution.name}`,
    user: req.user,
  });

  res.json(institution);
});

app.get("/diplomas", authRequired, (req, res) => {
  const data = db.diplomas.map((d) => ({
    ...d,
    institution: db.institutions.find((i) => i.id === d.institutionId) || null,
  }));
  res.json(data);
});

app.post("/diplomas", authRequired, (req, res) => {
  const body = req.body || {};
  const institution =
    db.institutions.find((i) => i.id === body.institutionId) || null;

  const diplomaNumber =
    body.diplomaNumber ||
    `NC-${new Date().getFullYear()}-${Math.random()
      .toString(36)
      .slice(2, 8)
      .toUpperCase()}`;

  const diploma = {
    id: uuidv4(),
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
    verificationUrl: `${PUBLIC_APP_URL}/verify/${encodeURIComponent(
      diplomaNumber
    )}`,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.diplomas.push(diploma);
  addAudit({
    action: "CREATE",
    entity: "Diploma",
    entityId: diploma.id,
    details: `Création diplôme: ${diploma.studentName} - ${diploma.degree}`,
    user: req.user,
  });

  res.status(201).json({
    ...diploma,
    institution,
  });
});

app.patch("/diplomas/:id", authRequired, (req, res) => {
  const diploma = db.diplomas.find((d) => d.id === req.params.id);
  if (!diploma) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  Object.assign(diploma, req.body, {
    updatedAt: new Date().toISOString(),
  });

  addAudit({
    action: "UPDATE",
    entity: "Diploma",
    entityId: diploma.id,
    details: `Mise à jour diplôme: ${diploma.diplomaNumber}`,
    user: req.user,
  });

  res.json({
    ...diploma,
    institution: db.institutions.find((i) => i.id === diploma.institutionId) || null,
  });
});

app.post("/diplomas/:id/certify", authRequired, (req, res) => {
  const diploma = db.diplomas.find((d) => d.id === req.params.id);
  if (!diploma) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  diploma.status = "CERTIFIED";
  diploma.blockchainStatus = "ANCHORED";
  diploma.blockchainHash =
    "0x" +
    uuidv4().replace(/-/g, "") +
    uuidv4().replace(/-/g, "").slice(0, 8);
  diploma.certifiedAt = new Date().toISOString();
  diploma.updatedAt = new Date().toISOString();

  addAudit({
    action: "CERTIFICATION",
    entity: "Diploma",
    entityId: diploma.id,
    details: `Diplôme certifié: ${diploma.diplomaNumber}`,
    user: req.user,
  });

  res.json({
    ...diploma,
    institution: db.institutions.find((i) => i.id === diploma.institutionId) || null,
  });
});

app.post("/diplomas/:id/revoke", authRequired, (req, res) => {
  const diploma = db.diplomas.find((d) => d.id === req.params.id);
  if (!diploma) {
    return res.status(404).json({ message: "Diploma not found" });
  }

  diploma.status = "REVOKED";
  diploma.updatedAt = new Date().toISOString();

  addAudit({
    action: "REVOCATION",
    entity: "Diploma",
    entityId: diploma.id,
    details: `Diplôme révoqué: ${diploma.diplomaNumber}`,
    user: req.user,
  });

  res.json({
    ...diploma,
    institution: db.institutions.find((i) => i.id === diploma.institutionId) || null,
  });
});

app.get("/audit", authRequired, (req, res) => {
  const { search = "", action = "", entity = "", page = 1, limit = 30 } = req.query;

  let logs = [...db.audit];

  if (search) {
    const q = String(search).toLowerCase();
    logs = logs.filter((l) => (l.details || "").toLowerCase().includes(q));
  }
  if (action) logs = logs.filter((l) => l.action === action);
  if (entity) logs = logs.filter((l) => l.entity === entity);

  const pageNum = Number(page) || 1;
  const limitNum = Number(limit) || 30;
  const start = (pageNum - 1) * limitNum;
  const data = logs.slice(start, start + limitNum);

  res.json({
    logs: data,
    total: logs.length,
    page: pageNum,
    limit: limitNum,
  });
});

app.get("/verify/:id", (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const diploma = db.diplomas.find((d) => d.diplomaNumber === id || d.id === id);

  if (!diploma) {
    return res.status(404).json({
      valid: false,
      blockchainConfirmed: false,
      verifiedAt: new Date().toISOString(),
      message: "Aucun diplôme trouvé avec cet identifiant.",
    });
  }

  const institution = db.institutions.find((i) => i.id === diploma.institutionId) || null;

  if (diploma.status === "REVOKED") {
    return res.json({
      valid: false,
      diploma: {
        diplomaNumber: diploma.diplomaNumber,
        studentName: diploma.studentName,
        degree: diploma.degree,
        field: diploma.field,
        graduationDate: diploma.graduationDate,
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
        diplomaNumber: diploma.diplomaNumber,
        studentName: diploma.studentName,
        degree: diploma.degree,
        field: diploma.field,
        graduationDate: diploma.graduationDate,
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
      diplomaNumber: diploma.diplomaNumber,
      studentName: diploma.studentName,
      degree: diploma.degree,
      field: diploma.field,
      graduationDate: diploma.graduationDate,
      status: "CERTIFIED",
      blockchainHash: diploma.blockchainHash,
      blockchainStatus: diploma.blockchainStatus,
      certifiedAt: diploma.certifiedAt,
      institution,
    },
    blockchainConfirmed: diploma.blockchainStatus === "ANCHORED",
    verifiedAt: new Date().toISOString(),
    message: "Ce diplôme est authentique et certifié.",
  });
});

app.listen(PORT, () => {
  console.log(`NedCertify simple backend running on port ${PORT}`);
});
