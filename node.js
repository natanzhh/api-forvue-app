const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());

app.use(express.json());

// ==============================
// CONFIG
// ==============================
const SECRET = "segredo_super_secreto";
const PORT = 3000;

// ==============================
// BANCO EM MEMÓRIA
// ==============================
let users = [];
let tasks = [];
let taskId = 1;

// ==============================
// MIDDLEWARE DE AUTENTICAÇÃO
// ==============================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ error: "Token não fornecido" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// ==============================
// ROTAS DE AUTENTICAÇÃO
// ==============================

// Registro
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const userExists = users.find((u) => u.username === username);
  if (userExists) return res.status(400).json({ error: "Usuário já existe" });

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
  };

  users.push(newUser);

  res.json({ message: "Usuário criado com sucesso" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ error: "Senha inválida" });

  const token = jwt.sign({ id: user.id }, SECRET, {
    expiresIn: "1h",
  });

  res.json({ token });
});

// ==============================
// CRUD DE TAREFAS (PROTEGIDO)
// ==============================

// Criar tarefa
app.post("/tasks", authMiddleware, (req, res) => {
  const { title } = req.body;

  const newTask = {
    id: taskId++,
    title,
    completed: false,
    userId: req.userId,
  };

  tasks.push(newTask);

  res.json(newTask);
});

// Listar tarefas do usuário
app.get("/tasks", authMiddleware, (req, res) => {
  const userTasks = tasks.filter((t) => t.userId === req.userId);
  res.json(userTasks);
});

// Atualizar tarefa
app.put("/tasks/:id", authMiddleware, (req, res) => {
  console.log("req.params.id", req.params.id);
  const task = tasks.find(
    (t) => t.id == req.params.id && t.userId === req.userId,
  );
  console.log("task", task);
  if (!task) return res.status(404).json({ error: "Tarefa não encontrada" });
  console.log("req.body.title", req.body.title);
  task.title = req.body.title ?? task.title;
  task.completed = req.body.completed ?? task.completed;

  res.json(task);
});

// Deletar tarefa
app.delete("/tasks/:id", authMiddleware, (req, res) => {
  const index = tasks.findIndex(
    (t) => t.id == req.params.id && t.userId === req.userId,
  );

  if (index === -1)
    return res.status(404).json({ error: "Tarefa não encontrada" });

  tasks.splice(index, 1);

  res.json({ message: "Tarefa removida" });
});

// ==============================
// START
// ==============================
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
