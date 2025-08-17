// rodar nessa pagina
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(cors({
  origin: 'http://localhost:3000', // ajuste se front em outra porta
  credentials: true,
}));
app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
  secret: 'uma_chave_secreta_super_forte',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true se usar https
}));

const db = new sqlite3.Database('./reclamacoes.db');

db.serialize(() => {
  // Criar tabela usuários
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    senha TEXT
  )`);

  // Criar tabela pins associando usuário
  db.run(`CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lat REAL,
    lng REAL,
    comentario TEXT,
    usuario_id INTEGER,
    data DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
  )`);
});

// Registro
app.post('/api/register', (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatórios' });

  bcrypt.hash(senha, SALT_ROUNDS, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Erro ao criptografar senha' });

    db.run(`INSERT INTO usuarios (email, senha) VALUES (?, ?)`, [email, hash], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'Email já cadastrado' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Usuário criado com sucesso' });
    });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatórios' });

  db.get(`SELECT * FROM usuarios WHERE email = ?`, [email], (err, user) => {
    if (err) return res.status(500).json({ error: 'Erro no banco' });
    if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

    bcrypt.compare(senha, user.senha, (err, result) => {
      if (result) {
        req.session.userId = user.id;
        res.json({ message: 'Logado com sucesso' });
      } else {
        res.status(401).json({ error: 'Senha incorreta' });
      }
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Desconectado' });
  });
});

// Verificar login
app.get('/api/user', (req, res) => {
  if (req.session.userId) {
    db.get('SELECT id, email FROM usuarios WHERE id = ?', [req.session.userId], (err, user) => {
      if (user) {
        res.json({ loggedIn: true, user });
      } else {
        res.json({ loggedIn: false });
      }
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// Criar pin — só usuário logado
app.post('/api/pins', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Não autorizado' });

  const { lat, lng, comentario } = req.body;
  if (!lat || !lng || !comentario) {
    return res.status(400).json({ error: 'Dados incompletos' });
  }

  db.run(`INSERT INTO pins (lat, lng, comentario, usuario_id) VALUES (?, ?, ?, ?)`,
    [lat, lng, comentario, req.session.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID });
    });
});

// Listar pins (sem filtro por enquanto)
app.get('/api/pins', (req, res) => {
  db.all(`SELECT pins.id, lat, lng, comentario, data, usuarios.email as usuario_email
          FROM pins LEFT JOIN usuarios ON pins.usuario_id = usuarios.id`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
