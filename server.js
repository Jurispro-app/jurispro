// server.js - SaaS jurídico completo num único arquivo

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/jurispro';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// --- MODELS ---

const { Schema, model } = mongoose;

const UserSchema = new Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

const User = model('User', UserSchema);

const ProcessSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: String,
  status: { type: String, default: 'Aberto' },
  createdAt: { type: Date, default: Date.now },
});

const Process = model('Process', ProcessSchema);

const PetitionSchema = new Schema({
  title: { type: String, required: true },
  area: String,
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Petition = model('Petition', PetitionSchema);

// --- AUTH MIDDLEWARE ---

const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user) return res.status(401).json({ error: 'Usuário inválido' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

// --- ROUTES ---

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    if (await User.findOne({ email })) return res.status(400).json({ error: 'Email já cadastrado' });

    const user = new User({ name, email, password });
    await user.save();
    res.json({ message: 'Usuário registrado com sucesso' });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Credenciais inválidas' });

    const passOk = await user.comparePassword(password);
    if (!passOk) return res.status(400).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Obter processos do usuário
app.get('/api/processes', auth, async (req, res) => {
  const processes = await Process.find({ userId: req.user._id });
  res.json(processes);
});

// Criar processo
app.post('/api/processes', auth, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) return res.status(400).json({ error: 'Título obrigatório' });

    const proc = new Process({ userId: req.user._id, title, description });
    await proc.save();
    res.json(proc);
  } catch {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Listar petições (geral)
app.get('/api/petitions', auth, async (req, res) => {
  const petitions = await Petition.find();
  res.json(petitions);
});

// Criar petição
app.post('/api/petitions', auth, async (req, res) => {
  try {
    const { title, area, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Título e conteúdo são obrigatórios' });

    const pet = new Petition({ title, area, content });
    await pet.save();
    res.json(pet);
  } catch {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Placeholder financeiro
app.get('/api/finance', auth, (req, res) => {
  res.json({ message: 'Financeiro em desenvolvimento' });
});

// --- FRONTEND SPA embutido ---

const frontendHTML = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>JurisPro SaaS Jurídico</title>
  <style>
    body { font-family: Arial, sans-serif; margin:0; padding:0; background:#f5f5f5; }
    nav { background:#2c3e50; color:#ecf0f1; padding:10px 20px; display:flex; align-items:center; }
    nav a { color:#ecf0f1; margin-right:20px; text-decoration:none; font-weight:bold; }
    nav button { margin-left:auto; background:#e74c3c; border:none; color:#fff; padding:6px 12px; cursor:pointer; border-radius:4px; }
    .container { max-width:900px; margin:30px auto; background:#fff; padding:20px; border-radius:6px; box-shadow: 0 0 10px rgba(0,0,0,0.1);}
    input, textarea { width:100%; padding:8px; margin-bottom:10px; border:1px solid #ccc; border-radius:4px; font-size:14px;}
    button { background:#2980b9; border:none; color:#fff; padding:10px 16px; font-size:16px; border-radius:4px; cursor:pointer; }
    ul { list-style:none; padding-left:0; }
    li { padding:8px 4px; border-bottom:1px solid #ddd; }
    h2 { margin-top:0; }
    .error { color:#c0392b; margin-bottom:10px; }
  </style>
</head>
<body>
<div id="root"></div>
<script src="https://unpkg.com/react@18/umd/react.development.js" crossorigin></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js" crossorigin></script>
<script src="https://unpkg.com/react-router-dom@6/umd/react-router-dom.development.js" crossorigin></script>
<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
<script>
const { useState, useEffect } = React;
const { BrowserRouter, Routes, Route, Link, Navigate, useNavigate } = ReactRouterDOM;

const API = '';

function Navbar() {
  const navigate = useNavigate();
  const logout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };
  return (
    React.createElement('nav', null,
      React.createElement(Link, { to: '/dashboard' }, 'Dashboard'),
      React.createElement(Link, { to: '/processes' }, 'Processos'),
      React.createElement(Link, { to: '/finance' }, 'Financeiro'),
      React.createElement(Link, { to: '/petitions' }, 'Petições'),
      React.createElement('button', { onClick: logout }, 'Sair')
    )
  );
}

function PrivateRoute({ children }) {
  const token = localStorage.getItem('token');
  if (!token) return React.createElement(Navigate, { to: '/login' });
  return children;
}

function Login() {
  const [form, setForm] = useState({ email:'', password:'' });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const submit = () => {
    setError('');
    if (!form.email || !form.password) return setError('Preencha email e senha');
    axios.post(API + '/api/auth/login', form)
      .then(res => {
        localStorage.setItem('token', res.data.token);
        navigate('/dashboard');
      })
      .catch(() => setError('Credenciais inválidas'));
  };

  return React.createElement('div', { className: 'container' },
    React.createElement('h2', null, 'Login'),
    error && React.createElement('p', { className: 'error' }, error),
    React.createElement('input', {
      type: 'email',
      placeholder: 'Email',
      value: form.email,
      onChange: e => setForm({...form, email: e.target.value}),
      autoComplete: 'username',
    }),
    React.createElement('input', {
      type: 'password',
      placeholder: 'Senha',
      value: form.password,
      onChange: e => setForm({...form, password: e.target.value}),
      autoComplete: 'current-password',
    }),
    React.createElement('button', { onClick: submit }, 'Entrar')
  );
}

function Dashboard() {
  return React.createElement('div', { className: 'container' },
    React.createElement('h2', null, 'Bem-vindo ao JurisPro'),
    React.createElement('p', null, 'Sistema jurídico completo para advogados.')
  );
}

function Processes() {
  const [processes, setProcesses] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const token = localStorage.getItem('token');

  useEffect(() => {
    axios.get(API + '/api/processes', { headers: { Authorization: 'Bearer ' + token } })
      .then(res => setProcesses(res.data))
      .catch(() => setError('Erro ao carregar processos'));
  }, [token]);

  const addProcess = () => {
    if (!title) return setError('Título obrigatório');
    setError('');
    axios.post(API + '/api/processes', { title, description }, { headers: { Authorization: 'Bearer ' + token } })
      .then(res => {
        setProcesses(prev => [...prev, res.data]);
        setTitle('');
        setDescription('');
      })
      .catch(() => setError('Erro ao adicionar processo'));
  };

  return React.createElement('div', { className: 'container' },
    React.createElement('h2', null, 'Meus Processos'),
    error && React.createElement('p', { className: 'error' }, error),
    React.createElement('input', {
      placeholder: 'Título',
      value: title,
      onChange: e => setTitle(e.target.value)
    }),
    React.createElement('textarea', {
      placeholder: 'Descrição',
      rows: 3,
      value: description,
      onChange: e => setDescription(e.target.value)
    }),
    React.createElement('button', { onClick: addProcess }, 'Adicionar Processo'),
    React.createElement('ul', null,
      processes.map(p => React.createElement('li', { key: p._id }, p.title + (p.description ? ' — ' + p.description : '')))
    )
  );
}

function Petitions() {
  const [petitions, setPetitions] = useState([]);
  const [form, setForm] = useState({ title:'', area:'', content:'' });
  const [error, setError] = useState('');
  const token = localStorage.getItem('token');

  useEffect(() => {
    axios.get(API + '/api/petitions', { headers: { Authorization: 'Bearer ' + token } })
      .then(res => setPetitions(res.data))
      .catch(() => setError('Erro ao carregar petições'));
  }, [token]);

  const savePetition = () => {
    if (!form.title || !form.content) return setError('Título e conteúdo obrigatórios');
    setError('');
    axios.post(API + '/api/petitions', form, { headers: { Authorization: 'Bearer ' + token } })
      .then(res => {
        setPetitions(prev => [...prev, res.data]);
        setForm({ title:'', area:'', content:'' });
      })
      .catch(() => setError('Erro ao salvar petição'));
  };

  return React.createElement('div', { className: 'container' },
    React.createElement('h2', null, 'Petições'),
    error && React.createElement('p', { className: 'error' }, error),
    React.createElement('input', {
      placeholder: 'Título',
      value: form.title,
      onChange: e => setForm({...form, title: e.target.value})
    }),
    React.createElement('input', {
      placeholder: 'Área',
      value: form.area,
      onChange: e => setForm({...form, area: e.target.value})
    }),
    React.createElement('textarea', {
      placeholder: 'Conteúdo',
      rows: 6,
      value: form.content,
      onChange: e => setForm({...form, content: e.target.value})
    }),
    React.createElement('button', { onClick: savePetition }, 'Salvar'),
    React.createElement('ul', null,
      petitions.map(p => React.createElement('li', { key: p._id }, p.title + (p.area ? ' (' + p.area + ')' : '')))
    )
  );
}

function Finance() {
  const [msg, setMsg] = useState('');
  const token = localStorage.getItem('token');

  useEffect(() => {
    axios.get(API + '/api/finance', { headers: { Authorization: 'Bearer ' + token } })
      .then(res => setMsg(res.data.message))
      .catch(() => setMsg('Erro ao carregar financeiro'));
  }, [token]);

  return React.createElement('div', { className: 'container' },
    React.createElement('h2', null, 'Financeiro'),
    React.createElement('p', null, msg)
  );
}

function App() {
  return React.createElement(BrowserRouter, null,
    React.createElement(Navbar, null),
    React.createElement(Routes, null,
      React.createElement(Route, { path: '/login', element: React.createElement(Login) }),
      React.createElement(Route, { path: '/dashboard', element: React.createElement(PrivateRoute, null, React.createElement(Dashboard)) }),
      React.createElement(Route, { path: '/processes', element: React.createElement(PrivateRoute, null, React.createElement(Processes)) }),
      React.createElement(Route, { path: '/petitions', element: React.createElement(PrivateRoute, null, React.createElement(Petitions)) }),
      React.createElement(Route, { path: '/finance', element: React.createElement(PrivateRoute, null, React.createElement(Finance)) }),
      React.createElement(Route, { path: '*', element: React.createElement(Navigate, { to: '/login' }) })
    )
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
</script>
</body>
</html>
`;

app.get('/', (req, res) => {
  res.send(frontendHTML);
});

// --- START SERVER & CONNECT MONGO ---

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB conectado em', MONGO_URI);
    app.listen(PORT, () => {
      console.log('Servidor rodando em http://localhost:' + PORT);
    });
  })
  .catch(err => {
    console.error('Erro ao conectar MongoDB:', err);
  });
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
