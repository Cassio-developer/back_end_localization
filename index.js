const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();
const Location = require('./models/Location');

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
  }
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Rota de teste simples
app.get('/test', (req, res) => {
  res.json({ message: 'Backend funcionando!' });
});

// Conectar ao MongoDB      'mongodb://localhost:27017/rastreamento-gps'
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/rastreamento-gps')
  .then(() => console.log('Conectado ao MongoDB'))
  .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Modelo de usuário
const userSchema = new mongoose.Schema({
  nome: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  senha: {
    type: String,
    required: true,
    minlength: 6
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Middleware de autenticação JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'sua-chave-secreta', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Middleware de admin
const requireAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Acesso negado - Admin necessário' });
  }
  next();
};

// Rotas de autenticação
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nome, senha } = req.body;
    //  console.log('senha',senha,nome)
    // Verificar se usuário já existe
    const existingUser = await User.findOne({ nome });
    if (existingUser) {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(senha, 12);

    // Criar usuário
    const user = new User({
      nome,
      senha: hashedPassword
    });

    await user.save();

    res.status(201).json({ message: 'Usuário criado com sucesso' });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { nome, senha } = req.body;
    // Buscar usuário
    const user = await User.findOne({ nome });
    if (!user) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Verificar senha
    const isValidPassword = await bcrypt.compare(senha, user.senha);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Gerar JWT
    const token = jwt.sign(
      {
        id: user._id,
        nome: user.nome,
        isAdmin: user.isAdmin
      },
      process.env.JWT_SECRET || 'sua-chave-secreta',
      { expiresIn: '7d' }
    );

    // Configurar cookie HttpOnly
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      //      sameSite: 'strict', alterado para permitir ser mais permissiva entre subdomínios, trocando  como estamos com back em um local 
      // lembrar caso alteremos!

      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
    });

    res.json({
      message: 'Login realizado com sucesso',
      user: {
        id: user._id,
        nome: user.nome,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-senha');
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    res.json({ user });
  } catch (error) {
    console.error('Erro ao buscar usuário:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para listar usuários (apenas admin)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-senha').sort({ createdAt: -1 });
    res.json({ users });
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para promover usuário a admin (apenas admin)
app.patch('/api/users/:id/promote', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isAdmin: true },
      { new: true }
    ).select('-senha');

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário promovido a admin', user });
  } catch (error) {
    console.error('Erro ao promover usuário:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota de teste para listar todos os usuários (apenas para desenvolvimento)  depois comentar!!! enão subir
// app.get('/api/test/users', async (req, res) => {
//   try {
//     const users = await User.find().select('-senha').sort({ createdAt: -1 });
//     res.json({ 
//       message: 'Usuários encontrados', 
//       count: users.length,
//       users 
//     });
//   } catch (error) {
//     console.error('Erro ao listar usuários:', error);
//     res.status(500).json({ message: 'Erro interno do servidor' });
//   }
// });

// Socket.io para rastreamento em tempo real
const localizacoes = {};

io.on('connection', (socket) => {
  // console.log('Usuário conectado:', socket.id);

  // Enviar localizações atuais para o novo usuário
  socket.emit('localizacoes', localizacoes);

  // Receber atualização de localização
  socket.on('localizacao', (data) => {
    localizacoes[socket.id] = {
      ...data,
      timestamp: Date.now()
    };

    // Enviar para todos os outros usuários
    socket.broadcast.emit('localizacao', {
      id: socket.id,
      ...localizacoes[socket.id]
    });
  });

  // Usuário desconectado
  socket.on('disconnect', () => {
    // console.log('Usuário desconectado:', socket.id);
    delete localizacoes[socket.id];

    // Notificar outros usuários
    socket.broadcast.emit('usuarioDesconectado', socket.id);
  });
});

// Endpoint para registrar localização do usuário
app.post('/api/locations', authenticateToken, async (req, res) => {
  try {
    const { lat, lng, accuracy, timestamp } = req.body;
    if (!lat || !lng || !timestamp) {
      return res.status(400).json({ message: 'Dados de localização incompletos' });
    }
    const location = new Location({
      userId: req.user.id,
      lat,
      lng,
      accuracy,
      timestamp: new Date(timestamp)
    });
    await location.save();
    res.status(201).json({ message: 'Localização registrada com sucesso' });
  } catch (error) {
    console.error('Erro ao registrar localização:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Endpoint para buscar histórico de localizações do usuário autenticado
app.get('/api/locations', authenticateToken, async (req, res) => {
  try {
    const { from, to } = req.query;
    const query = { userId: req.user.id };
    if (from || to) {
      query.timestamp = {};
      if (from) query.timestamp.$gte = new Date(from);
      if (to) query.timestamp.$lte = new Date(to);
    }
    const locations = await Location.find(query).sort({ timestamp: 1 });
    res.json({ locations });
  } catch (error) {
    console.error('Erro ao buscar histórico de localizações:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  // console.log(`Servidor rodando na porta ${PORT}`);
}); 