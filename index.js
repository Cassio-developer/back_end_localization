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
const User = require('./models/User');

const app = express();
const server = createServer(app);

// Configuração de variáveis de ambiente
const BACKGROUND_SYNC_ENABLED = process.env.BACKGROUND_SYNC_ENABLED === 'true';
const BACKGROUND_SYNC_INTERVAL = parseInt(process.env.BACKGROUND_SYNC_INTERVAL || '30000');
const LOCATION_CACHE_SIZE = parseInt(process.env.LOCATION_CACHE_SIZE || '100');
const SYNC_BATCH_SIZE = parseInt(process.env.SYNC_BATCH_SIZE || '10');

console.log('🔧 Configurações do Backend:');
console.log('  - Background Sync:', BACKGROUND_SYNC_ENABLED ? '✅ Habilitado' : '❌ Desabilitado');
console.log('  - Intervalo de Sync:', BACKGROUND_SYNC_INTERVAL, 'ms');
console.log('  - Tamanho do Cache:', LOCATION_CACHE_SIZE, 'localizações');
console.log('  - Tamanho do Lote:', SYNC_BATCH_SIZE, 'por sincronização');

// Configuração de CORS mais flexível
const allowedOrigins = [
  'http://localhost:3000',
  'https://live-tracking-app-world.vercel.app',
  'https://live-tracking-app-world.vercel.app/',
  'https://*.vercel.app',
  'https://*.vercel.app/',
  process.env.FRONTEND_URL
].filter(Boolean); // Remove valores undefined/null

// Função para verificar se a origem é permitida
const isOriginAllowed = (origin) => {
  if (!origin) return true; // Permitir requests sem origin
  
  // Verificar se a origem está na lista de permitidas
  return allowedOrigins.some(allowedOrigin => {
    // Remover barra final para comparação
    const cleanOrigin = origin.replace(/\/$/, '');
    const cleanAllowed = allowedOrigin.replace(/\/$/, '');
    
    // Se o allowedOrigin tem wildcard, usar regex
    if (cleanAllowed.includes('*')) {
      const regex = new RegExp(cleanAllowed.replace('*', '.*'));
      return regex.test(cleanOrigin);
    }
    
    return cleanOrigin === cleanAllowed;
  });
};

const io = new Server(server, {
  cors: {
    origin: function (origin, callback) {
      console.log('Socket.io CORS check - Origin:', origin);
      
      if (isOriginAllowed(origin)) {
        callback(null, true);
      } else {
        console.log('Socket.io CORS blocked - Origin:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  }
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    console.log('Express CORS check - Origin:', origin);
    
    if (isOriginAllowed(origin)) {
      callback(null, true);
    } else {
      console.log('Express CORS blocked - Origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json());
app.use(cookieParser());

// Rota de teste simples
app.get('/test', (req, res) => {
  res.json({ message: 'Backend funcionando!' });
});

// Rota para verificar usuários conectados (apenas para debug)
app.get('/debug/usuarios', (req, res) => {
  res.json({
    totalUsuarios: Object.keys(usuariosConectados).length,
    usuarios: Object.values(usuariosConectados),
    localizacoes: Object.keys(localizacoes).length
  });
});

// Conectar ao MongoDB      'mongodb://localhost:27017/rastreamento-gps'
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/rastreamento-gps')
  .then(() => console.log('Conectado ao MongoDB'))
  .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

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
  //      sameSite: 'strict', alterado para permitir ser mais permissiva entre subdomínios, trocando  como estamos com back em um local 
      // lembrar caso alteremos!
    // Configurar cookie HttpOnly
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      // sameSite: 'none',
 
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
  console.log('Logout solicitado - Origin:', req.headers.origin);
  
  // Limpar o cookie com as mesmas opções usadas no login
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/', // Garantir que o path seja o mesmo
    expires: new Date(0), // Forçar expiração imediata
    maxAge: 0 // Forçar expiração imediata
  };
  
  console.log('Opções do cookie para limpeza:', cookieOptions);
  
  res.clearCookie('token', cookieOptions);
  
  // Adicionar headers adicionais para garantir que o cookie seja removido
  res.setHeader('Set-Cookie', [
    'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; ' + 
    (process.env.NODE_ENV === 'production' ? 'Secure; SameSite=None' : 'SameSite=Lax')
  ]);
  
  console.log('Cookie removido com sucesso');
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

// ===== ROTAS DE AUTENTICAÇÃO FACIAL =====

// Rota para registrar dados faciais do usuário
app.post('/api/auth/register-face', authenticateToken, async (req, res) => {
  try {
    const { descriptors } = req.body;
    
    if (!descriptors || !Array.isArray(descriptors) || descriptors.length === 0) {
      return res.status(400).json({ message: 'Dados faciais inválidos' });
    }

    // Atualizar usuário com dados faciais
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        faceDescriptors: descriptors,
        faceDataUpdatedAt: new Date()
      },
      { new: true }
    ).select('-senha +faceDescriptors');

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ Dados faciais registrados para usuário:', user.nome, 'descriptors:', user.faceDescriptors ? user.faceDescriptors.length : 0);
    res.json({ 
      success: true,
      message: 'Dados faciais registrados com sucesso',
      userId: user._id
    });
  } catch (error) {
    console.error('❌ Erro ao registrar dados faciais:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para login com reconhecimento facial
app.post('/api/auth/face-login', async (req, res) => {
  try {
    const { descriptor } = req.body;
    
    if (!descriptor || !Array.isArray(descriptor)) {
      return res.status(400).json({ message: 'Dados faciais inválidos' });
    }

    // Verificar se o descritor tem o tamanho correto (128 valores para face-api.js)
    if (descriptor.length !== 128) {
      console.log(`❌ Descritor facial inválido - Tamanho: ${descriptor.length}`);
      return res.status(400).json({ message: 'Dados faciais inválidos' });
    }

    // Buscar todos os usuários com dados faciais
    const users = await User.find({ 
      faceDescriptors: { $exists: true, $ne: [] }
    }).select('-senha +faceDescriptors');

    if (users.length === 0) {
      return res.status(401).json({ message: 'Nenhum usuário com dados faciais encontrado' });
    }

    // Verificar se há pelo menos um descritor válido no sistema
    let totalDescriptors = 0;
    for (const user of users) {
      if (user.faceDescriptors && Array.isArray(user.faceDescriptors)) {
        totalDescriptors += user.faceDescriptors.length;
      }
    }

    if (totalDescriptors === 0) {
      console.log('❌ Nenhum descritor facial válido encontrado no sistema');
      return res.status(401).json({ message: 'Sistema de reconhecimento facial não configurado' });
    }

    // Função para calcular distância euclidiana
    const euclideanDistance = (desc1, desc2) => {
      if (desc1.length !== desc2.length) return Infinity;
      let sum = 0;
      for (let i = 0; i < desc1.length; i++) {
        sum += Math.pow(desc1[i] - desc2[i], 2);
      }
      return Math.sqrt(sum);
    };

    // Validação rigorosa com múltiplos critérios
    let bestMatch = null;
    let bestDistance = Infinity;
    let bestUserScores = [];
    const threshold = 0.55; // Limiar mais permissivo para teste em produção
    const minConfidence = 0.65; // Confiança mínima reduzida para teste

    console.log(`🔍 Comparando face com ${users.length} usuários...`);

    for (const user of users) {
      if (!user.faceDescriptors || !Array.isArray(user.faceDescriptors)) {
        console.log(`⚠️ Usuário ${user.nome} não tem descritores válidos`);
        continue;
      }

      const userDistances = [];
      let userBestDistance = Infinity;

      // Comparar com todos os descritores do usuário
      for (let i = 0; i < user.faceDescriptors.length; i++) {
        const storedDescriptor = user.faceDescriptors[i];
        if (!Array.isArray(storedDescriptor) || storedDescriptor.length !== 128) {
          console.log(`⚠️ Descritor inválido para usuário ${user.nome} - índice ${i}`);
          continue;
        }

        const distance = euclideanDistance(descriptor, storedDescriptor);
        userDistances.push(distance);
        
        if (distance < userBestDistance) {
          userBestDistance = distance;
        }

        console.log(`📊 ${user.nome} - Descritor ${i + 1}: ${distance.toFixed(4)}`);
      }

      // Calcular confiança baseada na consistência dos descritores
      if (userDistances.length > 0) {
        const avgDistance = userDistances.reduce((a, b) => a + b, 0) / userDistances.length;
        const consistency = 1 - (Math.max(...userDistances) - Math.min(...userDistances));
        const confidence = Math.max(0, 1 - avgDistance) * consistency;

        console.log(`📈 ${user.nome} - Média: ${avgDistance.toFixed(4)}, Consistência: ${consistency.toFixed(4)}, Confiança: ${confidence.toFixed(4)}`);

        // Critérios mais permissivos para teste em produção
        if (userBestDistance < threshold && 
            avgDistance < threshold * 1.5 && 
            confidence > minConfidence &&
            consistency > 0.5) {
          
          if (userBestDistance < bestDistance) {
            bestDistance = userBestDistance;
            bestMatch = user;
            bestUserScores = {
              bestDistance: userBestDistance,
              avgDistance: avgDistance,
              confidence: confidence,
              consistency: consistency
            };
          }
        }
      }
    }

    // Validação rigorosa com múltiplos critérios
    if (!bestMatch) {
      console.log(`❌ Nenhum usuário atende aos critérios rigorosos`);
      return res.status(401).json({ message: 'Face não reconhecida' });
    }

    // Verificações finais de segurança
    if (bestDistance > threshold) {
      console.log(`❌ Melhor distância (${bestDistance.toFixed(4)}) acima do threshold (${threshold})`);
      return res.status(401).json({ message: 'Face não reconhecida' });
    }

    if (bestUserScores.confidence < minConfidence) {
      console.log(`❌ Confiança muito baixa: ${bestUserScores.confidence.toFixed(4)} < ${minConfidence}`);
      return res.status(401).json({ message: 'Face não reconhecida com confiança suficiente' });
    }

    if (bestUserScores.consistency < 0.5) {
      console.log(`❌ Consistência muito baixa: ${bestUserScores.consistency.toFixed(4)} < 0.5`);
      return res.status(401).json({ message: 'Face não reconhecida com consistência suficiente' });
    }

    // Verificação final: distância deve ser baixa mas não excessivamente rigorosa
    if (bestDistance > 0.5) {
      console.log(`⚠️ Distância muito alta para segurança adequada: ${bestDistance.toFixed(4)}`);
      return res.status(401).json({ message: 'Face não reconhecida com segurança adequada' });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { id: bestMatch._id, nome: bestMatch.nome, isAdmin: bestMatch.isAdmin },
      process.env.JWT_SECRET || 'sua-chave-secreta',
      { expiresIn: '7d' }
    );

    // Configurar cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
    };

    res.cookie('token', token, cookieOptions);

    console.log(`✅ Login facial APROVADO para usuário: ${bestMatch.nome}`);
    console.log(`📊 Métricas finais:`);
    console.log(`   - Melhor distância: ${bestDistance.toFixed(4)}`);
    console.log(`   - Média de distâncias: ${bestUserScores.avgDistance.toFixed(4)}`);
    console.log(`   - Confiança: ${bestUserScores.confidence.toFixed(4)}`);
    console.log(`   - Consistência: ${bestUserScores.consistency.toFixed(4)}`);
    res.json({
      success: true,
      message: 'Login realizado com sucesso',
      user: {
        id: bestMatch._id,
        nome: bestMatch.nome,
        isAdmin: bestMatch.isAdmin,
        avatar: bestMatch.avatar
      },
      token
    });
  } catch (error) {
    console.error('❌ Erro no login facial:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para verificar se usuário tem dados faciais
app.get('/api/auth/face-data', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-senha +faceDescriptors');
    
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const hasFaceData = user.faceDescriptors && user.faceDescriptors.length > 0;
    
    console.log('🔍 Verificando dados faciais para usuário:', user.nome, 'hasFaceData:', hasFaceData, 'descriptors:', user.faceDescriptors ? user.faceDescriptors.length : 0);
    
    res.json({
      success: true,
      hasFaceData,
      message: hasFaceData ? 'Usuário possui dados faciais' : 'Usuário não possui dados faciais'
    });
  } catch (error) {
    console.error('❌ Erro ao verificar dados faciais:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para remover dados faciais
app.delete('/api/auth/remove-face', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        $unset: { faceDescriptors: 1, faceDataUpdatedAt: 1 }
      },
      { new: true }
    ).select('-senha');

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ Dados faciais removidos para usuário:', user.nome);
    res.json({
      success: true,
      message: 'Dados faciais removidos com sucesso'
    });
  } catch (error) {
    console.error('❌ Erro ao remover dados faciais:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Rota para atualizar dados faciais
app.put('/api/auth/update-face', authenticateToken, async (req, res) => {
  try {
    const { descriptors } = req.body;
    
    if (!descriptors || !Array.isArray(descriptors) || descriptors.length === 0) {
      return res.status(400).json({ message: 'Dados faciais inválidos' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        faceDescriptors: descriptors,
        faceDataUpdatedAt: new Date()
      },
      { new: true }
    ).select('-senha +faceDescriptors');

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ Dados faciais atualizados para usuário:', user.nome, 'descriptors:', user.faceDescriptors ? user.faceDescriptors.length : 0);
    res.json({
      success: true,
      message: 'Dados faciais atualizados com sucesso'
    });
  } catch (error) {
    console.error('❌ Erro ao atualizar dados faciais:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ===== FIM DAS ROTAS DE AUTENTICAÇÃO FACIAL =====

// Socket.io para rastreamento em tempo real
const localizacoes = {};
const usuariosConectados = {};

io.on('connection', (socket) => {
  console.log('🔌 Nova conexão socket:', socket.id);
  
  // Recebe identificação do usuário
  socket.on('identificacao', (userData) => {
    console.log('👤 Usuário identificado:', userData.nome, 'Admin:', userData.isAdmin, 'Socket:', socket.id);
    console.log('📊 Dados completos recebidos:', userData);
    console.log('🌐 Ambiente:', process.env.NODE_ENV);
    
    usuariosConectados[socket.id] = {
      ...userData,
      socketId: socket.id
    };
    
    console.log('📊 Total de usuários conectados:', Object.keys(usuariosConectados).length);
    console.log('📋 Lista completa de usuários conectados:', Object.values(usuariosConectados));
    
    // Notificar TODOS os admins sobre a nova conexão
    Object.values(usuariosConectados).forEach(user => {
      if (user.isAdmin && user.socketId !== socket.id) {
        console.log('📢 Notificando admin:', user.nome, 'sobre nova conexão');
        io.to(user.socketId).emit('usuariosConectados', Object.values(usuariosConectados));
      }
    });
    
    // Se o usuário que acabou de conectar é admin, envie a lista completa
    if (userData.isAdmin) {
      console.log('👑 Admin conectado, enviando lista de usuários:', Object.values(usuariosConectados).length);
      console.log('📋 Lista completa de usuários:', Object.values(usuariosConectados));
      socket.emit('usuariosConectados', Object.values(usuariosConectados));
    }
  });

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
    const userInfo = usuariosConectados[socket.id];
    console.log('🔌 Usuário desconectado:', userInfo?.nome || 'Desconhecido', 'Socket:', socket.id);
    console.log('👑 Era admin?', userInfo?.isAdmin);
    
    delete localizacoes[socket.id];
    delete usuariosConectados[socket.id];
    
    console.log('📊 Total de usuários conectados após desconexão:', Object.keys(usuariosConectados).length);
    console.log('📋 Lista atualizada de usuários:', Object.values(usuariosConectados));
    
    // Notificar TODOS os admins sobre a desconexão
    Object.values(usuariosConectados).forEach(user => {
      if (user.isAdmin) {
        console.log('📢 Notificando admin:', user.nome, 'sobre desconexão');
        io.to(user.socketId).emit('usuariosConectados', Object.values(usuariosConectados));
      }
    });
    
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

// Rota para sincronização de localização (Background Sync)
app.post('/api/location/sync', authenticateToken, async (req, res) => {
  try {
    // Verificar se background sync está habilitado
    if (!BACKGROUND_SYNC_ENABLED) {
      return res.status(503).json({ 
        success: false, 
        message: 'Background Sync está desabilitado' 
      });
    }

    const { latitude, longitude, accuracy, timestamp, userId } = req.body;
    const tokenUserId = req.user.id;

    // Verificar se o usuário está enviando sua própria localização
    if (userId !== tokenUserId) {
      return res.status(403).json({ 
        success: false, 
        message: 'Não autorizado a enviar localização de outro usuário' 
      });
    }

    // Validar dados
    if (!latitude || !longitude || !accuracy || !timestamp) {
      return res.status(400).json({ 
        success: false, 
        message: 'Dados de localização incompletos' 
      });
    }

    // Salvar localização no banco
    const location = new Location({
      userId: tokenUserId,
      latitude,
      longitude,
      accuracy,
      timestamp: new Date(timestamp),
      source: 'background-sync'
    });

    await location.save();

    console.log(`✅ Localização sincronizada via Background Sync - Usuário: ${tokenUserId}`);

    res.json({ 
      success: true, 
      message: 'Localização sincronizada com sucesso',
      location: {
        id: location._id,
        timestamp: location.timestamp
      }
    });

  } catch (error) {
    console.error('❌ Erro na sincronização de localização:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro interno no servidor' 
    });
  }
});

// Nova rota para atualizar avatar
app.patch('/api/users/me/avatar', authenticateToken, async (req, res) => {
  try {
    const { avatar } = req.body;
    if (!avatar) {
      return res.status(400).json({ message: 'URL do avatar não fornecida' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { avatar },
      { new: true }
    ).select('-senha');

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Avatar atualizado com sucesso', user });
  } catch (error) {
    console.error('Erro ao atualizar avatar:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
}); 