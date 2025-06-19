const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

let localizacoes = {};

io.on('connection', (socket) => {
  console.log('Novo usuário conectado:', socket.id);

  socket.on('localizacao', (data) => {
    localizacoes[socket.id] = data;
    
    io.emit('localizacoes', localizacoes);
  });

  socket.on('disconnect', () => {
    delete localizacoes[socket.id];
    io.emit('localizacoes', localizacoes);
    console.log('Usuário desconectado:', socket.id);
  });
});

app.get('/', (req, res) => {
  res.send('Servidor de rastreamento em tempo real está rodando!');
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
}); 