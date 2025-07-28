const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
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
  avatar: {
    type: String,
    default: ''
  },
  // Campos para reconhecimento facial
  faceDescriptors: {
    type: [[Number]], // Array de arrays de números (descritores faciais)
    default: undefined,
    select: false // Não incluir por padrão nas consultas
  },
  faceDataUpdatedAt: {
    type: Date,
    default: undefined
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Índices para otimizar consultas
UserSchema.index({ nome: 1 });
UserSchema.index({ isAdmin: 1 });
UserSchema.index({ 'faceDescriptors.0': { $exists: true } }); // Índice para usuários com dados faciais

// Método para verificar se usuário tem dados faciais
UserSchema.methods.hasFaceData = function() {
  return this.faceDescriptors && this.faceDescriptors.length > 0;
};

// Método para limpar dados faciais
UserSchema.methods.clearFaceData = function() {
  this.faceDescriptors = undefined;
  this.faceDataUpdatedAt = undefined;
  return this.save();
};

module.exports = mongoose.model('User', UserSchema); 