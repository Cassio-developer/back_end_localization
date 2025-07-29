const mongoose = require('mongoose');

const LocationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  latitude: {
    type: Number,
    required: true
  },
  longitude: {
    type: Number,
    required: true
  },
  accuracy: {
    type: Number
  },
  timestamp: {
    type: Date,
    required: true
  },
  source: {
    type: String,
    enum: ['realtime', 'background-sync', 'manual'],
    default: 'realtime'
  },
  altitude: {
    type: Number
  },
  heading: {
    type: Number
  },
  speed: {
    type: Number
  }
}, {
  timestamps: true
});

// Índices para melhor performance
LocationSchema.index({ userId: 1, timestamp: -1 });
LocationSchema.index({ timestamp: -1 });

module.exports = mongoose.model('Location', LocationSchema); 