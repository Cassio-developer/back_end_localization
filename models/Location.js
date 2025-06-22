const mongoose = require('mongoose');

const LocationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  lat: {
    type: Number,
    required: true
  },
  lng: {
    type: Number,
    required: true
  },
  accuracy: {
    type: Number
  },
  timestamp: {
    type: Date,
    required: true
  }
});

module.exports = mongoose.model('Location', LocationSchema); 