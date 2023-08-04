const mongoose = require('mongoose');

const User = mongoose.model('User', {
  login: String,
  password: String
});

module.exports = User
