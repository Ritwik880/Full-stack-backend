const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  image: {
    type: String, // You can store the image URL here
  },
  age: {
    type: Number,
  },
  bio: {
    type: String,
  },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
