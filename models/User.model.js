const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema(
  {
    username: {
      type: String,
      // unique: true -> try to implement later
    },
    password: String,
    externalSource: String,
    externalId: String,
    image: String,
    email: String,
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model('User', userSchema);
module.exports = User;
