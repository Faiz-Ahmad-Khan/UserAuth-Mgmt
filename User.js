const mongoose= require('mongoose');
  const userSchema = new mongoose.Schema({
    email: { type: String, required: true },
    encryptedMobileNumber: { type: String, required: true },
    encryptedFullName: { type: String, required: true },
    hashedPassword: { type: String, required: true },
  });
 
  const User = mongoose.model('User', userSchema);