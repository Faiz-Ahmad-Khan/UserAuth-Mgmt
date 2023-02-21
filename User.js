const mongoose= require('mongoose');
  const userSchema = new mongoose.Schema({
    email: { type: String, required: true },
    mobile_number: { type: String, required: true },
    full_name: { type: String, required: true },
    password : { type: String, required: true },
  });
 
  const User = mongoose.model('users', userSchema);