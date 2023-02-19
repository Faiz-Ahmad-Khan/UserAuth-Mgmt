const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');
require('./config');
const User = require("./User");
const app = express();
app.use(express.json());
const secretKey = 'mysecretkey';

app.post('/signup', async (req, res) => {
    try {
        const { email, mobile_number, full_name, password } = req.body;
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const encryptedMobileNumber = encryptWithPublicKey(mobile_number);
        const encryptedFullName = encryptWithPublicKey(full_name);
        const user = new User({ email, encryptedMobileNumber, encryptedFullName, hashedPassword });
        await user.save();
        res.json({ message: 'User created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/reset_password', async (req, res) => {
    try {
        const { email, old_password, new_password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const passwordMatch = await bcrypt.compare(old_password, user.hashedPassword);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(new_password, saltRounds);
        await User.updateOne({ _id: user._id }, { hashedPassword });
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const passwordMatch = await bcrypt.compare(password, user.hashedPassword);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const tokenPayload = { user_id: user._id, email: user.email, mobile_number: decryptWithPrivateKey(user.encryptedMobileNumber) };
        const token = jwt.sign(tokenPayload, secretKey);
        res.json({ token, ...tokenPayload });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email, mobile_number, full_name } = req.body;
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (email) {
            user.email = email;
        }
        if (mobile_number) {
            user.encryptedMobileNumber = encryptWithPublicKey(mobile_number);
        }
        if (full_name) {
            user.encryptedFullName = encryptWithPublicKey(full_name);
        }
        await user.save();
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

function encryptWithPublicKey(data) {
    const publicKey = fs.readFileSync('public.key', 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data));
    return encrypted.toString('base64');
}

function decryptWithPrivateKey(data) {
    const privateKey = fs.readFileSync('private.key', 'utf8');
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(data, 'base64'));
    return decrypted.toString('utf8');
}

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});