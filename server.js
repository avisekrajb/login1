require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Serve static files (HTML, CSS, JS)
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.send(`<h1>Welcome ${req.session.user.name}</h1><p>Email: ${req.session.user.email}</p><a href="/logout">Logout</a>`);
});

app.get('/check-auth', (req, res) => {
    res.json({ authenticated: !!req.session.user });
});

app.post('/signup', async (req, res) => {
    try {
        const { name, email, phone, address, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create new user
        const user = new User({
            name,
            email,
            phone,
            address,
            password: hashedPassword
        });
        
        await user.save();
        
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Create session
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email
        };
        
        res.json({ message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});