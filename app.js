const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const User = require('./models/User');
const Blog = require('./models/Blog');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({ dest: process.env.UPLOAD_DIR || 'uploads/' });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));



app.use(cors({
    origin: 'http://localhost:5173',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
}));


mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err);
    });

app.use(express.json());

// middleware to verify the token and extract user ID
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.error('Error verifying token:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
};


// Set up multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
});

// const upload = multer({ storage: storage });

// user signup route
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password, confirmPassword } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email is already registered' });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            fullName,
            email,
            password: hashedPassword,
        });
        await newUser.save();
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });
        res.status(200).json({
            message: 'User registered successfully',
            token,
            user: {
                id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                // Add other user data as needed
            },
        });
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// user login route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'User with this email does not exist' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                // Add other user data as needed
            },
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// user logout route
app.post('/api/logout', verifyToken, (req, res) => {
    res.json({ message: 'Logout successful' });
});


// get all users
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user); // Return the entire user object
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Update user details
app.put('/api/user/update', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const { fullName, age, bio } = req.body;
        const user = await User.findByIdAndUpdate(req.userId, { fullName, age, bio, image: req.file.filename }, { new: true });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User details updated successfully', user });
    } catch (error) {
        console.error('Error updating user data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Create a new blog post
app.post('/api/blogs', verifyToken, async (req, res) => {
    try {
        const { title, content, categories } = req.body;

        const userId = req.userId;

        const newBlog = new Blog({
            title,
            content,
            categories,
            author: userId,
        });

        await newBlog.save();

        res.status(200).json(newBlog);
    } catch (error) {
        console.error('Error creating blog:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Get all blog posts
app.get('/api/blogs', async (req, res) => {
    try {
        const blogs = await Blog.find().populate('author', 'fullName email');
        res.status(200).json(blogs);
    } catch (error) {
        console.error('Error fetching blogs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//delete blog
app.delete('/api/blogs/:id', verifyToken, async (req, res) => {
    try {
        const blogId = req.params.id;
        const userId = req.userId;

        const blog = await Blog.findOne({ _id: blogId, author: userId });

        if (!blog) {
            return res.status(404).json({ error: 'Blog not found or unauthorized' });
        }

        await Blog.deleteOne({ _id: blogId });

        res.status(200).json({ message: 'Blog deleted successfully' });
    } catch (error) {
        console.error('Error deleting blog:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
