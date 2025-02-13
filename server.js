const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/blogplatform', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  // tokens: [{ token: String }], // Store tokens in DB
});
const User = mongoose.model('User', userSchema);

// Blog Schema
const blogSchema = new mongoose.Schema({
  title: String,
  content: String,
  tags: [String],
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Blog = mongoose.model('Blog', blogSchema);

// Middleware for authentication (Fixed)
const authenticate = async (req, res, next) => {
  const tokenHeader = req.header('Authorization');
  if (!tokenHeader) return res.status(401).json({ error: 'Access Denied. No token provided.' });

  try {
    const token = tokenHeader.split(' ')[1]; // Extract token after "Bearer"
    if (!token) return res.status(401).json({ error: 'Invalid Token Format' });

    const verified = jwt.verify(token, 'secretKey');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid Token' });
  }
};

// Register User (Fixed)
app.post('/users', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      // tokens: []
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error in user registration:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login User (Fixed, Store Token in DB)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ error: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ _id: user._id }, 'secretKey', { expiresIn: '1h' });
    user.tokens.push({ token }); // Store token in DB
    await user.save();

    res.json({
      message: 'Login successful',
      token: `Bearer ${token}`,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete User (Fixed)
app.delete('/users', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    await Blog.deleteMany({ author: req.user._id }); // Delete user's blogs
    await User.findByIdAndDelete(req.user._id); // Delete user

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Blog (Fixed - Ensures User is Authenticated)
app.post('/blogs', authenticate, async (req, res) => {
  try {
    const { title, content, tags } = req.body;

    if (!title || !content ) {
      return res.status(400).json({ error: 'Title and Content are required' });
    }

    const blog = new Blog({
      title,
      content,
      tags,
      author: req.user._id
    });

    await blog.save();
    res.status(201).json({ message: 'Blog created successfully', blog });
  } catch (error) {
    console.error('Blog creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Get All Blogs
app.get('/blogs', async (req, res) => {
  const blogs = await Blog.find().populate('author', 'username email');
  res.json(blogs);
});

// Get Single Blog by ID
app.get('/blogs/:id', async (req, res) => {
  const blog = await Blog.findById(req.params.id).populate('author', 'username email');
  if (!blog) return res.status(404).send('Blog not found');
  res.json(blog);
});

// Update Blog (Only Owner)
app.put('/blogs/:id', authenticate, async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (!blog) return res.status(404).send('Blog not found');
  if (blog.author.toString() !== req.user._id) return res.status(403).send('Access denied');
  
  blog.title = req.body.title || blog.title;
  blog.content = req.body.content || blog.content;
  blog.tags = req.body.tags || blog.tags;
  await blog.save();
  res.send('Blog updated successfully');
});

// Delete Blog (Only Owner)
app.delete('/blogs/:id', authenticate, async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (!blog) return res.status(404).send('Blog not found');
  if (blog.author.toString() !== req.user._id) return res.status(403).send('Access denied');
  
  await blog.remove();
  res.send('Blog deleted successfully');
});

// Start Server
const PORT = 80;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
