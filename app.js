const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const sanitize = require('dompurify');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB Atlas');
});

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  email: { type: String, unique: true },
  name: String,
});
const User = mongoose.model('User', userSchema);

// Define Ticket schema
const ticketSchema = new mongoose.Schema({
  ticketId: String,
  ticketData: [],
});
const Ticket = mongoose.model('Ticket', ticketSchema);

// Register API
app.post(
  '/register',
  [
    body('username').trim().notEmpty(),
    body('password').isLength({ min: 6 }),
    body('email').isEmail().normalizeEmail(),
    body('name').trim().notEmpty(),
  ],
  async (req, res, next) => {
    try {
      // Check validation results
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { username, password, email, name } = req.body;

      // Check if the username or email already exists
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).json({ message: 'Username or email already exists' });
      }

      // Create a new user
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await User.create({ username, password: hashedPassword, email, name });

      res.json({ message: 'User registered successfully' });
    } catch (error) {
      next(error);
    }
  }
);

// Login API
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate token
    const token = jwt.sign({ username: user.username }, 'secret-key');

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Verify Token Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided' });
  }

  jwt.verify(token, 'secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    req.username = decoded.username;
    next();
  });
};

// Logout API
app.post('/logout', verifyToken, (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    // Check if the token is missing
    if (!token) {
      return res.status(401).json({ message: 'User is already logged out' });
    }

    // Clear token from client-side by setting an empty token in the response headers
    res.setHeader('Authorization', '');

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' });
  }
});


// Tambula Ticket Create API
app.post('/tickets', verifyToken, async (req, res) => {
  const { numTickets } = req.body;

  try {
    // Generate unique tickets
    const tickets = [];
    for (let i = 0; i < numTickets; i++) {
      const newTicket = generateTicket();
      const ticketId = generateUniqueTicketId();

      // Store ticket in the database
      await Ticket.create({ ticketId, ticketData: newTicket });

      tickets.push({ ticketId, ticketData: newTicket });
    }

    res.json(tickets);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Helper function to generate a unique ticket ID
const generateUniqueTicketId = () => {
  // Generate a unique ticket ID using a timestamp and random number
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substr(2, 5);
  return `${timestamp}${random}`;
};


// Tambula Ticket Fetch API
app.get('/tickets/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { page, limit } = req.query;

  try {
    // Retrieve tickets based on the ID and pagination options
    const tickets = await Ticket.find({ ticketId: id })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json(tickets);
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' });
  }
});


// Helper function to generate a unique ticket
const generateTicket = () => {
  // Generate ticket data based on the Tambula rules
  const columns = [[], [], [], [], [], [], [], [], []];

  for (let i = 1; i <= 90; i++) {
    const column = Math.floor((i - 1) / 10);
    columns[column].push(i);
  }

  const ticketData = [];
  for (let i = 0; i < 3; i++) {
    const row = [];
    for (let j = 0; j < 9; j++) {
      if (columns[j].length > 0) {
        const randomIndex = Math.floor(Math.random() * columns[j].length);
        const number = columns[j].splice(randomIndex, 1)[0];
        row.push(number);
      } else {
        row.push('x');
      }
    }
    ticketData.push(row);
  }

  return ticketData;
};

// Error Handler Middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'An error occurred' });
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
