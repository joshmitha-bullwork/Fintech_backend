const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose'); 
const cookieParser = require('cookie-parser');
const cors = require('cors'); 


// Load environment variables
dotenv.config();

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 5000;

// ---------------------------------
// CORS Configuration (Critical Fix)
// ---------------------------------
// ✅ FIX: Added the deployed Vercel frontend domains to allow cross-origin requests
const allowedOrigins = [
    'http://localhost:3000', // Local development
    'https://fintech-nine-eta.vercel.app', // Current Vercel frontend domain
    'https://fintech-web-dashboard.vercel.app', // Target Vercel frontend domain
];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like Postman or server-to-server)
    if (!origin) return callback(null, true); 
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `The CORS policy for this site does not allow access from origin: ${origin}`;
      console.error(msg);
      // Return false to block the request
      return callback(new Error(msg), false);
    }
    // Return true to allow the request
    return callback(null, true);
  },
  // ✅ FIX: Essential for sending cookies (access/refresh tokens)
  credentials: true, 
  // ✅ FIX: Essential for handling preflight requests (POST/PUT/DELETE)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  optionsSuccessStatus: 200 // Use 200 for better compatibility
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
const connectDB = async () => {
  try {
    // NOTE: If you are using Prisma in your authController, ensure this Mongoose 
    // connection is necessary, or remove it to avoid conflicts/redundancy.
    await mongoose.connect(process.env.DATABASE_URL); 
    console.log('✅ MongoDB connected successfully!');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
};
connectDB();

// -----------------
// ROUTES
// -----------------
const authRoutes = require('./src/routes/authroute');
app.use('/api/auth', authRoutes);

// Fix 1: Use require() to import the ES module, then access the .default property.
const chatModule = require('./src/routes/chat');
const chatRoutes = chatModule.default || chatModule; 

app.use("/api/chat", chatRoutes);

// Simple protected route example
const { protect } = require('./src/middleware/auth.middleware');
app.get('/api/protected', protect, (req, res) => {
  res.json({ message: 'Welcome to the protected route!', userId: req.user.id });
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running in ${process.env.NODE_ENV} mode on port ${PORT}`));
