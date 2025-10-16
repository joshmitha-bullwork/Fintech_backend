const express = require('express');
const dotenv = require('dotenv');
// NOTE: You are using Mongoose/MongoDB here, but Prisma in authController.js. 
// This setup might cause conflicts. For now, we fix the routing issue.
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
const allowedOrigins = [
    'http://localhost:3000',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URL); 
    console.log('✅ MongoDB connected successfully!');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
};
// NOTE: Since your auth controller uses Prisma (and MongoDB URL), 
// connecting Mongoose here might be redundant or conflicting.
connectDB();

// -----------------
// ROUTES
// -----------------
const authRoutes = require('./src/routes/authroute');
app.use('/api/auth', authRoutes);

// 💡 FIX 1: Use require() to import the ES module, then access the .default property.
// The file src/routes/chat uses 'export default', which is imported as module.exports.default in CommonJS.
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
