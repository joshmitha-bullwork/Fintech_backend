const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const ms = require('ms'); // ✅ FIX: ms is properly required here

const prisma = new PrismaClient();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Middleware to verify the accessToken and attach user ID to req.user.
 * This is crucial for protected routes like getProfile.
 */
exports.authMiddleware = (req, res, next) => {
  const accessToken = req.cookies.accessToken;
  if (!accessToken) {
    return res.status(401).json({ message: 'Unauthorized: No access token provided.' });
  }
  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    req.user = { id: decoded.id }; // Attach user ID for protected routes
    next();
  } catch (error) {
    res.status(401).json({ message: 'Unauthorized: Invalid or expired access token.' });
  }
};

exports.register = async (req, res) => {
  const { name, email, phoneNumber } = req.body;
  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists.' });
    }
    await prisma.user.create({
      data: { 
        name, 
        email, 
        phoneNumber, 
        isVerified: false,
      },
    });
    res.status(201).json({ message: 'User registered successfully. You can now log in.' });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.login = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES) || 10;
    const otpExpiresAt = new Date(Date.now() + otpExpiryMinutes * 60 * 1000);

    await prisma.user.update({
      where: { email },
      data: { otp, otpExpiresAt },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your Login OTP',
      text: `Your OTP is ${otp}. It is valid for ${otpExpiryMinutes} minutes.`,
    });
    
    // ✅ IMPROVEMENT: Use JWT_TEMP_SECRET for separation of concerns
    const tempTokenExpiry = '1d';
    const tempToken = jwt.sign({ email }, process.env.JWT_TEMP_SECRET, { 
        expiresIn: tempTokenExpiry
    });
    
    res.cookie('temp-token', tempToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax', 
      maxAge: ms(tempTokenExpiry), // Use ms for consistency
    });

    res.status(200).json({ message: 'OTP sent to your email.' });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.verifyOtp = async (req, res) => {
  const { otp } = req.body;
  const tempToken = req.cookies['temp-token'];

  if (!tempToken) {
    return res.status(401).json({ message: 'Unauthorized: No session token provided.' });
  }

  try {
    // Note: The temporary token is verified against the TEMP_SECRET
    const decoded = jwt.verify(tempToken, process.env.JWT_TEMP_SECRET); 
    const { email } = decoded;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    
    // Clear the temporary cookie
    res.clearCookie('temp-token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    });

    // 1. Generate Access Token (Short-lived)
    const accessExpiryTime = process.env.ACCESS_TOKEN_EXPIRY || '15m';
    const accessToken = jwt.sign(
      { id: user.id }, 
      process.env.JWT_ACCESS_SECRET, 
      { expiresIn: accessExpiryTime }
    );
    const accessExpiryMs = ms(accessExpiryTime);

    // 2. Generate Refresh Token (Long-lived)
    const refreshExpiryTime = process.env.REFRESH_TOKEN_EXPIRY || '7d';
    const refreshToken = jwt.sign(
      { id: user.id }, 
      process.env.JWT_REFRESH_SECRET, 
      { expiresIn: refreshExpiryTime }
    );
    const refreshExpiryMs = ms(refreshExpiryTime);

    // 3. Hash and store Refresh Token and its expiry in the DB
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshTokenExpiresAt = new Date(Date.now() + refreshExpiryMs);

    await prisma.user.update({
      where: { email },
      data: { 
        isVerified: true, 
        otp: null, 
        otpExpiresAt: null,
        refreshTokenHash,
        refreshTokenExpiresAt,
      },
    });

    // 4. Set Access Token as cookie
    res.cookie('accessToken', accessToken, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: accessExpiryMs,
    });
    
    // 5. Set Refresh Token as cookie
    res.cookie('refreshToken', refreshToken, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: refreshExpiryMs,
    });

    res.status(200).json({ message: 'Verification successful.' });
  } catch (error) {
    console.error('Verify OTP Error:', error);
    if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Session expired. Please log in again.' });
    }
    res.status(500).json({ error: 'Server error' });
  }
};

// --- Refresh Token Endpoint ---
exports.refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Unauthorized: No refresh token provided.' });
  }

  try {
    // 1. Verify Refresh Token signature
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const userId = decoded.id;

    // 2. Look up user and refresh token details
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, refreshTokenHash: true, refreshTokenExpiresAt: true },
    });

    if (!user) {
      return res.status(403).json({ message: 'Forbidden: User not found.' });
    }

    // 3. Compare the request's refresh token with the stored hash
    const incomingRefreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    
    if (user.refreshTokenHash !== incomingRefreshTokenHash) {
      // Security: Token mismatch (possible token theft), clear all tokens.
      await prisma.user.update({
        where: { id: userId },
        data: { refreshTokenHash: null, refreshTokenExpiresAt: null },
      });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(403).json({ message: 'Forbidden: Invalid refresh token.' });
    }
    
    // 4. Check if refresh token is expired (DB expiry check)
    if (user.refreshTokenExpiresAt < new Date()) {
      await prisma.user.update({
        where: { id: userId },
        data: { refreshTokenHash: null, refreshTokenExpiresAt: null },
      });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(403).json({ message: 'Forbidden: Refresh token expired. Log in again.' });
    }

    // 5. Generate a NEW Access Token
    const accessExpiryTime = process.env.ACCESS_TOKEN_EXPIRY || '15m';
    const newAccessToken = jwt.sign(
      { id: user.id }, 
      process.env.JWT_ACCESS_SECRET, 
      { expiresIn: accessExpiryTime }
    );
    const accessExpiryMs = ms(accessExpiryTime);

    // 6. Set the NEW Access Token cookie
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: accessExpiryMs,
    });

    res.status(200).json({ message: 'Access token refreshed successfully.' });

  } catch (error) {
    console.error('Refresh Token Error:', error);
    // Token verification failed (e.g., signature invalid)
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(403).json({ message: 'Forbidden: Invalid or manipulated token.' });
  }
};


exports.checkAuthStatus = (req, res) => {
  // This route is now redundant if you use the authMiddleware for actual data retrieval
  const accessToken = req.cookies.accessToken;
  if (!accessToken) {
    return res.status(401).json({ message: 'Unauthorized: No access token provided.' });
  }
  try {
    jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET); 
    res.status(200).json({ message: 'User is authenticated.' });
  } catch (error) {
    res.status(401).json({ message: 'Unauthorized: Invalid or expired access token.' });
  }
};

exports.getProfile = async (req, res) => {
  // ✅ FIX: This route relies on req.user.id set by authMiddleware
  try {
    const userId = req.user.id; 

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        name: true,
        email: true,
        phoneNumber: true,
      },
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error('Failed to get user profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  
  if (refreshToken) {
    try {
      // ✅ SECURITY FIX: Use verify instead of decode to ensure the token is valid
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      // 1. Invalidate refresh token in DB
      if (decoded && decoded.id) {
        await prisma.user.update({
          where: { id: decoded.id },
          data: { refreshTokenHash: null, refreshTokenExpiresAt: null },
        });
      }
    } catch (error) {
      console.error('Logout token verification failed:', error.message);
      // Even if verification fails, we still proceed to clear the user's cookies.
    }
  }

  // Clear both cookies
  res.clearCookie('accessToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  });
  
  res.status(200).json({ message: 'Logged out successfully.' });
};