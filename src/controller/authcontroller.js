const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const ms = require('ms');

const prisma = new PrismaClient();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Common configuration for cross-site cookies in production
 */
/**
 * Cookie options helper
 * Works for localhost (HTTP) and production (HTTPS)
 */
const getCookieOptions = (maxAge, httpOnly = true) => {
  const isProduction = process.env.NODE_ENV === 'production';
  return {
    httpOnly,
    secure: isProduction,     // must be true on Vercel HTTPS
    sameSite: 'None',         // always None for cross-site cookies
    path: '/',                // good practice for clarity
    maxAge,
  };
};


/**
 * Middleware to verify the accessToken and attach user ID to req.user.
 */
exports.authMiddleware = (req, res, next) => {
  const accessToken = req.cookies.accessToken;
  if (!accessToken) {
    return res.status(401).json({ message: 'Unauthorized: No access token provided.' });
  }
  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    req.user = { id: decoded.id };
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
    
    // Use JWT_TEMP_SECRET for separation of concerns
    const tempTokenExpiry = '1d';
    const tempToken = jwt.sign({ email }, process.env.JWT_TEMP_SECRET, { 
        expiresIn: tempTokenExpiry
    });
    const tempTokenMs = ms(tempTokenExpiry);
    
    // ✅ FIX APPLIED: Using common cookie options for cross-site access
    res.cookie('temp-token', tempToken, getCookieOptions(tempTokenMs));

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
    const decoded = jwt.verify(tempToken, process.env.JWT_TEMP_SECRET); 
    const { email } = decoded;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    
    // Clear the temporary cookie
    // ✅ FIX APPLIED: Use updated cookie options for clearing
    res.clearCookie('temp-token', getCookieOptions(0));

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
    // ✅ FIX APPLIED: Using updated cookie options
    res.cookie('accessToken', accessToken, getCookieOptions(accessExpiryMs));
    
    // 5. Set Refresh Token as cookie
    // ✅ FIX APPLIED: Using updated cookie options
    res.cookie('refreshToken', refreshToken, getCookieOptions(refreshExpiryMs));

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
      // ✅ FIX APPLIED: Using updated cookie options for clearing
      res.clearCookie('accessToken', getCookieOptions(0));
      res.clearCookie('refreshToken', getCookieOptions(0));
      return res.status(403).json({ message: 'Forbidden: Invalid refresh token.' });
    }
    
    // 4. Check if refresh token is expired (DB expiry check)
    if (user.refreshTokenExpiresAt < new Date()) {
      await prisma.user.update({
        where: { id: userId },
        data: { refreshTokenHash: null, refreshTokenExpiresAt: null },
      });
      // ✅ FIX APPLIED: Using updated cookie options for clearing
      res.clearCookie('accessToken', getCookieOptions(0));
      res.clearCookie('refreshToken', getCookieOptions(0));
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
    // ✅ FIX APPLIED: Using updated cookie options
    res.cookie('accessToken', newAccessToken, getCookieOptions(accessExpiryMs));

    res.status(200).json({ message: 'Access token refreshed successfully.' });

  } catch (error) {
    console.error('Refresh Token Error:', error);
    // Token verification failed (e.g., signature invalid)
    // ✅ FIX APPLIED: Using updated cookie options for clearing
    res.clearCookie('accessToken', getCookieOptions(0));
    res.clearCookie('refreshToken', getCookieOptions(0));
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
  // This route relies on req.user.id set by authMiddleware
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
      // SECURITY FIX: Use verify instead of decode to ensure the token is valid
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
  // ✅ FIX APPLIED: Use updated cookie options for clearing
  res.clearCookie('accessToken', getCookieOptions(0));
  res.clearCookie('refreshToken', getCookieOptions(0));
  
  res.status(200).json({ message: 'Logged out successfully.' });
};


