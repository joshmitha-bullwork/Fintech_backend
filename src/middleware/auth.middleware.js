const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const protect = async (req, res, next) => {
  let token; // This is the ACCESS TOKEN

  // 1. Check for token in Authorization header
  if (req.headers.authorization?.startsWith('Bearer')) { 
    try {
      token = req.headers.authorization.split(' ')[1];
    } catch (error) {
      console.error('Error parsing token from header:', error);
      return res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } 
  // 2. Fallback to check for token in cookies (check for 'accessToken')
  else if (req.cookies.accessToken) { // 💡 CHANGED from req.cookies.token
    token = req.cookies.accessToken;
  }

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no access token' });
  }

  try {
    // 💡 Verify Access Token with JWT_ACCESS_SECRET
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET); 
    req.user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true },
    });

    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized, user not found' });
    }
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    // Client-side logic should call the /refresh-token endpoint if this error occurs
    res.status(401).json({ message: 'Not authorized, access token expired or invalid' });
  }
};

module.exports = { protect };