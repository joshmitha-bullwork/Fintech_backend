const express = require('express');
// 💡 IMPORT refreshToken
const { register, login, verifyOtp, checkAuthStatus, logout, getProfile, refreshToken } = require('../controller/autcontroller');
const { protect } = require('../middleware/auth.middleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-otp', verifyOtp);

// 💡 NEW ROUTE: To renew the access token using the refresh token cookie
router.post('/refresh-token', refreshToken);

router.get('/check-auth', checkAuthStatus);
router.post('/logout', logout);

// Protected route examples
router.get('/profile', protect, getProfile);

// Example of a protected route where the middleware is necessary
// router.get('/dashboard', protect, (req, res) => {
//   res.status(200).json({ message: `Welcome, user ${req.user.id}` });
// });

module.exports = router;
