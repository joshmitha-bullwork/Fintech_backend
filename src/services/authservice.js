// src/services/emailService.js (Renamed from .ts)
import nodemailer from 'nodemailer';
// Removed: import { User } from '@prisma/client'; 
// (The type import is not needed in plain JS)

// Configure transporter using Gmail details from .env
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE, // e.g., 'gmail'
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // This should be an App Password if using Gmail
    },
});

// 🟢 FIX: Removed the TypeScript type annotation (user: User)
export const sendOtpEmail = async (user) => {
    // The code assumes the 'user' object has 'otp' and 'email' properties.
    if (!user.otp) return;
    
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: 'Your One-Time Password (OTP) for Verification',
        html: `
            <h1>Account Verification</h1>
            <p>Hello ${user.email},</p>
            <p>Your OTP is: <strong>${user.otp}</strong></p>
            <p>This code is valid for 5 minutes.</p>
        `,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`OTP sent to ${user.email}`);
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Failed to send verification email. Check nodemailer configuration.');
    }
};