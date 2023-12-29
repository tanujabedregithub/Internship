1.  Signup
const User = require('../models/user');
const bcrypt = require('bcrypt');
const saltRounds = 10;

exports.signup = async (req, res) => {
 try {
    const { name, email, phoneNumber, password, profileImage } = req.body;

    if (!name || !email && !phoneNumber || !password) {
      return res.status(400).json({ error: 'Please fill all required fields' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      name,
      email,
      phoneNumber,
      password: hashedPassword,
      profileImage,
    });

    await newUser.save();

    return res.status(201).json({ message: 'User created successfully' });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

2] Login
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');

passport.use(
 new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });

        if (!user) {
          return done(null, false, { message: 'Incorrect email.' });
        }

        const isValidPassword = await user.isValidPassword(password);

        if (!isValidPassword) {
          return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
      } catch (error) {
        console.error(error);
        return done(error);
      }
    }
 )
);   
exports.login = passport.authenticate('local', {
 successRedirect: '/dashboard',
 failureRedirect: '/login',
 failureFlash: true,
});

Modify User Details:
exports.updateUser = async (req, res) => {
 try {
    const userId = req.user._id;
    const { name, profileImage } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { name, profileImage },
      { new: true }
    );

    return res.status(200).json({ user: updatedUser });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

 Delete User:
 exports.deleteUser = async (req, res) => {
 try {
    const userId = req.user._id;

    await User.findByIdAndDelete(userId);

    return res.status(200).json({ message: 'User deleted successfully' });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

Verify User's Email:
const nodemailer = require('nodemailer');

exports.sendVerificationEmail = async (req, res) => {
 try {
    const { name, email } = req.user;
    const verificationCode = req.user.generateVerificationCode();

    await req.user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'your-email@gmail.com',
        pass: 'your-password',
      },
    });

    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Please verify your email',
      text: `Hello ${name},\n\nPlease verify your email by clicking the link below:\nhttp://localhost:3000/verify-email/${verificationCode}\n\nThank you!`,
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({ message: 'Verification email sent successfully' });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

exports.verifyEmail = async (req, res) => {
 try {
    const user = await User.findOne({ verificationCode: req.params.verificationCode });

    if (!user) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({ message: 'Email verified successfully' });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

Forgot Password and Reset Password:
// In auth.js controller

exports.forgotPassword = async (req, res) => {
 try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const resetPasswordCode = user.generateResetPasswordCode();
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'your-email@gmail.com',
        pass: 'your-password',
      },
    });

    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Password Reset',
      text: `Hello ${user.name},\n\nPlease reset your password by clicking the link below:\nhttp://localhost:3000/reset-password/${resetPasswordCode}\n\nIf you did not request this, please ignore this email.\n\nThank you!`,
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({ message: 'Password reset email sent successfully' });
 } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
 }
};

exports.resetPassword = async (req, res) => {
 try {
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await User.findOne({ resetPasswordCode: req.params.resetPasswordCode });

    if (!user) {
      return res.status(400).json({ error: 'Invalid reset password code' });

      
 
