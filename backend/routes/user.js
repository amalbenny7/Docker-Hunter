const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const validateToken = require("../middlewares/ValidateToken");
const mongoose = require("mongoose");
const Validator = require("../middlewares/Validator");
const User = require("../model/User");
const Tokens = require("../model/Tokens");
const axios = require("axios");
const NodeCache = require("node-cache");

dotenv.config();

const router = express.Router();
const cache = new NodeCache(); // In-memory cache for performance

router.post("/signup", Validator("signup"), async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check cache for existing user
    const cachedUser = cache.get(email);
    if (cachedUser) {
      return res.status(400).json({ message: "Email already registered.", status: false });
    }

    const emailExist = await User.findOne({ email: email });
    if (emailExist) {
      cache.set(email, emailExist, 3600); // Cache for 1 hour
      return res.status(400).json({ message: "Email already registered.", status: false });
    }

    // Fetch avatar image from the URL with a timeout
    const avatarResponse = await axios.get("https://joesch.moe/api/v1/random", {
      responseType: "arraybuffer",
      timeout: 5000, // 5 seconds timeout
    });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username: null,
      email: email,
      password: hashedPassword,
      avatar: {
        data: avatarResponse.data,
        contentType: "image/jpeg",
      },
    });

    const user = await newUser.save();

    const newToken = new Tokens({
      userId: user._id,
      accessToken: generateToken(user),
      refreshToken: generateRefreshToken(user),
    });

    await newToken.save();

    const expirationTime = Math.floor(Date.now() / 1000) + 24 * 60 * 60;

    res.status(201).json({
      message: "User registered successfully.",
      accessToken: newToken.accessToken,
      refreshToken: newToken.refreshToken,
      status: true,
      userId: user._id,
      username: user.username,
      avatar: user.avatar,
      expiresAt: expirationTime,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error", status: false });
  }
});

router.post("/login", Validator("login"), async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(401).json({ message: "Incorrect email or password.", status: false });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Incorrect email or password.", status: false });
    }

    const accessToken = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    const newToken = await updateToken({
      res,
      userId: user._id,
      refreshToken,
      accessToken,
    });

    const expirationTime = Math.floor(Date.now() / 1000) + 24 * 60 * 60;

    res.header("Authorization", `Bearer ${newToken.accessToken}`)
      .status(200)
      .json({
        message: "User logged in successfully.",
        accessToken: newToken.accessToken,
        refreshToken: newToken.refreshToken,
        status: true,
        userId: user._id,
        username: user.username,
        avatar: user.avatar,
        expiresAt: expirationTime,
      });
  } catch (err) {
    res.status(500).json({ message: err.message, status: false });
  }
});

router.get("/getUser", validateToken, async (req, res) => {
  const decodedToken = req.user;
  try {
    const user = await User.findById(decodedToken.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found.", status: false });
    }

    return res.status(200).json({
      message: "User details successfully found.",
      status: true,
      userId: user._id,
      username: user.username,
      avatar: user.avatar,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: false });
  }
});

router.get("/refresh-token", async (req, res) => {
  const { refreshToken } = req.query;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token found.", status: false });
  }

  try {
    let user;
    try {
      user = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
      if (err.message === "invalid signature") {
        return res.status(498).json({ message: "Invalid Token", status: false });
      }
      return res.status(498).json({ message: err.message, status: false });
    }

    const newAccessToken = generateToken(user);
    const newRefreshToken = generateRefreshToken(user);

    const tokenInDB = await Tokens.findOne({
      $and: [{ userId: user.userId }, { refreshToken: refreshToken }],
    });

    if (!tokenInDB) {
      return res.status(404).json({
        message: "User or Token doesn't exist in the DB",
        status: false,
      });
    }

    const newToken = await updateToken({
      res,
      userId: user.userId,
      refreshToken: newRefreshToken,
      accessToken: newAccessToken,
    });

    const expirationTime = Math.floor(Date.now() / 1000) + 24 * 60 * 60;

    res.header("Authorization", `Bearer ${newToken.accessToken}`)
      .status(201)
      .json({
        accessToken: newToken.accessToken,
        refreshToken: newToken.refreshToken,
        status: true,
        expiresAt: expirationTime,
      });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message, status: false });
  }
});

router.put("/addUsername", validateToken, async (req, res) => {
  const username = req.body.username;
  const decodedToken = req.user;

  try {
    const updatedUser = await User.findByIdAndUpdate(decodedToken.userId, {
      username: username,
    }, { new: true });

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found.", status: false });
    }

    return res.status(200).json({ message: "Username added successfully", status: true });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: false });
  }
});

router.post("/checkUsername", validateToken, async (req, res) => {
  const username = req.body.username;

  try {
    const user = await User.findOne({ username: username });

    if (user) {
      return res.status(400).json({
        message: "Username is not available",
        isAvailable: false,
        status: false,
      });
    }

    res.status(200).json({
      message: "Username is available",
      isAvailable: true,
      status: true,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: false });
  }
});

router.delete("/delete", validateToken, async (req, res) => {
  try {
    const userID = req.user.userId;

    const userResult = await User.findByIdAndDelete(userID);
    if (!userResult) {
      return res.status(404).json({ message: "User not found" });
    }

    const tokenResult = await Tokens.deleteMany({ userId: userID });
    if (tokenResult.deletedCount === 0) {
      return res.status(404).json({ message: "No tokens found for user" });
    }

    res.status(200).json({ message: "User and associated tokens deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

const updateToken = async ({ res, userId, accessToken, refreshToken }) => {
  try {
    const newToken = await Tokens.findOneAndUpdate(
      { userId: userId },
      { $set: { accessToken: accessToken, refreshToken: refreshToken } },
      { new: true }
    );

    if (!newToken) {
      return res.status(404).json({
        message: "No Token found in the database for the user",
        status: false,
      });
    }

    return newToken;
  } catch (err) {
    return res.status(503).json({ message: err.message, status: false });
  }
};

const generateToken = (user) => {
  return jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "24h",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({userId: user._id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "15d",
  });
};

module.exports = router;