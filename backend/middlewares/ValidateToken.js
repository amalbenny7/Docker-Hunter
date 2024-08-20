const jwt = require("jsonwebtoken");
const User = require("../model/User");
const Tokens = require("../model/Tokens");
const mongoose = require("mongoose");

module.exports = validateToken = async (req, res, next) => {
  const authorization = req.header("Authorization");
  if (!authorization)
    return res
      .status(401)
      .json({ status: false, message: "No token provided." });
  const token = authorization.split(" ")[1];

  if (!token && token === null)
    return res
      .status(401)
      .json({ message: "Access denied. No token found.", status: false });

  let verifiedToken;

  try {
    verifiedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    if (!verifiedToken)
      return res.status(401).json({ message: "Token expired", status: false });
  } catch (err) {
    return res.status(401).json({ message: err.message, status: false });
  }

  if (verifiedToken.exp < Date.now() / 1000)
    return res.status(401).json({ message: "Token expired", status: false });

  if (!mongoose.Types.ObjectId.isValid(verifiedToken.userId))
    return res.status(401).json({
      message: "Something wrong with UserId.",
      status: false,
    });

  let user;
  let userToken;
  try {
    user = await User.findOne({ userId: verifiedToken.userId });
    userToken = await Tokens.findOne({ userId: verifiedToken.userId });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: false });
  }

  if (!user)
    return res.status(404).json({ message: "User not found.", status: false });

  if (!userToken)
    return res.status(404).json({ message: "User not found.", status: false });

  if (token !== userToken.accessToken)
    return res.status(401).json({
      message: "Invalid Token",
      status: false,
    });

  req.user = verifiedToken;
  next();
};
