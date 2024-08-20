const mongoose = require("mongoose");
const dotenv = require("dotenv");

dotenv.config();
const mogodbURL = process.env.MONGODB_URL;

const connectToDb = () => {
  try {
    mongoose.connect(mogodbURL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    const db = mongoose.connection;
    db.on("error", console.error.bind(console, "Database connection error: "));
    db.once("open", function () {
      console.log("Connected to database successfully");
    });
  } catch (e) {
    console.log(e);
    throw e;
  }
};

module.exports = connectToDb;
