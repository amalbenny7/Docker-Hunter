const express = require("express");
const cors = require("cors");
const connectToDb = require("./config/db");
const dotenv = require("dotenv");
const user = require("./routes/user");
const issueRoutes = require("./routes/issue");
const path = require("path");
dotenv.config();

const app = express();

connectToDb();

const port = process.env.PORT || 8080;

app.use(express.json());

app.use(cors());

app.use("*", express.static(path.join(__dirname, "./public")));

app.use("/user", user);

app.use("/issue", issueRoutes);

// app.get("/", (req, res) => {
//   res.json({ status: 200, message: "API Working" });
// });

app.listen(port, "0.0.0.0", () => {
  console.log(`Server listening on all interfaces at port ${port}`);
});
