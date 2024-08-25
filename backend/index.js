const express = require("express");
const cors = require("cors");
const connectToDb = require("./config/db");
const dotenv = require("dotenv");
const user = require("./routes/user");
const issueRoutes = require("./routes/issue");
const path = require("path")

dotenv.config();

const app = express();

connectToDb();

const port = process.env.PORT || 8080;


app.use(express.static(path.join(__dirname,"public")))

app.use(express.json());

app.use(cors());



app.use("/API/user", user);

app.use("/API/issue", issueRoutes);

app.get("/API", (req, res) => {
  res.json({ status: 200, message: "API Working" });
});

app.get("*", (req,res) => {
  res.sendFile(path.join(__dirname,"public"))
})

app.listen(port, '0.0.0.0', () => {
  console.log(`Server is up and running at port ${port}`);
});
