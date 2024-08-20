// models/issue.js
const mongoose = require("mongoose");

const issueSchema = new mongoose.Schema({
  summary: { type: String, required: true },
  description: { type: String, required: true },
  userDetails: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  projectDetails: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "project",
    required: true,
  },
  issueKey: { type: String, unique: true, required: true },
  status: {
    type: String,
    enum: [
      "Open",
      "In Progress",
      "Testing",
      "Done",
      "OPEN",
      "IN PROGRESS",
      "TESTING",
      "DONE",
    ],
    default: "Open",
  },
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Comment" }],
});

const Issue = mongoose.model("Issue", issueSchema);

module.exports = Issue;
