const mongoose = require("mongoose");

const projectSchema = new mongoose.Schema({
  project_name: { type: String, required: true },
});

const Project = mongoose.model("project", projectSchema);

module.exports = Project;
