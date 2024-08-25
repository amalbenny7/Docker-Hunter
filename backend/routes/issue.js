const express = require("express");
const router = express.Router();
const Issue = require("../model/Issue");
const Project = require("../model/Projects");
const mongoose = require("mongoose");
const validateToken = require("../middlewares/ValidateToken");
const Comment = require("../model/Comment");
const User = require("../model/User");
const Counter = require('../model/Counter')

router.post("/init-project", async (req, res) => {
  try {
    const project = new Project({
      project_name: "Bug hunter",
    });
    await project.save();
    res.status(201).json({
      ...project.toObject(),
      status: true,
      message: "Successfully created new issue",
    });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});



router.post("/create", validateToken, async (req, res) => {
  try {
    const { summary, description, userId } = req.body;

    // Validate required fields
    if (!summary || !description || !userId) {
      return res
        .status(400)
        .json({ message: "Required fields missing", status: false });
    }

    // Validate data types and lengths
    if (typeof summary !== "string" || summary.length < 5) {
      return res.status(400).json({
        message: "Summary must be a string with at least 5 characters",
        status: false,
      });
    }
    if (typeof description !== "string" || description.length < 10) {
      return res.status(400).json({
        message: "Description must be a string with at least 10 characters",
        status: false,
      });
    }
    if (
      typeof userId !== "string" ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid userId", status: false });
    }

    // Fetch project and user in parallel
    const [firstProject, user] = await Promise.all([
      Project.findOne(),
      User.findById(userId).select("-password -createdAt -__v"),
    ]);

    // Check if the project exists
    if (!firstProject) {
      return res
        .status(404)
        .json({ message: "No projects found", status: false });
    }

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ message: "User not found", status: false });
    }

    // Atomic issue key generation
    const counter = await Counter.findOneAndUpdate(
      { name: "issue_key" },
      { $inc: { sequence_value: 1 } },
      { new: true, upsert: true } // Create if not exists
    );

    if (!counter) {
      return res.status(500).json({ message: "Failed to generate issue key", status: false });
    }

    const issueKey = `BUG-${counter.sequence_value}`;

    // Create and save the issue
    const issue = new Issue({
      summary,
      description,
      userDetails: userId,
      projectDetails: firstProject._id,
      issueKey,
    });
    await issue.save();

    res.status(201).json({
      ...issue.toObject(),
      status: true,
      message: "Successfully created new issue",
    });
  } catch (error) {
    if (error instanceof Error && error.name === "ValidationError") {
      const errors = Object.values(error.errors).map((err) => err.message);
      res
        .status(400)
        .json({ message: "Validation failed", details: errors, status: false });
    } else if (error.name === "CastError") {
      res.status(400).json({ message: "Invalid issue ID", status: false });
    } else {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error", status: false });
    }
  }
});



// Get all issues
router.get("/", async (req, res) => {
  try {
    const issues = await Issue.find()
      .populate({
        path: "userDetails",
        select: "-password -createdAt -__v", // Exclude the specified fields
      })
      .populate({ path: "projectDetails", select: "-__v" });
    res.status(200).json({
      issues: issues,
      status: true,
      message: "successfully retrived issues",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error", status: false });
  }
});

// Update issue status
router.put("/:id", validateToken, async (req, res) => {
  try {
    const { summary, description, status } = req.body;

    // Check if at least one field is provided for update
    if (!summary && !description && !status) {
      return res
        .status(400)
        .json({ message: "No fields provided for update", status: false });
    }

    // Construct the update object with provided fields
    const updateFields = {};
    if (summary) updateFields.summary = summary;
    if (description) updateFields.description = description;
    if (status) updateFields.status = status;

    const issue = await Issue.findByIdAndUpdate(req.params.id, updateFields, {
      new: true,
    });

    if (!issue) {
      res.status(404).json({ message: "Issue not found", status: false });
    } else {
      res.status(200).json({
        issue: issue,
        message: "Issue updated successfully",
        status: true,
      });
    }
  } catch (error) {
    if (error instanceof Error && error.name === "ValidationError") {
      const errors = Object.values(error.errors).map((err) => err.message);
      res
        .status(400)
        .json({ message: "Validation failed", details: errors, status: false });
    } else if (error.name === "CastError") {
      res.status(400).json({ message: "Invalid issue ID", status: false });
    } else {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error", status: false });
    }
  }
});

// Delete an issue
router.delete("/:issueKey", validateToken, async (req, res) => {
  try {
    const deletedIssue = await Issue.findOneAndDelete({
      issueKey: req.params.issueKey,
    });

    if (!deletedIssue) {
      return res
        .status(404)
        .json({ message: "Issue not found", status: false });
    }

    res
      .status(200)
      .json({ status: true, message: "Issue deleted successfully" });
  } catch (error) {
    if (error instanceof Error && error.name === "ValidationError") {
      const errors = Object.values(error.errors).map((err) => err.message);
      res
        .status(400)
        .json({ message: "Validation failed", details: errors, status: false });
    } else if (error.name === "CastError") {
      res.status(400).json({ message: "Invalid issue ID", status: false });
    } else {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error", status: false });
    }
  }
});

// Update based on issueKey
router.put("/key/:issueKey", validateToken, async (req, res) => {
  try {
    const { summary, description, status } = req.body;

    // Check if at least one field is provided for update
    if (!summary && !description && !status) {
      return res
        .status(400)
        .json({ message: "No fields provided for update", status: false });
    }

    // Construct the update object with provided fields
    const updateFields = {};
    if (summary) updateFields.summary = summary;
    if (description) updateFields.description = description;
    if (status) updateFields.status = status;

    const issue = await Issue.findOneAndUpdate(
      { issueKey: req.params.issueKey },
      updateFields,
      {
        new: true,
      }
    );

    if (!issue) {
      res.status(404).json({ message: "Issue not found", status: false });
    } else {
      res.status(200).json({
        issue: issue,
        message: "Issue updated successfully",
        status: true,
      });
    }
  } catch (error) {
    if (error instanceof mongoose.ValidationError) {
      const errors = error.errors.map((err) => err.message);
      res
        .status(400)
        .json({ message: "Validation failed", details: errors, status: false });
    } else {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error", status: false });
    }
  }
});

// GET Issue
router.get("/:issueKey", async (req, res) => {
  const { issueKey } = req.params;

  try {
    const issue = await Issue.findOne({ issueKey })
      .populate({
        path: "userDetails",
        select: "-password -createdAt -__v",
      })
      .populate({ path: "projectDetails", select: "-__v" });

    if (!issue) {
      return res.status(404).json({
        status: false,
        message: "Issue not found",
      });
    }

    res.status(200).json({
      issue: issue,
      status: true,
      message: "Successfully retrieved the issue",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error", status: false });
  }
});

// Add comment
router.post("/:issueKey/comments", validateToken, async (req, res) => {
  try {
    const { text, userId } = req.body;
    const issueKey = req.params.issueKey;

    // Validate input
    if (!text || !userId) {
      return res
        .status(400)
        .json({ message: "Required fields missing", status: false });
    }

    // Validate userId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid userId", status: false });
    }

    // Find the issue
    const issue = await Issue.findOne({ issueKey });
    if (!issue) {
      return res
        .status(404)
        .json({ message: "Issue not found", status: false });
    }

    // Find the user
    const user = await User.findById(userId).select(
      "-password -createdAt -__v"
    ); // Assuming you have a User model
    if (!user) {
      return res.status(404).json({ message: "User not found", status: false });
    }

    // Create and save the comment
    const comment = new Comment({
      text,
      userDetails: user._id, // Store the user object ID in userDetails
      issueDetails: issue._id,
    });
    await comment.save();

    // Add the comment to the issue's comments array
    issue.comments.push(comment._id);
    await issue.save();

    res.status(201).json({
      data: {
        ...comment.toObject(),
        userDetails: user.toObject(), // Include the user details in the response
      },
      status: true,
      message: "Successfully created new comment",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error", status: false });
  }
});

// Fetch comments for a particular issue
router.get("/:issueKey/comments", async (req, res) => {
  try {
    const issueKey = req.params.issueKey;

    // Find the issue
    const issue = await Issue.findOne({ issueKey }).populate({
      path: "comments",
      options: { sort: { createdAt: -1 } }, // Sort comments by createdAt in descending order
      populate: {
        path: "userDetails",
        model: "User",
        select: "-password -createdAt -__v",
      },
    });

    if (!issue) {
      return res
        .status(404)
        .json({ message: "Issue not found", status: false });
    }

    // Extract and send the comments
    const comments = issue.comments.map((comment) => comment.toObject());

    res.status(200).json({
      comments,
      status: true,
      message: "Successfully fetched comments for the issue",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error", status: false });
  }
});

module.exports = router;
