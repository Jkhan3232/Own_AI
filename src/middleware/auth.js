// Importing necessary modules
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";

// Middleware to check if the user is authenticated
const isAuthenticated = async (req, res, next) => {
  try {
    // Extract the token from the cookies
    const token = req.cookies.token;

    // If there is no token, return an error
    if (!token) {
      return res
        .status(401)
        .json(new ApiError(401, "Authentication failed. Please login."));
    }

    // Verify the token using the secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Extract the user ID from the decoded token
    const userId = decoded.sub;

    // Find the user by ID
    const user = await User.findById(userId);

    // If the user does not exist, return an error
    if (!user) {
      return res
        .status(404)
        .json(new ApiError(404, "Authentication failed. User not found."));
    }

    // Attach the user object to the request for future route handlers
    req.user = user;

    // Set the Content-Type header
    res.setHeader("Content-Type", "application/json");

    // Continue to the next middleware/route handler
    next();
  } catch (error) {
    // Log the error and return a server error response
    console.error("Error during authentication:", error);
    return res
      .status(500)
      .json(
        new ApiError(500, "Internal server error. Please try again later.")
      );
  }
};

// Exporting the isAuthenticated middleware
export default isAuthenticated;
