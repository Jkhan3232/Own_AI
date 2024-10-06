import { asyncHandler } from "../utils/AsyncHendaler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import passport from "passport";
import jwt from "jsonwebtoken";

const register = asyncHandler(async (req, res) => {
  try {
    const { email, username, password, role, phone, city, country } = req.body;

    // Check if any required field is missing
    if (
      [email, username, password, role, phone, city, country].some(
        (field) => !field?.trim()
      )
    ) {
      throw new ApiError(400, "All fields are required");
    }

    // Validate the role (must be either 'Admin' or 'Staff')
    if (!["Admin", "Staff"].includes(role)) {
      throw new ApiError(
        400,
        "Invalid role. Must be either 'Admin' or 'Staff'"
      );
    }

    // Validate phone number format (assuming a 10-digit phone number)
    const phoneRegex = /^\d{10}$/;
    if (!phoneRegex.test(phone)) {
      throw new ApiError(400, "Invalid phone number. It must be 10 digits");
    }

    // Check if user with the same email or username already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      throw new ApiError(409, "User with email or username already exists");
    }

    // Create a new user
    const user = await User.create({
      email,
      password,
      username: username,
      role,
      phone,
      city,
      country,
    });

    // Fetch the created user without the password field
    const createdUser = await User.findById(user._id).select("-password");

    if (!createdUser) {
      throw new ApiError(
        500,
        "Something went wrong while registering the user"
      );
    }

    return res
      .status(201)
      .json(new ApiResponse(200, createdUser, "User registered successfully"));
  } catch (error) {
    console.error(error);
    // Use throw to propagate the error to the error handling middleware
    throw new ApiError(501, "Internal Server Error");
  }
});

// Login route
const login = asyncHandler(async (req, res, next) => {
  // Use passport's "local" strategy for authentication
  passport.authenticate(
    "local",
    { session: false },
    async (err, user, info) => {
      if (err) {
        return next(err);
      }

      // If no user is found or invalid credentials are provided
      if (!user) {
        return res
          .status(401)
          .json(new ApiError(401, "Invalid email or password"));
      }

      // Generate a JWT token on successful authentication
      const token = jwt.sign(
        { sub: user._id, role: user.role }, // Payload contains user ID and role
        process.env.JWT_SECRET, // Secret key from environment variables
        { expiresIn: "1h" } // Token expiration time
      );

      // Set the JWT token in an HTTP-only cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // Secure flag in production
        maxAge: 3600000, // 1 hour
      });

      // Check if the user is an Admin or Staff
      if (user.role === "Admin") {
        // Admin: Retrieve all user details
        const users = await User.find().select("-password"); // Fetch all users except password
        return res.status(200).json({
          token,
          users,
          message: "Admin logged in successfully",
        });
      } else if (user.role === "Staff") {
        // Staff: Return only their own details
        const staffDetails = await User.findById(user._id).select("-password");
        return res.status(200).json({
          token,
          user: staffDetails,
          message: "Staff logged in successfully",
        });
      }
    }
  )(req, res, next);
});
const getMe = asyncHandler(async (req, res) => {
  try {
    const token = req.cookies.token || "";

    // Check if token exists
    if (!token) {
      throw new ApiError(401, "Login first");
    }

    // The user object (req.user) should be available after token verification
    const user = req.user;

    // If user is an Admin, they can access any user's details by userId
    if (user.role === "Admin") {
      const userId = req.params.userId; // Assuming userId is passed in params
      const targetUser = await User.findById(userId).select("-password");

      if (!targetUser) {
        throw new ApiError(404, "User not found");
      }

      return res
        .status(200)
        .json(
          new ApiResponse(
            200,
            targetUser,
            "User details retrieved successfully"
          )
        );
    }

    // If the user is not Admin, they can only access their own details
    const currentUser = await User.findById(user._id).select("-password");

    return res
      .status(200)
      .json(
        new ApiResponse(200, currentUser, "Your details retrieved successfully")
      );
  } catch (error) {
    console.error(error);
    throw new ApiError(500, "Failed to retrieve user details");
  }
});

const listUsers = asyncHandler(async (req, res) => {
  try {
    const token = req.cookies.token || "";

    // Check if token exists
    if (!token) {
      throw new ApiError(401, "Login first");
    }

    // Ensure only Admins can access this route
    const user = req.user;
    if (user.role !== "Admin") {
      throw new ApiError(403, "Access denied. Admins only");
    }

    // Search and filter functionality
    const { name, email, country } = req.query; // Extract search/filter parameters

    // Build query object based on filters
    const query = {};
    if (name) query.username = { $regex: name, $options: "i" }; // Case-insensitive regex search
    if (email) query.email = { $regex: email, $options: "i" };
    if (country) query.country = country;

    // Fetch users based on search/filter conditions
    const users = await User.find(query).select("-password");

    // Check if any users were found
    if (users.length === 0) {
      throw new ApiError(404, "No users found");
    }

    // Respond with the filtered user list
    return res
      .status(200)
      .json(new ApiResponse(200, users, "Users retrieved successfully"));
  } catch (error) {
    console.error(error);
    throw new ApiError(500, "Failed to retrieve users");
  }
});

// Logout route
const logout = asyncHandler(async (req, res) => {
  try {
    // Clear the token cookie
    res.clearCookie("token");
    // Respond with a success message
    return res
      .status(200)
      .json(new ApiResponse(200, null, "User logged out successfully"));
  } catch (error) {
    console.error("Error logging out user:", error);
    throw new ApiError(500, "Internal server error");
  }
});

// Export endpoints
export { register, login, getMe, logout, listUsers };
