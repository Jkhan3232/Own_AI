// Importing necessary modules
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { User } from "../models/user.model.js";

// Function to initialize passport
const initializePassport = () => {
  // Using local strategy for authentication
  passport.use(
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        // Finding the user with the provided email
        const user = await User.findOne({ email });
        // If user not found, return false
        if (!user) return done(null, false);
        // Checking if the password is correct
        const isMatch = await user.isPasswordCorrect(password);
        // If password is not correct, return false
        if (!isMatch) return done(null, false);
        // If user is found and password is correct, return the user
        return done(null, user);
      }
    )
  );

  // Serializing the user
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  // Deserializing the user
  passport.deserializeUser(async (id, done) => {
    try {
      // Finding the user with the provided id
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  });
};

// Exporting the initializePassport function
export default initializePassport;
