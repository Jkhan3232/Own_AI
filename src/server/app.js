import express from "express";
const app = express();
import passport from "passport";
import expressSession from "express-session";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import passportstrt from "../utils/passport.js";

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());
app.use(
  expressSession({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.session());
app.use(passport.initialize());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

passportstrt();

// routes import
import userRouter from "../routes/user.route.js";

// routes declaration
app.use("/api/v1/users", userRouter);



app.get("/", (req, res) => {
  res.send("Hello World! This is a test!");
});

export { app };
