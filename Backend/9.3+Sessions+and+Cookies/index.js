// Import necessary modules from npm packages
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

// Initialize the Express application
const app = express();
const port = 3000; // Define the port on which the server will listen
const saltRounds = 10; // Set the number of rounds for bcrypt salt generation
env.config(); // Load environment variables from .env file

// Configure session middleware for persistent user sessions
app.use(
  session({
    secret: "TOPSECRETWORD", // Secret used to sign the session ID cookie (should be an environment variable in production)
    resave: false, // Avoid resaving sessions that haven't changed
    saveUninitialized: true, // Save sessions that are new but not modified
  })
);

// Middleware to parse URL-encoded bodies (as sent by HTML forms)
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the 'public' directory
app.use(express.static("public"));

// Initialize passport for authentication and session handling
app.use(passport.initialize());
app.use(passport.session());

// Create a new database client using pg and connect to it
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "Paloma!2001",
  port: 5432,
});
db.connect(); // Establish a connection to the database

// Define routes for the application
app.get("/", (req, res) => {
  res.render("home.ejs"); // Serve the home page
});

app.get("/login", (req, res) => {
  res.render("login.ejs"); // Serve the login page
});

app.get("/register", (req, res) => {
  res.render("register.ejs"); // Serve the registration page
});

// Logout route clears the user session and redirects to home
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Protect the secrets route to ensure only authenticated users can access it
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs"); // Serve the secrets page if authenticated
  } else {
    res.redirect("/login"); // Redirect to login if not authenticated
  }
});

// Handle login form submissions
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets", // Redirect to secrets page upon successful login
    failureRedirect: "/login", // Redirect back to login on failure
  })
);

// Handle registration form submissions
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Check if user already exists in the database
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      // User exists, redirect to login
      req.redirect("/login");
    } else {
      // Hash the password and store new user in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          // Log the user in and redirect to secrets page
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Configure passport to use a local strategy for authentication
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      // Check if the user exists in the database
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        // Compare submitted password with the stored hashed password
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              // Password is valid, authenticate the user
              return cb(null, user);
            } else {
              // Password is invalid, authentication failed
              return cb(null, false);
            }
          }
        });
      } else {
        // User not found
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// Serialize and deserialize user instances to and from the session
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
