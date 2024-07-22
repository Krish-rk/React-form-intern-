// app.js
const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { z } = require("zod");

const app = express();
const dbPath = path.join(__dirname, "fnMoney.db");

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

app.use(bodyParser.json());

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).send("Access denied");
  }

  jwt.verify(token, "your_jwt_secret", (err, user) => {
    if (err) {
      return res.status(403).send("Invalid token");
    }

    req.user = user;
    next();
  });
};

// Define Zod schemas for validation
const userSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

const assessmentSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().min(1, "Description is required"),
});

// User registration endpoint
app.post("/register", async (req, res) => {
  try {
    const { username, password } = userSchema.parse(req.body);
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.run("INSERT INTO users (username, password) VALUES (?, ?)", [
      username,
      hashedPassword,
    ]);
    res.status(201).send("User created successfully");
  } catch (e) {
    if (e instanceof z.ZodError) {
      res.status(400).send(e.errors);
    } else {
      res.status(400).send("Username already exists");
    }
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  try {
    const { username, password } = loginSchema.parse(req.body);
    const user = await db.get("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { id: user.id, username: user.username },
        "your_jwt_secret",
        { expiresIn: "1h" }
      );
      res.send({ token });
      console.log({ token });
    } else {
      res.status(401).send("Invalid credentials");
    }
  } catch (e) {
    if (e instanceof z.ZodError) {
      res.status(400).send(e.errors);
    } else {
      res.status(500).send("An error occurred");
    }
  }
});

// Assessment submission endpoint
app.post("/assessments", authenticateJWT, async (req, res) => {
  try {
    const { title, description } = assessmentSchema.parse(req.body);
    const userId = req.user.id;

    await db.run(
      "INSERT INTO assessments (user_id, title, description) VALUES (?, ?, ?)",
      [userId, title, description]
    );
    res.status(201).send("Assessment submitted successfully");
  } catch (e) {
    if (e instanceof z.ZodError) {
      res.status(400).send(e.errors);
    } else {
      res.status(500).send("Error submitting assessment");
    }
  }
});

app.listen(3000, () => {
  console.log("Server Running at http://localhost:3000/");
});
