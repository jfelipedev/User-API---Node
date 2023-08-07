require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

//Config JSON response
app.use(express.json());

app.use(cors());

//Models
const User = require("./models/User");

//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  //check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "User not found" });
  }
  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Unauthorized" });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: "Invalid token" });
  }
}

//Public Route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Ping! Pong!" });
});

// Register User
app.post("/auth/register", async function (req, res) {
  const { login, password } = req.body;

  //validations
  if (!login) {
    return res.status(422).json({ msg: "Login is required" });
  }

  if (!password) {
    return res.status(422).json({ msg: "Password is required" });
  }

  // Checking if the user exists already
  const userExists = await User.findOne({ login: login });
  if (userExists) {
    return res.status(422).json({ msg: "User already exists" });
  }

  // Create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Create user
  const user = new User({
    login,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ msg: "Failed to register user" });
  }
});

// Login user
app.post("/auth/login", async (req, res) => {
  const { login, password } = req.body;

  //Validations
  if (!login) {
    return res.status(422).json({ msg: "Login is required" });
  }

  if (!password) {
    return res.status(422).json({ msg: "Password is required" });
  }

  // Checking if the user exists already
  const user = await User.findOne({ login: login });
  if (!user) {
    return res.status(404).json({ msg: "User not found" });
  }

  //Checking the password
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Invalid password" });
  }
  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({ msg: "Autenticado:", token });
  } catch (error) {
    res.status(500).json({ msg: "Failed to generate token" });
  }
});

//Credencials
const dbUser = process.env.DATABASE_USER;
const dbPadd = process.env.DATABASE_PASSWORD;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPadd}@backend-rpg.9wnbxgo.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3333);
    console.log("Connected to the database and listening on port 3333");
  })
  .catch((err) => console.log(err));
