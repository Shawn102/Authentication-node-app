//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
// Creating a user "schema"
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  userSecret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Encrypting our db using mongoose-encryption
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']})

// Creating model using "userSchema"
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:4100/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUserWithSecret) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUserWithSecret) {
        res.render("secrets", { AllUserSecret: foundUserWithSecret });
      }
    }
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", (req, res) => {
  const userText = req.body.secret;
  const userId = req.user.id;
  User.findById(userId, (err, foundUser) => {
    if (!err) {
      if (foundUser) {
        foundUser.userSecret = userText;
        foundUser.save().then(() => res.redirect("/secrets"));
      }
    } else {
      console.log(err);
      res.redirect("/submit");
    }
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (!err) {
      res.redirect("/");
    } else {
      console.log(err);
    }
  });
});

//this post method for register page
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.render("failed");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

// this post for login page
app.post("/login", (req, res) => {
  const logUser = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(logUser, (err) => {
    if (!err) {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    } else {
      console.log(err);
      res.render("failed");
    }
  });
});

const port = process.env.PORT || 4100;
app.listen(port, () => {
  console.log(`Your app started on port ${port}`);
});
