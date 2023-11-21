const express = require("express");
const { createUser, loginUser, checkAuth, logout,resetPasswordRequest, resetPassword } = require("../controller/Auth");
const passport = require("passport");

const router = express.Router();

router
  .post("/signup", createUser)
  .post(
    "/login",
    function (req, res, next) {
      passport.authenticate("local", function (err, user, info) {
        if (err) {
          return res.status(400).json({ message: "Error during login" });
        }
        if (!user) {
          // The 'info' object contains the message from passport.use
          return res
            .status(400)
            .json({ message: info.message || "Invalid login credentials" });
        }

        req.user = user;
        next();
      })(req, res, next);
    },
    loginUser
  )
  .get("/check",passport.authenticate("jwt"), checkAuth)
  .get("/logout", logout)
  .post("/reset-password-request",resetPasswordRequest)
  .post("/reset-password",resetPassword)
  
exports.router = router;
