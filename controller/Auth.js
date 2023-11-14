const { User } = require("../model/User");
const crypto = require("crypto");
const { sanitiZeUser } = require("../services/common");
const jwt = require("jsonwebtoken");

const SECRET_KEY = "SECRET_KEY";

exports.createUser = async (req, res) => {
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
        const newuser = new User({
          ...req.body,
          password: hashedPassword,
          salt,
        });
        const user = await newuser.save();
        req.login(sanitiZeUser(user), (err) => {
          if (err) {
            res.status(400).json(err);
          } else {
            const token = jwt.sign(sanitiZeUser(user), SECRET_KEY);
            res.cookie("jwt", req.user.token, {
              expires: new Date(Date.now() + 3600000),
              httpOnly: true,
            });
            res.status(201).json({
              id: user.id,
              role: user.role,
              token:token,
              email: user.email,
              addresses: user.addresses,
              orders: user.orders,
            });
          }
        });
      }
    );
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.loginUser = async (req, res) => {
  try {
    const user = req.user;

    res
      .cookie("jwt", req.user.token, {
        expires: new Date(Date.now() + 3600000),
        httpOnly: true,
      })
      .status(201)
      .json({
        id: user.id,
        role: user.role,
        token: user.token,
        email: user.email,
        addresses: user.addresses,
        orders: user.orders,
      });
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.checkAuth = async (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.sendStatus(401);
  }
};

exports.logout = async (req, res) => {
  res
    .cookie("jwt", null, {
      expires: new Date(Date.now()),
      httpOnly: true,
    })
    .sendStatus(200);
};
