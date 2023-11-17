const { User } = require("../model/User");
const crypto = require("crypto");
const { sanitiZeUser, transporter } = require("../services/common");
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

        try {
          const existingUser = await User.findOne({ email: req.body.email });
          if (existingUser) {
            return res.status(400).json({ message: "Email already in use" });
          }

          const user = await newuser.save();
          const token = jwt.sign(sanitiZeUser(user), SECRET_KEY);
          if (!existingUser) {
          
            // Only send the cookie if the user doesn't exist already
            res.cookie("jwt", token, {
              expires: new Date(Date.now() + 3600000),
              httpOnly: true,
            });
          }
          res.status(201).json({
            id: user.id,
            role: user.role,
            token: token,
            email: user.email,
            addresses: user.addresses,
            orders: user.orders,
            name:user.name,
            ProfileUrl:user.ProfileUrl
          });
        } catch (error) {
          res.status(400).json({ message: "Error creating user", error });
        }
      }
    );
  } catch (err) {
    res.status(400).json(err);
  }
};



exports.loginUser = async (req, res) => {
  try {
    // Assuming authentication was successful and user is available in req.user
    if (req.user) {
      const user = req.user;
      const token = jwt.sign(sanitiZeUser(user), SECRET_KEY);

      return res.cookie("jwt", token, {
        expires: new Date(Date.now() + 3600000),
        httpOnly: true,
      }).status(201).json({
        id: user.id,
        role: user.role,
        token: user.token,
        email: user.email,
        addresses: user.addresses,
        orders: user.orders,
        name:user.name,
        ProfileUrl:user.ProfileUrl
      });
    } else {
      // Handle case when user is not available (e.g., invalid login credentials)
      return res.status(400).json({ message: "Invalid login credentials" });
    }
  } catch (err) {
    return res.status(400).json({ message: "Invalid login credentials" });
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

exports.resetPasswordRequest = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email: email });

  if (user) {
    const token = crypto.randomBytes(48).toString("hex");
    user.resetPasswordToken = token;
    const usersave = await user.save();
    if (usersave && email) {
      let url = `https://ecommerce-backend-five-ruby.vercel.app/reset-password?token=${token}&email=${email}`;
      let info = await transporter.sendMail({
        from: '"oneStore" <jituyt8456@gmail.com>', // sender address
        to: email, // list of receivers
        subject: "Reset Password for  oneStore", // Subject line
        html: `<p>Click <a href='${url}'> here </a> to Reset Password</p>`, // html body
      });

      res.json(info);
    } else {
      res.sendStatus(400);
    }
  } else {
    res.sendStatus(400);
  }
};

exports.resetPassword = async (req, res) => {
  const { email } = req.body;
  const { password } = req.body;
  const { token } = req.body;
  const user = await User.findOne({ email: email, resetPasswordToken: token });

  if (user) {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
       user.password=hashedPassword
       user.salt=salt;
       await user.save()
      });

    let info = await transporter.sendMail({
      from: '"oneStore" <jituyt8456@gmail.com>', // sender address
      to: email, // list of receivers
      subject: "Reset Password successfully", // Subject line
      html: `<h2>Reset Password successfully ,of your OneStore account</h2>`, // html body
    });

    res.json(info);
  } else {
    res.sendStatus(400);
  }
};
