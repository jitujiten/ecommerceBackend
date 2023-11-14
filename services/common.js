const passport = require("passport");
const nodemailer = require("nodemailer");

exports.IsAuth = (req, res, done) => {
  return passport.authenticate("jwt");
};

exports.sanitiZeUser = (user) => {
  return { id: user.id, role: user.role };
};

exports.cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  return token;
};


exports.transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    // TODO: replace `user` and `pass` values from <https://forwardemail.net>
    user: "jituyt8456@gmail.com",
    pass: "qjffhrgduhlevzlb",
  },
});