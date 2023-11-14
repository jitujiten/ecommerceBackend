const passport = require("passport");

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
