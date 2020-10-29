const http = require("http");
const fs = require("fs");
const express = require("express");
const dotenv = require("dotenv");
// const session = require("express-session");
// const cookie = require("cookie-parser");
const passport = require("passport");
const saml = require("passport-saml");

dotenv.config();

console.log("🍁 ENTRY_POINT", process.env.ENTRY_POINT);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});


const samlStrategy = new saml.Strategy(
  {
    // URL that goes from the Identity Provider -> Service Provider
    callbackUrl: process.env.CALLBACK_URL,
    // URL that goes from the Service Provider -> Identity Provider
    entryPoint: process.env.ENTRY_POINT,
    // Usually specified as `/shibboleth` from site root
    issuer: process.env.ISSUER,
    identifierFormat: null,
    // Service Provider private key
    decryptionPvk: fs.readFileSync( __dirname + "/cert/urn_arch_local.cert", "utf8"),
    // Service Provider Certificate
    privateCert: fs.readFileSync(__dirname + "/cert/urn_arch_local.key", "utf8"),
    // Identity Provider's public key
    cert: fs.readFileSync(__dirname + "/cert/adfs-rods-local.pem", "utf8"),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true
  },
  function(profile, done) {
    return done(null, profile);
  }
);

passport.use(samlStrategy);

const app = express();

app.use(express.json());
// app.use(cookie);
// app.use(session({
//     secret: "cookie_secret",
//     name: "cookie_name",
//     proxy: true,
//     resave: true,
//     saveUninitialized: true
// }));
app.use(passport.initialize());
// app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  console.log("🌭🌭🌭", "ensureAuthenticated");
  if (req.isAuthenticated()) return next();
  else return res.redirect("/login");
}

app.get("/", ensureAuthenticated, function(req, res) {
  console.log("⛽⛽⛽", Authenticated);
  res.send("Authenticated");
});

app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  function(req, res) {
    res.redirect("/");
  }
);

app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  function(req, res) {
    res.redirect("/");
  }
);

app.get("/login/fail", function(req, res) {
  res.status(401).send("Login failed");
});

app.get("/Shibboleth.sso/Metadata", function(req, res) {
  res.type("application/xml");
  res
    .status(200)
    .send(
      samlStrategy.generateServiceProviderMetadata(
        fs.readFileSync(__dirname + "/cert/cert.pem", "utf8")
      )
    );
});

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

var server = app.listen(3050, function() {
  console.log("🦂 🦂 Listening on %d", server.address().port);
});
