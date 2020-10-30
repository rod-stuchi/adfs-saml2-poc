const https = require("https");
const fs = require("fs");
const express = require("express");
const dotenv = require("dotenv");
const session = require("express-session");
const body = require("body-parser");
const cookie = require("cookie-parser");
const passport = require("passport");
const saml = require("passport-saml");

dotenv.config();

console.log("🍁 ENTRY_POINT:", process.env.ENTRY_POINT);
console.log("🍁 ISSUER:", process.env.ISSUER);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

const samlStrategy = new saml.Strategy(
  {
    entryPoint: process.env.ENTRY_POINT,
    callbackUrl: process.env.CALLBACK_URL,
    issuer: process.env.ISSUER,
    identifierFormat: null,
    // authnContext: 'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows',
    // Service Provider private key
    decryptionPvk: fs.readFileSync(__dirname + "/cert/arch_local.cert", "utf8"),
    // Service Provider Certificate
    privateCert: fs.readFileSync(__dirname + "/cert/arch_local.key", "utf8"),
    // Identity Provider's public key
    cert: fs.readFileSync(__dirname + "/cert/adfs-rods-local.pem", "utf8"),
    // cert: fs.readFileSync( __dirname + "/cert/arch_local.cert", "utf8"),
    // validateInResponseTo: false,
    // disableRequestedAuthnContext: true,
    forceAuthn: true,
    signatureAlgorithm: "sha256"
  },
  function(profile, done) {
    return done(null, profile);
  }
);

passport.use(samlStrategy);

const app = express();

app.use(express.json());
app.use(cookie());
app.use(
  session({
    secret: "cookie_secret",
    name: "cookie_name",
    proxy: true,
    resave: false,
    saveUninitialized: true
  })
);
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  else return res.redirect("/login");
}

app.get("/", ensureAuthenticated, function(req, res) {
  const sessionId = req.sessionID;
  const session = JSON.parse(req.sessionStore.sessions[req.sessionID]);
  console.log("😁😁😁😁", JSON.stringify(session, null, 2));
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title></title>
  </head>
  <body>
    <h1>Enfim vc está logado! 🙌 </h1>
    <pre>
    sessionID: ${sessionId}
     username: ${session.passport.user["uname"]}
        email: ${session.passport.user["email"]}
    telephone: ${session.passport.user["telephone"]}
    </pre>
    <button onClick="document.location.replace('/logout')" style='font-size: 1.5em;'>logoff</button>
  </body>
  </html>
  `);
});

app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  function(req, res) {
    console.log("🍇🍇🍇🍇", "/login");
    res.redirect("/");
  }
);

app.post(
  "/login/callback",
  body.urlencoded({ extended: false }),
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  // passport.authenticate("saml", (err, user, info) => {
  //   console.log("🧵🧵🧵🧵", err, user, info);
  // }),
  function(req, res) {
    console.log("🍇🍇🍇🍇", "/login/callback");
    res.redirect("/");
  }
);

app.get("/logout", function(req, res) {
  console.log("🍇🍇🍇🍇", "/logout");
  res.clearCookie("cookie_name");
  res.redirect("/");
});

app.get("/login/fail", function(req, res) {
  console.log("🍇🍇🍇🍇", "/login/fail");
  res.status(401).send("Login failed");
});

app.get("/adfs", function(req, res) {
  console.log("🏰🏰🏰🏰", "/adfs");
  res.type("application/xml");
  res
    .status(200)
    .send(
      samlStrategy.generateServiceProviderMetadata(
        fs.readFileSync(__dirname + "/cert/arch_local.key", "utf8"),
        fs.readFileSync(__dirname + "/cert/arch_local.cert", "utf8")
      )
    );
});

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

const httpsOptions = {
  // key: fs.readFileSync('./cert-arch-local/cert.key'),
  // cert: fs.readFileSync('./cert-arch-local/cert.pem')
  key: fs.readFileSync("./cert-arch-local/arch.local.key"),
  cert: fs.readFileSync("./cert-arch-local/arch.local.crt")
};

// var server = app.listen(3050, function() {
//   console.log("🦂 🦂 Listening on %d", server.address().port);
// });

const port = 3050;
const server = https.createServer(httpsOptions, app).listen(port, () => {
  console.log("server running at " + port);
});
