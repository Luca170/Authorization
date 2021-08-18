const express = require("express")
const bodyParser = require("body-parser")
const myDB = require("./connection")
const path = require("path")
const passport = require("passport")
const LocalStrategy = require("passport-local")
const bcrypt = require("bcrypt")
const session = require("express-session")
const {ObjectId} = require("mongodb")
const app = express()

app.set("view engine", "ejs")
app.use(express.static(__dirname + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret:"Your secret key",
    resave:true,
    saveUninitialized:true,
    cookie:{secure:false}
}))
app.use(passport.initialize())
app.use(passport.session())

myDB( async (client) => {
    const myDataBase = await client.db("mydb").collection("auths")


  app.get("/",(req, res) => {
    res.render('home');
  });
  app.get("/login", (req,res) => {
      res.render("login.ejs")
  })
  app.post("/loginreq",passport.authenticate('local', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/profile');
  });
  app.get("/profile",ensureAuthenticated, (req,res) => {
      res.render("profile.ejs")
  })
  app.post("/profilereq",ensureAuthenticated, (req,res) => {
      req.logout()
      res.redirect("/")
  })
app.get("/register",(req,res) => {
    res.render("register.ejs")
})
  app.route('/registerreq').post(
    (req, res, next) => {
      const hash = bcrypt.hashSync(req.body.password, 12);
      myDataBase.findOne({ username: req.body.username }, function (err, user) {
        if (err) {
          next(err);
        } else if (user) {
          res.redirect('/');
        } else {
          myDataBase.insertOne({ username: req.body.username, password: hash }, (err, doc) => {
            if (err) {
              res.redirect('/');
            } else {
              next(null, doc);
            }
          });
        }
      });
    },
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res, next) => {
      res.redirect('/');
    }
  );

    passport.serializeUser((user, done) => {
        done(null, user._id);
      });
      passport.deserializeUser((id, done) => {
        myDataBase.findOne({ _id: new ObjectId(id) }, (err, doc) => {
          if (err) return console.error(err);
          done(null, doc);
        });
      });
      passport.use(new LocalStrategy(
        function (username, password, done) {
          myDataBase.findOne({ username: username }, function (err, user) {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            if (!bcrypt.compareSync(password, user.password)) { 
              return done(null, false);
            }
            return done(null, user);
          });
        }
      ));

})
function ensureAuthenticated(req, res, next) {
     if (req.isAuthenticated()) {
      return next();
     }
     res.redirect('/');
   }
app.listen(8000)