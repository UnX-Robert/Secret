require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}))

// Initialize passport to deal with the sessions
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

// Initialize passport-local-mongoose
userSchema.plugin(passportLocalMongoose);

const User  = mongoose.model('User', userSchema);

// passport-local
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', function(req, res) {
  res.render('home');
});

app.get('/secrets', function(req, res) {
  if (req.isAuthenticated()) {
    res.render('secrets');
  }
  else {
    res.redirect('/login');
  }
});

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
})

app.route('/login')
  .get(function(req, res) {
    res.render('login');
  })
  .post(function(req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    // passport method
    req.login(user, function(err){
      if (err) {
        console.log(err);
      }
      else {
        passport.authenticate('local')(req, res, function(){
          res.redirect('/secrets');
        });
      }
    });
  });

app.route('/register')
  .get(function(req, res) {
    res.render('register');
  })
  .post(function(req, res) {
      // passport local mongoose method
      User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
          console.log(err);
          res.redirect('/register');
        }
        else {
          passport.authenticate('local')(req, res, function(){
            res.redirect('/secrets');
          });
        }
      });
  });

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
