require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

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

mongoose.connect('"mongodb+srv://' + process.env.USERNAME + ':' + process.env.PASSWORD + '@cluster0.ixg4u.mongodb.net/userDB?retryWrites=true&w=majority');

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// Initialize passport-local-mongoose
userSchema.plugin(passportLocalMongoose);

// Find or create
userSchema.plugin(findOrCreate);

const User  = mongoose.model('User', userSchema);

// passport-local
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/', function(req, res) {
  res.render('home');
});

app.get('/secrets', function(req, res) {
  if (req.isAuthenticated()) {
    User.find({'secret': {$ne: null}}, function(err, foundUsers) {
      if (err) {
        console.log(err);
      }
      else {
        if (foundUsers) {
          res.render('secrets', {usersWithSecrets: foundUsers});
        }
      }
    });
  }
  else {
    res.redirect('/login');
  }
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }
);

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
  }
);

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
    }
);

app.route('/submit')
  .get(function(req, res) {
    if (req.isAuthenticated()) {
      res.render('submit');
    }
    else {
      res.redirect('/login');
    }
  })
  .post(function(req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user._id, function(err, foundUser) {
      if (err) {
        console.log(err);
      }
      else {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save(function() {
            res.redirect('/secrets');
          });
        }
      }
    });
  }
);

app.listen(process.env.PORT, () => {
  console.log('Server started on port 3000');
});
