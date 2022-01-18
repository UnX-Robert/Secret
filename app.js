const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = {
  email: String,
  password: String
}

const User  = mongoose.model("User", userSchema);

app.get('/', function(req, res) {
  res.render('home');
});

app.route('/login')
  .get(function(req, res) {
    res.render('login');
  })
  .post(function(req, res) {
    User.findOne({email: req.body.username}, function(err, foundUser) {
      if (!err) {
        if (foundUser) {
          if (req.body.password === foundUser.password) {
            res.render('secrets');
          }
          else {
            res.send("Wrong password!");
          }
        }
        else {
          res.send("No account with this email!");
        }
      }
      else {
        console.log(err);
      }
    });
  });

app.route('/register')
  .get(function(req, res) {
    res.render('register');
  })
  .post(function(req, res) {
    const newUser = new User({
      email: req.body.username,
      password: req.body.password
    });

    newUser.save(function(err) {
      if(err) {
        console.log(err);
      }
      else {
        res.render("secrets");
      }
    });
  });

app.listen(3000, () => {
  console.log('Server started on port 3000');
});