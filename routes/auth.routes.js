const express = require('express');
const router = express.Router();
// Require user model
const User = require('../models/User.model');

// Add bcrypt to encrypt passwords
const bcrypt = require('bcrypt');

// Add passport
const passport = require('passport');

const ensureLogin = require('connect-ensure-login');

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('auth/private', { user: req.user });
});

router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  // get username and password
  const { username, password } = req.body;
  console.log('signup POST', username);
  if (!password || !username) {
    return res.render('auth/signup', {
      message: 'Please enter an Username and a Password',
    });
  }

  if (password.length < 8) {
    return res.render('auth/signup', {
      message: 'Your password has to be 8 chars min',
    });
  }
  User.findOne({ username }).then((user) => {
    if (user) {
      res.render('auth/signup', {
        message: 'This username is already taken',
      });
      return;
    } else {
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);
      User.create({ username, password: hash }).then((createdUser) => {
        console.log('createdUser', createdUser);
        /*
        req.login(createdUser, (err) => {
          if (err) {
            next(err);
          } else {
            res.redirect('/');
          }
        });

node:internal/process/promises:245
          triggerUncaughtException(err, true // fromPromise //);
Error [ERR_HTTP_HEADERS_SENT]: Cannot set headers after they are sent to the client



        */
        // redirect to login
        res.redirect('/login');
      });
    }
  });
});

router.get('/login', (req, res, next) => {
  console.log('login POST req.body', req.body);
  res.render('auth/login');
});

router.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    passReqToCallback: true,
  })
);

router.get('/logout', (req, res, next) => {
  req.logout();
  res.redirect('/');
});

// auth login

router.get('/auth', (req, res, next) => {
  res.render('auth/login');
});

// GitHub2 login

router.get(
  '/auth/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

router.get(
  '/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  }
);

// Slack login

router.get('/auth/slack', passport.authenticate('slack'));
router.get(
  '/auth/slack/callback',
  passport.authorize('slack', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

module.exports = router;

// some interesting notes
// consider adding connect-flash instead - for showing error messages
// check req.isAuthenticated
// passport.authenticate -> failureFlash if using package connect-flash
