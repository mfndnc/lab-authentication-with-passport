require('dotenv').config();

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const express = require('express');
const favicon = require('serve-favicon');
const hbs = require('hbs');
const mongoose = require('mongoose');
const logger = require('morgan');
const path = require('path');

// ******* for authentication
const session = require('express-session');
const MongoStore = require('connect-mongo');
const User = require('./models/User.model');
const passport = require('passport');
const bcrypt = require('bcrypt');

const LocalStrategy = require('passport-local').Strategy;
const SlackStrategy = require('passport-slack-oauth2').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
// ******* for authentication END

const DB_URL =
  process.env.MONGO_URL || 'mongodb://localhost/auth-with-passport';

mongoose
  .connect(DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  })
  .then((x) =>
    console.log(`Connected to Mongo! Database name: "${x.connections[0].name}"`)
  )
  .catch((err) => console.error('Error connecting to mongo', err));

const app_name = require('./package.json').name;
const debug = require('debug')(
  `${app_name}:${path.basename(__filename).split('.')[0]}`
);

const app = express();

// Middleware Setup
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
//app.use(cookieParser());

// Express View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')));

/*
 ******
 ****** for local authentication
 ******
 */

passport.use(
  new LocalStrategy((username, password, done) => {
    // this logic will be executed when we log in
    console.log('LocalStrategy', username);
    User.findOne({ username })
      .then((userFromDB) => {
        console.log('LocalStrategy findOne', userFromDB.username);
        if (userFromDB === null) {
          // there is no user with this username
          done(null, false, { message: 'Wrong Credentials' });
        } else if (!bcrypt.compareSync(password, userFromDB.password)) {
          // the password does not match
          done(null, false, { message: 'Wrong Credentials' });
        } else {
          // everything correct - user should be logged in
          done(null, userFromDB);
        }
      })
      .catch((err) => {
        // this is NOT working
        //done(err);
        done(err, false, { message: 'Wrong Credentials' });
      });
  })
);

/*
 ******
 ****** for github authentication
 ******
 */

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
      callbackURL: 'http://127.0.0.1:3000/auth/github/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('GITHUB profile', profile);

      User.findOne({ externalSource: 'GitHub', externalId: profile.id })
        .then((user) => {
          console.log('GITHUB findOne', user);

          if (user !== null) {
            done(null, user);
          } else {
            User.create({
              externalSource: 'GitHub',
              externalId: profile.id,
              username: profile.username || 'unknown',
              image: profile._json.avatar_url || '',
              email: profile.email || '',
            }).then((user) => {
              done(null, user);
            });
          }
        })
        .catch((err) => {
          done(err);
        });
    }
  )
);

/*
 ******
 ****** for lack authentication
 ******
 */
passport.use(
  new SlackStrategy(
    {
      clientID: process.env.SLACK_ID,
      clientSecret: process.env.SLACK_SECRET,
      skipUserProfile: false, // default
      scope: ['identity.basic', 'identity.email', 'identity.avatar'],
      callbackURL: 'http://127.0.0.1:3000/auth/slack/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('Slack account details:', profile);

      User.findOne({ externalSource: 'Slack', externalId: profile.id })
        .then((user) => {
          console.log('Slack findOne', user);

          if (user !== null) {
            done(null, user);
          } else {
            User.create({
              externalSource: 'Slack',
              externalId: profile.id,
              username: profile.displayName || 'unknown',
              image: profile.user.image_512 || '',
              email: profile.user.email || '',
            }).then((user) => {
              done(null, user);
            });
          }
        })
        .catch((err) => {
          done(err);
        });
    }
  )
);

/*
User log in, is identified, created in collection or retrieved if relogged in
the session gets created but the user is not considered logged
I suspect it has to do with this:
https://api.slack.com/docs/sign-in-with-slack#implementation__token-negotiation-flow
*/

/*
 ******
 ****** for **** authentication
 ******
 */

// twitter require registration and that I give a phone number
// amazon has a 8 steps requirement for website authentication

/*
 ******
 ****** saving sessions in local
 ******
 */
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
    saveUninitialized: false,
    resave: true,
    store: MongoStore.create({
      mongoUrl: DB_URL,
    }),
  })
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

// this is used to retrieve the user by it's id (that is stored in the session)
passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((dbUser) => {
      done(null, dbUser);
    })
    .catch((err) => {
      done(err);
    });
});

app.use(passport.initialize());
app.use(passport.session());

/*
 ******
 ****** END
 ******
 */

// default value for title local
app.locals.title = 'Express - Generated with IronGenerator';

// Routes middleware goes here
const index = require('./routes/index.routes');
app.use('/', index);
const authRoutes = require('./routes/auth.routes');
app.use('/', authRoutes);

module.exports = app;
