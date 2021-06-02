const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits
const LocalStrategy = require('passport-local').Strategy
const fortune = require('fortune-teller')
const JWTStrategy = require('passport-jwt').Strategy
const GitHubStrategy = require('passport-github2').Strategy
const users = require('./users.json')
const bcrypt = require('bcrypt')
// const saltRounds = 10

const port = 3000

const app = express()
app.use(logger('dev'))

app.use(express.urlencoded({ extended: true })) 

const cookieExtractor = function (req) {
  let token = null
  if (req && req.cookies && req.cookies.token) {
    token = req.cookies.token
  }
  return token
}

passport.use('local', new LocalStrategy(
  {
    usernameField: 'username', 
    passwordField: 'password', 
    session: false 
  },
  function (username, password, done) {
    for (let index = 0; index < users.length; index++) {
      if (username === users[index].username && bcrypt.compare(password, users[index].hash)) {
        const user = {
          username: users[index].username,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user)
      }
    }
    return done(null, false) 
  }
))

passport.use('jwt', new JWTStrategy(
  {
    jwtFromRequest: cookieExtractor,
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    //If we have an external user, we directly return the jwtpayload sub. Otherwise, we will be redirected to the '/login' page instead of '/' one.
    if(jwtPayload){
        return done(null, jwtPayload.sub)
    }
    for (let index = 0; index < users.length; index++) {
      if (jwtPayload.sub === users[index].username) {
        const user = {
          name: 'silvia',
          surname: 'margarit'
        }
        return done(null, user)
      }
    }
    return done(null, false) // if passport returning false as the user object means that the authentication process failed.
  }))

passport.use('github', new GitHubStrategy({
    clientID: '9c6be585ef9a007c0943',
    clientSecret: 'aa2e4193b1ff3444235aedb95c3ea67747408362',
    callbackURL: "http://localhost:3000/oauth/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    user = {githubId: profile.id, username:profile.username}
    return done(null, user)
  }
  ))

app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser())

app.get('/',
  passport.authenticate('jwt', { failureRedirect: '/login', session: false }),
  (req, res) => {
    res.send(fortune.fortune())
  })

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.get('/logout',
  (req, res) => {
    res.clearCookie('token')
    res.send('You have logged out.')
  }
)

app.get('/auth/github',
    passport.authenticate('github', { scope: [ 'user:email' ] }),
    (req, res) => {
        res.redirect('/')
    }
)

//for this redirection we must write the URL callback of our OAuth application.
app.get('/oauth/callback', 
  passport.authenticate('github', { failureRedirect: '/login', session: false}),
    // Successful authentication, redirect home.
    (req, res) => {
        const jwtClaims = {
          sub: req.user.username,
          iss: 'localhost:3000',
          aud: 'localhost:3000',
          exp: Math.floor(Date.now() / 1000) + 604800,
          // 1 week (7×24×60×60=604800s) from now
          role: 'user', // just to show a private JWT field
        }
    
        // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    
        const token = jwt.sign(jwtClaims, jwtSecret)
    
        res.cookie('token', token, { maxAge: 60000, httpOnly: true })
        res.redirect('/')
        console.log('Cookies created successfully')
    
        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
      }
  );

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      // 1 week (7×24×60×60=604800s) from now
      role: 'user', // just to show a private JWT field
      exam: {
        name: 'silvia',
        surname: 'margarit'
      }
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('token', token, { maxAge: 60000, httpOnly: true })
    res.redirect('/')
    console.log('Cookies created successfully')

    // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
