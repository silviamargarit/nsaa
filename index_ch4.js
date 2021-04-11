const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits
const LocalStrategy = require('passport-local').Strategy
const fortune = require('fortune-teller')
const JWTStrategy = require('passport-jwt').Strategy
const users = require('./users.json')
const bcrypt = require('bcrypt')
// const saltRounds = 10

const port = 3000

const app = express()
app.use(logger('dev'))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)

// CHALLENGE 2 CREEM UNA COOKIE
const cookieExtractor = function (req) {
  let token = null
  if (req && req.cookies && req.cookies.token) {
    token = req.cookies.token
  }
  return token
}

// bcrypt.hash('nsaa2021', saltRounds,
//  (err, hash) => {
//    console.log(hash)
//  })

passport.use('local', new LocalStrategy(
  {
    usernameField: 'username', // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password', // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's stateless
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
    return done(null, false) // in passport returning false as the user object means that the authentication process failed.
  }
))

passport.use('jwt', new JWTStrategy(
  {
    jwtFromRequest: cookieExtractor,
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    for (let index = 0; index < users.length; index++) {
      if (jwtPayload.sub === users[index].username) {
        const user = {
          username: users[index].username,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user)
      }
    }
    return done(null, false) // in passport returning false as the user object means that the authentication process failed.
  }))

app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser())

// CHALLENGE 2 PART 1 i 2
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

// app.post('/login',
//  passport.authenticate('local', { failureRedirect: '/login', session: false }),
//  (req, res) => { //
// we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
// we'll do it later, right now we'll just say 'Hello ' and the name of the user that we get from the `req.user` object provided by passport
//    res.send(`Hello ${req.user.username}`)
//  }
// )

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Just for testing, send the JWT directly to the browser. Later on we should send the token inside a cookie.
    // res.json(token)

    // Challenge1
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
