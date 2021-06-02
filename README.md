# Express with Passport

## Challenge 1: Exchange the JWT using cookies
First we have to set the `cookie-parser` middleware:

```javascript
const cookieParser = require('cookie-parser')
app.use(cookieParser())
```
Then, we set the cookie with the response property when the user logs in the webpage:
```javascript
res.cookie('cookies', token, { maxAge: 60000, httpOnly: true })
```
Finally, we automatically redirect the user to the main webpage.

```javascript
res.redirect('/')
```

## Challenge 2: Create the fortune-teller endpoint
We want to change the `/` route to be our `fortune-teller`, but this endpoint will be authenticated (check if the cookie is correct) or redirect the user to the login page if not. We will use the Passport's JWT strategy for it:

```javascript
app.get('/',
 passport.authenticate('jwt', { failureRedirect: '/login', session: false }),
 (req, res) => {
   res.send(fortune.fortune())
 })
```
To build a cookie we will use the `cookieExtractor` function:

```javascript
const cookieExtractor = function (req) {
 let token = null
 if (req && req.cookies && req.cookies.token) {
   token = req.cookies.token
 }
 return token
}
```
In the `passport-jwt` strategy, we need to define the secret used to create the JWT and how the JWT is recovered, that is from the cookie in this case. We also defined a function that is called as a middleware if the verification is correct. The code of our jwt strategy is the following one:

```javascript
passport.use('jwt', new JWTStrategy(
 {
   jwtFromRequest: cookieExtractor,
   secretOrKey: jwtSecret
 },
 function (jwtPayload, done) {
   if (jwtPayload.sub === 'walrus') {
     const user = {
       username: 'walrus',
       description: 'the only user that deserves to contact the fortune teller'
     }
     return done(null, user)
   }
   return done(null, false)
 }))
```
The strategy will check that the cookie generated for the cookieExtractor function is the appropriate one, and will return the constant `user` only if the authentication of this cookie is correct.

## Challenge 3: Add a logout endpoint
We want to create a new route to logout the user. We can achieve this only by resetting the cookie. As the server is stateless, the only thing that stores the session is the cookie that we previously generated.

```javascript
app.get('/logout',
 (req, res) => {
   res.clearCookie('token')
   res.send('You have logged out.')
 }
)
```
## Challenge 4: Add bcrypt or scrypt to the login process
For this challenge, we firstly had to create a json file to store our usernames and their hashed passwords, named `users.json`. It was used the strong key derivation function `bcrypt` for creating the hashes. First, we had to add the bcrypt requirement to our code, also defining the value of the variable `saltRounds`, which will be used to compute the hashes, and we calculated the hash of the passwords that our users had:

```javascript
const bcrypt = require('bcrypt')
const saltRounds = 10
bcrypt.hash('nsaa2021', saltRounds,
 (err, hash) => {
   console.log(hash)
 })
```

Once we had our file ready with the usernames and hashed passwords, we had to change the strategies. Now, when the user logs in, we must compare the provided password with the one stored in our file using the `passport's local strategy`. To achieve this, we used the `compare` function included in the bcrypt package.


```javascript
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
```
```javascript
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
   return done(null, false)
 }))
```

## OAuth with GitHub
After creating an OAuth application on GitHub, we can add a new strategy on our express-app.

```javascript
const GitHubStrategy = require('passport-github2').Strategy

passport.use('github', new GitHubStrategy({
    clientID: '...',
    clientSecret: '...',
    callbackURL: "http://localhost:3000/oauth2/token" //the callback of our OAuth application
  },
  function(accessToken, refreshToken, profile, done) {
    user = {githubId: profile.id, username:profile.username}
    return done(null, user)
  }
  ))
```
In order to use it, we add the following code

```javascript
app.get('/auth/github',
    passport.authenticate('github', { scope: [ 'user:email' ] }),
    (req, res) => {
        res.redirect('/')
    }
)

app.get('/oauth2/token', 
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
    
        // generate a signed json web token.
    
        const token = jwt.sign(jwtClaims, jwtSecret)
    
        res.cookie('token', token, { maxAge: 60000, httpOnly: true })
        res.redirect('/')
        console.log('Cookies created successfully')
    
      }
  );
```

Moreover, we have also changed a little bit the jwt Strategy code because now our user is external
```javascript
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
    return done(null, false) // in passport returning false as the user object means that the authentication process failed.
  }))
```
## Radius
Now we have a Radius server, and we want to add a login page for the users that have been registered in this server. In order to create a new strategy, we first need the Node's support for Radius:
```javascript
const radius = require('radius');
const dgram  = require("dgram");
const RADIUS_SECRET = "..."
const RADIUS_IP     = "127.0.0.1";
const RADIUS_PORT   = 1812;
```

The new Radius local strategy is the following one:

```javascript
passport.use('radius', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    session      : false
},
function (username, password, done) {
    username = username
    // Radius request
    var request = radius.encode({
        code: "Access-Request",
        secret: RADIUS_SECRET,
        attributes: [
            ['NAS-IP-Address', RADIUS_IP],
            ['User-Name', username],
            ['User-Password', password],
        ]
    })
    // start a socket for communication
    var rclient = dgram.createSocket("udp4");
    // prepare reception routine
    rclient.on('message', function(message) {
        var response = radius.decode({packet: message, secret: RADIUS_SECRET})
        // check validation
        var valid_response = radius.verify_response({ 
            response: message,
            request : request,
            secret  : RADIUS_SECRET
        })
        var isValidPass = valid_response && (response.code == 'Access-Accept');
        // give access (or not)
        if (isValidPass) {
            const user = { username: username, description: 'A good user' }
            return done(null, user)
        }
        return done(null, false)
    })
    // send request 
    rclient.send(request, 0, request.length, RADIUS_PORT, RADIUS_IP);
}))
```

Now we can define our endpoint for the Radius log in:
```javascript
app.get('/login_radius', (req, res) => {
    res.sendFile('login_radius.html', {root: __dirname})
})

// Create Radius login token
app.post('/login_radius',
    passport.authenticate('radius', { failureRedirect: '/login_radius', session: false }),
    (req, res) => {
        
        const jwtClaims = {
          sub: req.user.username,
          iss: 'localhost:3000',
          aud: 'localhost:3000',
          exp: Math.floor(Date.now() / 1000) + 604800,
          // 1 week (7×24×60×60=604800s) from now
          role: 'user',
        }
    
        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('token', token, { maxAge: 60000, httpOnly: true })
        res.redirect('/')
      }
)
```
