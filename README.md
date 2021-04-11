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



