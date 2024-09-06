const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local')

const app = express();
let users = [];

app.use(express.urlencoded({extended: true}));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email,password, done) => {
    const user = users.find((user) => user.email === email);

    if (user === undefined){
        return done(null, null, {message: 'Incorect email'});
    }
    if (await bcrypt.compare(password,user.password )) {
        return done(null,user)
    }

    done(null,null,{message: "Incorrect password"})
}));

passport.serializeUser((user, done) => {
done(null,user.id)
});
passport.deserializeUser((id,done) => {
  done(null,users.find((user) => user.id === id))
})

function checkNotAuthentication (req,res,next) {
    if (req.isAuthenticated() === true) {
        return res.redirect("/")
    }
    next()
}
app.get('/register', checkNotAuthentication, (req,res) => {
    res.sendFile(path.resolve("views/register.html"));
});

app.post('/register', async (req,res)=> {
    const {name, email, password} = req.body;

    const hashedPwd = await bcrypt.hash(password, 10)
    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        email,
        password: hashedPwd
    })
    res.redirect('/login')
});

app.get('/login', checkNotAuthentication, (req,res) => {
    res.sendFile(path.resolve("views/login.html"));
});

app.post('/login', passport.authenticate('local', {
    successRedirect: "/",
    failureRedirect: "/register"
}));

function checkAuthentication (req,res,next) {
    if (req.isAuthenticated() === false) {
        return res.redirect("/login")
    }
    next();
}
app.use(checkAuthentication);

app.get('/', (req,res) => {
    res.sendFile(path.resolve("views/app.html"));
});

app.get('/logout',(req,res,next) => {
    req.logout(function(err) {
        if (err) {
            return next(err);
        }
        res.redirect('/login');
    });
})

app.listen(process.env.PORT)