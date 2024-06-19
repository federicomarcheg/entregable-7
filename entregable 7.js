const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});


userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next()
    } catch (error) {
        next(error);
    }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);

};

const user = mongoose.model('user', userSchema);
module.exports = user;




const LocalStrategy = require('passport-local').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');

module.exports = function(passport) {
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        user.findByid(id, (err, user) => {
            done(err, user);
        });
    });


    passport.use(new LocalStrategy (async (username, password, done) => {
        try {
            const user = await User.findOne({ username });
            if (!user) {
                return done(null, false, {message: 'incorrect username.'});
            }
            const isMatch = await 
            user.comparePassword(password);
            if (!isMatch) {
                return done(null, false, {message: 'incorrect password.'});
            }
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }));


    passport.use(new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/github/callback"
    })),

    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await 
            user.findOne({ githubId: profile.id });
            if (!user) {
                user = new user ({ username: profile.username, githubId: profile.id });
                await user.save();
            }
            return done(null, user);

        } catch (error) {
            return done(error);
        }
    }
    
};


const express = require('express');
const passport = require('passport');
const router = express.router();
const User = require('../models/user');

router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const newUser = new user({ username, password });
        await newUser.save();
        res.redirect('/login');
    } catch (error) {
        res.status(400).sen('error al registrar al usuario')
    }
});


router.post('/login', passport.authenticate('local', {
    sucessRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

router.get('/auth/github', 
passport.authenticate('github', { scope: [ 'user:mail'] }));


router.get('/auth/github/callback', 
    passport.authenticate('github', { failureRedirect: '/login' })),
    (req, res) => {
        res.redirect('/')
    };


    const express = require('express');
    const mongoose = require('mongoose');
    const session = require('express-session');
    const passport = require('passport');
    const flash = require('connect-flash');
    require('dotenv').config();
    require('./config/passport')(passport);

    const app = express();

    mongoose.connect('mongodb://localhost/yourdatabase', { useNewUrlParser: true,
     useUnifiedTopology: true });

     app.use(express.urlemcoded({ extended: true }));

     app.use(session({
        secret: 'secret',
        resave: true,
        saveUninitialized: true
     }));

     app.use(passport.initialize());
     app.use(passport.session());
     app.use(flash());

     app.use(require('./routes/auth'));

     app.get('/', (req, res) => {
        res.send('welcome to the home paga!');
     });

     const PORT = process.env.PORT || 3000;
     app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
     });