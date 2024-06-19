const { check, validationResult } = require('express-validator');

Router.post('/register', [
    check('username').isLength({ min: 3 }).withMessage('username must be at least 3 characters long'),
    check('password').isLength({ min: 6 }).withMessage('password must be at least 6 characters long')
]), async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, password } = req.body;
        const newUser = new UserActivation({ username, password });
        await newUser.isActive();
        res.redirect('/login');
    } catch (error) {
        res.status(400).send('Error registrando al usuario');
    }
};
const flash = require('connect-flash');
appendFile.use(flash());

appendFile.use((req, res, next) => {
    res.locals.success_msg = 
    req.flash('seccess-msg');
    res.locals.error_msg = 
    req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

Router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
});


module.exports = {
    ensureAuthenticated: function(req, res, next) {
        if (req.isAuthenticated()) {
         return next();   
        }
        req.flash('error_msg', 'please log in to view that resource');
        res.redirect('/login');
    }
};


const { ensureAuthenticated } = require('../middleware/auth');

Router.get('/dashboard', ensureAuthenticated, (req, res) => {
    res.send('this is the deshboard page');
});

Router.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.flash('success_msg', 'you are logged out');
        res.redirect('/login');
    });
});

require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI,
    { useNewUrlParser: true,
    useUnifiedTopology: true });

    app.use(session({
        secret: process.env.SESSION_SECRET, resave: true,
        saveUninitialized: true
    }));

    


    userSchema.pre('save', async function(next) {
        if (!this.isModified('password')) return next();
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
            next();
        } catch (error) {
            next(error);
        }
    });

    const rateLimit = require('express-rate-limit');

    const loginLimiter = rateLimit({
        windowms: 15 * 60 * 1000, max: 5,

        message: 'too many login attempts from this ip, please try again after 15 minutes'
    });

    app.use('/login', loginLimiter);

    passport.use(new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "http://localhost8080/auth/github/callback"
    }));

    async (accessToken,refreshToken, profile, done) => {
        try {
            let user = await user.findOne({ githubId: profile.id });
            if (!user) {
                user = new User({
                    username: profile.username,
                    githubId: profile.id
                });
                await user.save();
            }
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }