const express = require("express");
const app = express();
const path = require("path");

const { pool } = require("./dbConfig");

const bcrypt = require("bcrypt");

const session = require("express-session");
const flash = require("express-flash");

const passport = require("passport");

const initializePassport = require("./passportConfig");

initializePassport(passport);

const PORT = process.env.PORT || 4000;

app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: "secret",

    resave: false,

    saveUninitialized: false
}));

app.use(flash());

app.use(passport.initialize());

app.use(passport.session());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/register', checkAuthenticated, (req, res) => {
    res.render('register');
});

app.get('/login', checkAuthenticated, (req, res) => {
    res.render('login');
});

app.get("/final", checkNotAuthenticated, (req, res) => {
    console.log(req.isAuthenticated());
    res.render("final", { user: req.user.fullname });
});

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/login'); // Redirect the user after logout
    });
});


app.post('/register', async (req, res) => {

    let { name, email, password, confirmpassword } = req.body;

    console.log({ name, email, password, confirmpassword });

    let errors = [];

    if (!name || !email || !password || !confirmpassword) {
        errors.push({ message: "Please enter all the fields" });
    }

    if (password.length < 6) {
        errors.push({ message: "Password should be at least 6 characters" });
    }

    if (password != confirmpassword) {
        errors.push({ message: "Password do not match" });
    }

    if (errors.length > 0) {
        res.render("register", { errors });
    }
    else {
        // no errors, form validation has passed
        let hashedPassword = await bcrypt.hash(password, 10); // 10 - rounds of encryption
        console.log(hashedPassword);

        pool.query(
            `SELECT * from users WHERE email = $1`, [email], (err, results) => {
                if (err) {
                    throw err
                }
                console.log(results.rows)

                if (results.rows.length > 0) {
                    errors.push({ message: "Email already registered" });
                    res.render("/register", { errors })
                }
                else {
                    pool.query(
                        `INSERT INTO users (fullname, email, password) 
                            VALUES ($1, $2, $3)
                                RETURNING id, password`, [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', 'You are succesfully registered. Please login to continue');
                            res.redirect('/login');
                        });
                }
            });
    }
});

app.post('/login',
    passport.authenticate('local', {
        successRedirect: "/final",
        failureRedirect: "/login",
        failureFlash: true
    }));

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/final');
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
