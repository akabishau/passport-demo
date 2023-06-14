require('dotenv').config()
const express = require('express')
const path = require('path')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const mongoose = require('mongoose')
const Schema = mongoose.Schema

const mongoDb = process.env.MONGODB_URI
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true })
const db = mongoose.connection
db.on('error', console.error.bind(console, 'mongo connection error'))

const User = mongoose.model(
    'User',
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true }
    })
)

const app = express()
app.set('views', __dirname)
app.set('view engine', 'ejs')



passport.use(
    new LocalStrategy(async (username, password, done) => {
        console.log('LocalStrategy')
        try {
            const user = await User.findOne({ username: username })

            if (!user) {
                return done(null, false, { message: 'Incorrect username' })
            }
            if (user.password !== password) {
                return done(null, false, {message: 'Incorrect password' })
            }
            return done(null, user)
        } catch (err) {
            return done(err)
        }
    })
)

// creates session cookie stored in browser
passport.serializeUser(function (user, done) {
    console.log('passport.serializeUser')
    done(null, user.id)
})

passport.deserializeUser(async function (id, done) {
    try {
        const user = await User.findById(id)
        done(null, user)
    } catch (err) {
        done(err)
    }
})




app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))


app.use(function(req, res, next) {
    res.locals.currentUser = req.user
    console.log('res.locals.currentUser')
    console.log(req.user)
    next()
})


app.get("/", (req, res) => {
    res.render("index") // user is stored in the locals.currentUser
})


app.post(
    '/log-in',
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
)

app.get('/log-out', (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err)
        }
        res.redirect('/')
    })
})

app.get('/sign-up', (req, res) => res.render('sign-up-form'))
app.post('/sign-up', async (req, res, next) => {
    try {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        })
        const result = await user.save()
        res.redirect('/')
    } catch (err) {
        return next(err)
    }
})

app.listen(3000, () => console.log('app listening on port 3000!'))