require('dotenv').config()
const express = require('express')
const path = require('path')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcryptjs')

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
            // messages can be accessed in req.session.messages
            if (!user) {
                return done(null, false, { message: 'Incorrect username' })
            }
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    return done(null, user)
                } else {
                    return done(null, false, { message: 'Incorrect Password' })
                }
            })
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


// store session information in mongo
const MongoDBStore = require('connect-mongodb-session')(session) // integrates express-session to the package
var store = new MongoDBStore({ uri: process.env.MONGODB_URI, collection: 'sessions' })
// event listener for any errors
store.on('error', function (error) {
    console.log(error)
})


// middelware initialized with the session object with options, including using mongo db as a store
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true, store: store }))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))


app.use(function (req, res, next) {
    res.locals.currentUser = req.user
    console.log('res.locals.currentUser')
    console.log(req.user)
    next()
})


app.get('/', (req, res) => {
    let messages = []
    if (req.session.messages) {
        messages = req.session.messages
        req.session.messages = []
    }
    res.render('index', { messages }) // user is stored in the locals.currentUser
})


app.post(
    '/log-in',
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/',
        failureMessage: true // put messages into array req.session.messages
    })
)

app.get('/log-out', (req, res, next) => {
    req.session.destroy(function (err) {
        res.redirect('/')
    })
})


// tutorial asks to switch to req.session.destroy to remove session information
// my understanding when using Passport, it's better to call .logut
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
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        await User.create({ username: req.body.username, password: hashedPassword })
        res.redirect('/')
    } catch (err) {
        return next(err)
    }
})


const authMiddleware = (req, res, next) => {
    if (!req.user) {
        if (!req.session.messages) {
            req.session.messages = []
        }
        req.session.messages.push(`You can't access that page before logon`)
        res.redirect('/')
    } else {
        next()
    }
}

app.get('/restricted', authMiddleware, (req, res) => {
    if (!req.session.pageCount) {
        req.session.pageCount = 1
    } else {
        req.session.pageCount += 1
    }
    res.render('restricted', { pageCount: req.session.pageCount })
})

app.listen(3000, () => console.log('app listening on port 3000!'))