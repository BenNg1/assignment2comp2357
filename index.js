require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

/* Secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));
//1
//we want a homepage with a sign up and login
//not logged in = sign up / log in option
//logged in = hello "name"
// go to members area / logout options
app.get('/', (req, res) => {
    var html = `
        <h1>Hello friend</h1>
        <button onclick="window.location.href='/signup'">Sign up</button>
        <form action='/login' method='post'>
            <button>Login</button>
        </form>
    `;
    res.send(html);
});
//loggin get
app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        var html = `
            You are logged in!
            <form action='/members' method='get'>
                <button>Go to members page</button>
            </form>
        `;
        res.send(html);
    }
});
//login post
app.post('/loggingin', async (req, res) => {
    var name = req.body.name;
    var password = req.body.password;

    const result = await userCollection.find({ name: name }).project({ name: 1, password: 1, _id: 1 }).toArray();

    if (result.length != 1 || !(await bcrypt.compare(password, result[0].password))) {
        res.redirect("/tryagain");
    } else {
        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/loggedIn');
    }
});

//try again
app.get('/tryagain', (req, res) => {
    var html = `
        Incorrect password. <br>
        <form action='/login' method='post'>
            <button>Try again</button>
        </form>
    `;
    res.send(html);
});

// sign up
// we now have to setup the post using method: get // yeah
// there will be a form with name, email and password // done
// the signup form will POST the form fields. // yeah
// must validate that all are filled, and are not empty // yeah
// if 3 fields are filled, add the user to your MongoDB, name email and bcrypted password //12:16 start 
// then create a session and send the user to /members page
// sign up
// pre much my create user  
app.get('/signup', (req, res) => {
    var html = `
        Signup 
        <form action='/submitUser' method='post'>
            <input name='name' type='text' placeholder='Name'>
            <br><input name='email' type='text' placeholder='Email'>
            <br><input name='password' type='password' placeholder='Password'>
            <br><button type='submit'>Sign up</button>
        </form>
    `;
    res.send(html);
});

// validate the mfs
app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    // Check if name, email, or password fields are empty
    if (!name) {
        var errorMessage = "Name is required. Please try again.";
        errorMessage += '<a href="/signup">Try again</a>';
        return res.send(errorMessage);
    }

    if (!email) {
        var errorMessage = "Email is required. Please try again.";
        errorMessage += '<a href="/signup">Try again</a>';
        return res.send(errorMessage);
    }

    if (!password) {
        var errorMessage = "Password is required. Please try again.";
        errorMessage += '<a href="/signup">Try again</a>';
        return res.send(errorMessage);
    }

    // Encrpyt the mf
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the user into the database
    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });

    // Redirect to the "/members" page after successful signup

    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/login', (req, res) => {
    var html = `
        log in
        <form action='/loggingin' method='post'>
            <input name='name' type='text' placeholder='name'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});
app.get('/login', (req, res) => {
    var html = `
        log in
        <form action='/loggingin' method='post'>
            <input name='name' type='text' placeholder='name'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    var html = `
        You are logged out. <br>
        <button onclick="window.location.href='/login'">Back to Login</button>
    `;
    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/login");
    } else {
        //imageees?
        const name = req.session.name;
        const randId = Math.floor(Math.random() * 2) + 1;
        const img = ['minion.png', 'minion2.png'];
        const randomImg = img[randId - 1];
        const html = `
            <h1>Hello, ${name}</h1>
            <img src="${randomImg}" style="width:250px;">
            <br>
            <button onclick="window.location.href='/logout'">Sign out</button>
        `;
        res.send(html);
    }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404).send("Page not found - 404");
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
