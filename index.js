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

var { database } = include('databaseConnection'); // Original comment corrected

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

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


function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

// Routes with original comments

app.get('/', (req, res) => {
    res.render("index");
});

app.get('/nosql-injection', async (req,res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: "+username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {  
       console.log(validationResult.error);
       res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
       return;
    }   

    const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        res.render("loggedIn");
    }
});

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

app.get('/tryagain', (req, res) => {
    res.render("tryagain");
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({username, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.redirect("/signup");
       return;
   }
    var hashedPassword = await bcrypt.hash(password, saltRounds);
    
    await userCollection.insertOne({username: username, password: hashedPassword, user_type: "user"});
    console.log("Inserted user");

    var html = "successfully created user";
    res.render("submitUser", {html: html});
});

app.post('/login', (req, res) => {
    res.render("login");
});

app.get('/login', (req, res) => {
    res.render("loginGet");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;

    res.render("contact", {missing: missingEmail});
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});
// Promote the user by name
app.post("/promote/:name", async (req, res) => {
    var name = req.params.name; 
        await userCollection.findOneAndUpdate(
            { name: name }, // Find the user by name
            { $set: { user_type: "admin" } }
        );
        res.redirect("/admin");
    }
);

// Demote the user by name
app.post("/demote/:name", async (req, res) => {
    var name = req.params.name;

        await userCollection.findOneAndUpdate(
            { name: name }, // Find the user by name
            { $set: { user_type: "user" } }
        );
        res.redirect("/admin");
    }
);

app.get('/members', (req, res) => {
    const isAuthenticated = req.session.authenticated === true;

    if (!isAuthenticated) {
        return res.redirect("/login");
    } else {
        const name = req.session.name;

        res.render("members", {
            authenticated: isAuthenticated,
            name: name,
        });
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, _id: 1, }).toArray();
 
    res.render("admin", {users: result});
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
