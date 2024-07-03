const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const customer_routes = require('./router/auth_users.js').authenticated;
const authenticatedUser = require('./router/auth_users.js').authenticatedUser;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer", session({secret:"fingerprint_customer", resave: true, saveUninitialized: true}))

app.use("/customer/auth/*", function auth(req,res,next){
    const username = req.body.username;
    const password = req.body.password;

    if (!req.session.authorization) {
        // Check if username or password is missing
        if (!username || !password) {
            return res.status(404).json({ message: "Error logging in" });
        }

        if (authenticatedUser(username, password)) {
            // Generate JWT access token
            let accessToken = jwt.sign({
                data: password
            }, 'access', { expiresIn: 3600 });

            // Store access token and username in session
            req.session.authorization = {
                accessToken, username
            }
            return res.status(200).send("Customer successfully logged in");
        }
        else {
            return res.status(208).json({ message: "Invalid Login. Check username and password" });
        }
    } 
    else {
        const token = req.session.authorization['accessToken'];

        jwt.verify(token, "access", (err, user) => {
            if (!err) {
                req.user = user;
                next();
            }
            else {
                return res.status(403).json({ message: "Customer not authenticated" });
            }
        });
    }
});

const PORT = 5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT, ()=>console.log("Server is running"));
