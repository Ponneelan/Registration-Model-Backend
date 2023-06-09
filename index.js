// import express, cors, mysql , dotenv, bcrypt
const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');


//create express app
const app = express();
app.use(express.json());
app.use(cors());


//connect mysql
const connection = mysql.createConnection({
    host: process.env.HOST_NAME,
    user: process.env.USER_NAME,
    password: process.env.PASSWORD,
    database: process.env.DB_NAME
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Database connected');
});

//create mail transporter verify transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

transporter.verify((err, success) => {
    if (err) {
        console.log(err);
    }
    if (success) {
        console.log('Mail Server is ready to take messages');
    }
});


//create function to sent mail to user using nodemailer transporter
const sendMail = (email, token, res,) => {
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Verify your account',
        html: `<h1>Click on the link to verify your account</h1><br/> <p>${process.env.DOMAIN}/verify/?token=${token}</p>`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            res.status(400).json({ err: '5.something went wrong' });
        }
        if (info) {
            res.send({ success: 'check your email to verify your account' });
        }
    }
    );
};




// step1: create route signup
// step2: get username,email,password as data from body and  add validation for username, email, password
// step3: use bcrypt to hash password
// step4: verify email does not exist in user table if exist then check isVerified column is 0 or 1 if 0 then send mail to user to verify account else send response as error
// step5: if success  insert into database and table name users and use ? in sql query to prevent sql injection else send response as own error  message
// step6: if success create jwt token using hash password 
// step7: sent mail with jwt token as parameter in href link to user email to verify account
// step8: if error send response as error and success as success

app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;
    if ((username && username !== null && username !== undefined && username !== '') && (email && email !== null && email !== undefined && email !== '') && (password && password !== null && password !== undefined && password !== '')) {
        const hash = bcrypt.hashSync(password, 10);
        const token = jwt.sign({ mail: email, username: username }, process.env.SECRET_KEY);
        connection.query('SELECT * FROM users WHERE email=?', [email], (err, result) => {
            if (err) {
                res.status(400).json({ err: '1.something went wrong' });
            }
            if (result.length > 0) {
                if (result[0].isVerified === 0) {
                    sendMail(email, token, res);
                } else {
                    res.status(400).json({ err: '2.something went wrong' });
                }
            }
            if (result.length === 0) {
                connection.query('INSERT INTO users (username,email,password) VALUES (?,?,?)', [username, email, hash], (err, result) => {
                    if (err) {
                        res.status(400).json({ err: '3.something went wrong' });
                    }
                    if (result) {
                        sendMail(email, token, res);
                    }
                });
            }
        });
    }else{
        res.status(400).json({ err: '4.something went wrong' });
    }
});

// step1: create route verify
// step2: get token from body and add validation for token
// strp3: if token is not null then verify token using jwt verify method  else send response as error
// step4: if success update isVerified column in users table
// step5: if error send response as error and success as success.


app.put('/verify', (req, res) => {
    const { token } = req.body;
    if (token && token !== null && token !== undefined && token !== '') {
        jwt.verify(token, process.env.SECRET_KEY, (err, result) => {
            if (err) {
                res.status(400).json({ err: 'something went wrong' });
            }
            if (result) {
                connection.query('UPDATE users SET isVerified=? WHERE email=?', [1, result.mail], (err, result) => {
                    if (err) {
                        res.status(400).json({ err: 'something went wrong' });
                    }
                    if (result) {
                        res.send({ success: 'your account is verified' });

                    }
                });
            }
        });
    } else {
        res.status(400).json({ err: 'something went wrong' });
    }
});

// step1: create route login
// step2: get email,password from body and add validation for email,password
// step3: if email and password is not null then verify email exist in users table
// step4: if email exist then verify isVerified column is 0 or 1 if 0 then send mail to user to verify account else send response as error
// step5: if email does not exist then send response as error
// step6: if email exist and isVerified column is 1 then verify password using bcrypt compare method
// step7: if password is correct then create jwt token using hash password and send response as success
// step8: if password is incorrect then send response as error

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if ((email && email !== null && email !== undefined && email !== '') && (password && password !== null && password !== undefined && password !== '')) {
        connection.query('SELECT * FROM users WHERE email=?', [email], (err, result) => {
            if (err) {
                res.status(400).json({ err: '1.something went wrong' });
            }
            if (result.length > 0) {
                if (result[0].isVerified === 0) {
                    const token = jwt.sign({ mail: email, username: result[0].username }, process.env.SECRET_KEY);
                    sendMail(email, token, res);
                } else {
                    const isMatch = bcrypt.compareSync(password, result[0].password);
                    if (isMatch) {
                        const token = jwt.sign({ mail: email, username: result[0].username }, process.env.SECRET_KEY);
                        res.status(200).json({ token: token });
                    } else {
                        res.status(400).json({ err: '2.something went wrong' });
                    }
                }
            }
            if (result.length === 0) {
                res.status(400).json({ err: '3.something went wrong' });
            }
        });
    } else {
        res.status(400).json({ err: '4.something went wrong' });
    }
});




//create listen port user port from .env file
app.listen(process.env.SERVER_PORT, () => {
    console.log(`Server is running on port ${process.env.SERVER_PORT}`);
});


