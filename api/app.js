const express = require('express');
const app = express();

const {mongoose} = require('./db/mongooose')

const bodyParser = require('body-parser')
const {List, Password, User} = require('./db/models/index');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const key = 'your-secret-key';

app.use(bodyParser.json());

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE, PATCH");

    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});

let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if (err) {
            res.status(401).send(err)
        } else {
            req.user_id = decoded._id;
            next();
        }
    })
}


let verifySession = (req, res, next) => {
    let refreshToken = req.header('x-refresh-token');

    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if (!user) {
            return Promise.reject({
                'error': 'User not found. Make sure that the refresh token and user id are correct'
            });
        }
        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    isSessionValid = true;
                }
            }
        });

        if (isSessionValid) {
            next();
        } else {
            return Promise.reject({
                'error': 'Refresh token has expired or the session is invalid'
            })
        }
    }).catch((e) => {
        res.status(401).send(e);
    })
}


app.get('/all-passwords', authenticate, (req, res) => {
    List.find({
        _userId: req.user_id
    }).then((lists) => {
        const key = 'your-secret-key'; // replace with your own secret key

        // Decrypt password for each list item using AES algorithm
        const decryptedLists = lists.map(list => {
            const ciphertextPassword = list.password;
            const bytes = CryptoJS.AES.decrypt(ciphertextPassword, key);
            list.password = bytes.toString(CryptoJS.enc.Utf8);;
            return list;
        });

        res.send(decryptedLists);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('An error occurred while retrieving the passwords.');
    });
});

app.post('/create-password', authenticate, (req, res) => {
    let title = req.body.title;
    let titleAccount = req.body.titleAccount;
    let plaintextPassword = req.body.password;
    let togglePassword = req.body.togglePassword;

    // Encrypt password using AES algorithm
    const key = 'your-secret-key'; // replace with your own secret key
    const ciphertextPassword = CryptoJS.AES.encrypt(plaintextPassword, key).toString();

    let newList = new List({
        title,
        titleAccount,
        password: ciphertextPassword, // save encrypted password to database
        _userId: req.user_id,
        togglePassword
    });

    newList.save().then((listDoc) => {
        res.send(listDoc);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('An error occurred while saving the password.');
    });
});

app.patch('/edit-password/:id', authenticate, (req, res) => {
    const key = 'your-secret-key'; // replace with your own secret key

    // Encrypt password using AES algorithm
    const plaintextPassword = req.body.password;
    const ciphertextPassword = CryptoJS.AES.encrypt(plaintextPassword, key).toString();

    List.findOneAndUpdate({_id: req.params.id, _userId: req.user_id}, {
        $set: {
            title: req.body.title,
            titleAccount: req.body.titleAccount,
            password: ciphertextPassword, // save encrypted password
            togglePassword: req.body.togglePassword
        }
    }).then(() => {
        res.sendStatus(200);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('An error occurred while updating the password.');
    });
});

app.delete('/delete-password/:id', authenticate, (req, res) => {
    const key = 'your-secret-key'; // replace with your own secret key

    List.findOneAndDelete({_id: req.params.id, _userId: req.user_id}).then((removedListDoc) => {
        // Decrypt password using AES algorithm
        const ciphertextPassword = removedListDoc.password;
        const bytes = CryptoJS.AES.decrypt(ciphertextPassword, key);
        const plaintextPassword = bytes.toString(CryptoJS.enc.Utf8);

        // Update removedListDoc object with decrypted password
        const removedListDocWithDecryptedPassword = Object.assign({}, removedListDoc.toObject(), {password: plaintextPassword});

        res.send(removedListDocWithDecryptedPassword);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('An error occurred while deleting the password.');
    });
});

app.get('/find-password/:id', (req, res) => {
    const key = 'your-secret-key'; // replace with your own secret key

    List.findOne({_id: req.params.id}).then((task) => {
        // Decrypt password using AES algorithm
        const ciphertextPassword = task.password;
        const bytes = CryptoJS.AES.decrypt(ciphertextPassword, key);
        const plaintextPassword = bytes.toString(CryptoJS.enc.Utf8);

        // Update task object with decrypted password
        const taskWithDecryptedPassword = Object.assign({}, task.toObject(), {password: plaintextPassword});

        res.send(taskWithDecryptedPassword);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('An error occurred while finding the password.');
    });
});

app.post('/user/create', (req, res) => {
    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        return newUser.generateAccessAuthToken().then((accessToken) => {
            return {accessToken, refreshToken}
        })
    }).then((authToken) => {
        res
            .header('x-refresh-token', authToken.refreshToken)
            .header('x-access-token', authToken.accessToken)
            .send(newUser)
    }).catch((e) => {
        res.status(400).send(e);
    })
})


app.post('/user/login', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;
    let userName = req.body.userName;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            return user.generateAccessAuthToken().then((accessToken) => {
                return {accessToken, refreshToken}
            });
        }).then((authTokens) => {
            res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user)
        })
    }).catch((e) => {
        res.status(400).send(e);
    })
})

app.get('/users/me/access-token', verifySession, (req, res) => {
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({accessToken});
    }).catch((e) => {
        res.status(400).send(e);
    })
})


app.listen(3000, () => {
    console.log("Server is listening on port 3000")
})
