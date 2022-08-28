const express = require('express');
const app = express();

const {mongoose} = require('./db/mongooose')

const bodyParser = require('body-parser')
const {List, Password, User} = require('./db/models/index');
const jwt = require('jsonwebtoken');


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


app.get('/all-passwords', authenticate,  (req, res) => {
    List.find({
        _userId: req.user_id
    }).then((lists) => {
        res.send(lists)
    }).catch((e) => {
        res.send(e);
    })
})

app.post('/create-password', authenticate,(req, res) => {
    let title = req.body.title
    let titleAccount = req.body.titleAccount
    let password = req.body.password
    let _userId = req.body._userId
    let togglePassword = req.body.togglePassword
    let newList = new List({
        title,
        titleAccount,
        password,
        _userId: req.user_id,
        togglePassword
    });
    newList.save().then((listDoc) => {
        res.send(listDoc)
    })
})

app.patch('/edit-password/:id', authenticate, (req, res) => {
    List.findOneAndUpdate({_id: req.params.id, _userId: req.user_id},{
        $set: req.body
    }).then(() => {
        res.sendStatus(200)
    });
});

app.delete('/delete-password/:id', authenticate, (req, res) => {
    List.findOneAndDelete({
        _id: req.params.id,
        _userId: req.user_id
    }).then((removedListDoc) => {
        res.send(removedListDoc)
    });
})

app.get('/find-password/:id', (req, res) => {
    List.findOne({
        _id: req.params.id

    }).then((task) => {
        res.send(task)
    })
})

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