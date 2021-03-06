const express = require('express')
const sqlite = require('sqlite-cipher');
const http = require('http');
const bodyParser = require('body-parser');
const NodeRSA = require('node-rsa');
const request = require('request');
const os = require('os');
const ifaces = os.networkInterfaces();
const fs = require('fs');

const app = express()
const myprofile = {}
const timetolive = 5000;
let centralserver = "";

let servercommunicationkey = new NodeRSA().generateKeyPair(1024);
let serversigningkey = new NodeRSA().generateKeyPair(1024);
let centralservercommunicationkey;
let centralserversigningkey;

request.post(process.argv[2] + "/ping", (err, serres, body) => {
    if (err || serres.statusCode !== 200) {
        console.error("Problem connecting to central server " + process.argv[2]);
        process.exit();
    } else {
        centralserver = process.argv[2];
        centralservercommunicationkey = new NodeRSA(JSON.parse(body).keys.communication);
        centralserversigningkey = new NodeRSA(JSON.parse(body).keys.signing);
    }
});

app.set('port', process.env.PORT || process.argv[3] || 3010);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

app.all('/ping', (req, res) => {
    res.send({
        status: "online",
        keys: {
            communication: servercommunicationkey.exportKey('public'),
            signing: serversigningkey.exportKey('public')
        }
    });
});

const sign = (msg) => {
    return serversigningkey.encryptPrivate(msg, 'base64');
}

const encryptForFE = (msg) => {
    return myprofile.appcommunicationkey.encrypt(msg, 'base64');
}

const encryptForCS = (msg) => {
    return centralservercommunicationkey.encrypt(msg, 'base64');
}

const encryptForFriend = (friendkey, msg) => {
    return friendkey.encrypt(msg, 'base64');
}

const unsignFriend = (friendkey, msg) => {
    return friendkey.decryptPublic(msg).toString('utf-8');
}

const decryptFriend = (friendkey, msg) => {
    return friendkey.decrypt(msg).toString('utf-8');
}

const decryptFromFE = (msg) => {
    return servercommunicationkey.decrypt(msg).toString('utf-8');
}

const unsignFE = (msg) => {
    return myprofile.appsigningkey.decryptPublic(msg).toString('utf-8');
}

const unsignCS = (msg) => {
    return centralserversigningkey.decryptPublic(msg).toString('utf-8');
}

const signAsUser = (msg) => {
    return myprofile.signingkey.encryptPrivate(msg, 'base64');
}

app.post('/register', (req, res) => {
    try {
        const dbkey = new NodeRSA().generateKeyPair(1024);
        const signingkey = new NodeRSA().generateKeyPair(1024);
        const decryptedmessage = JSON.parse(decryptFromFE(req.body.message));
        const username = decryptedmessage.username;
        const appcommunicationkey = new NodeRSA(decryptedmessage.communicationkey);
        request.post({
            url: centralserver + "/register",
            body: {
                message: JSON.stringify({
                    username: decryptedmessage.username,
                    key: signingkey.exportKey('public'),
                    address: getIP() + ":" + app.get('port')
                })
            },
            json: true
        }, (err, serres, body) => {
            if (err || serres.statusCode !== 200) {
                res.status(500);

                res.send(sign(JSON.stringify({
                    "yasmscode": 2
                })));

            } else {
                body = unsignCS(body);
                if (JSON.parse(body).status && JSON.parse(body).status == "success") {
                    sqlite.connect("./db/" + username + ".enc", dbkey.exportKey('private'));
                    sqlite.run("CREATE TABLE MYSIGNINGKEY(key TEXT PRIMARY KEY);", (resp) => {
                        if (resp.error) {
                            res.status(500);

                            res.send(sign(JSON.stringify({
                                "yasmscode": 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE MYIDENTITIES(identityname TEXT PRIMARY KEY);", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE RECEIVEDFRIENDREQUESTS(sender TEXT, receiver TEXT, status INTEGER, receivedat TEXT NOT NULL, PRIMARY KEY (sender, receiver, status));", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE SENTFRIENDREQUESTS(receiver TEXT, sender TEXT, status INTEGER, sentat TEXT NOT NULL, PRIMARY KEY (receiver, sender, status));", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE INCOMINGMESSAGEKEYS(for TEXT, talkingto TEXT, key TEXT NOT NULL, createdat TEXT NOT NULL, PRIMARY KEY(for, talkingto));", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE OUTGOINGMESSAGEKEYS(for TEXT, talkingto TEXT, key TEXT NOT NULL, createdat TEXT NOT NULL, PRIMARY KEY(for, talkingto));", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });
                    sqlite.run("CREATE TABLE MESSAGES(sender TEXT, receiver TEXT, sentat TEXT, messagetext TEXT);", (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send(sign(JSON.stringify({
                                ...resp,
                                yasmscode: 300
                            })));
                        }
                    });

                    sqlite.insert("MYSIGNINGKEY", {
                        key: signingkey.exportKey('private')
                    }, (resp) => {
                        if (resp.error) {
                            res.status(500);
                            res.send({
                                ...resp,
                                yasmscode: 300
                            });
                        }
                    });
                    sqlite.close();
                    res.send(sign(appcommunicationkey.encrypt(JSON.stringify({
                        username: username,
                        key: dbkey.exportKey('private')
                    }), 'base64')));
                } else {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                }
            }
        });
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/updateaddress', (req, res) => {
    try {
        if (myprofile.username) {
            request.post({
                url: centralserver + "/updateaddress",
                body: {
                    username: myprofile.username,
                    command: signAsUser(JSON.stringify({
                        command: "updateaddress",
                        address: getIP() + ":" + app.get('port'),
                        timestamp: (new Date()).getTime()
                    }))
                },
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        res.send(sign(encryptForFE(body)));
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 3
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 2
        })));
    }
});

app.post('/searchidentities', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username) {
            request.post({
                url: centralserver + "/searchidentities",
                body: {
                    username: myprofile.username,
                    command: signAsUser(JSON.stringify({
                        command: "searchidentities",
                        query: decryptedmessage.query,
                        timestamp: (new Date()).getTime()
                    }))
                },
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        res.send(sign(encryptForFE(body)));
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 3
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/sendchatrequest/', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        const identitynameto = decryptedmessage.identitynameto;
        const identitynamefrom = decryptedmessage.identitynamefrom;
        if (myprofile.username) {
            request.post({
                url: centralserver + "/requestchat/" + identitynameto,
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        const userdata = JSON.parse(body);
                        userdata.key = new NodeRSA(userdata.key);
                        request.post({
                            url: 'http://' + userdata.address + "/ping",
                            json: true
                        }, (err, serres, body) => {
                            if (err || serres.statusCode !== 200) {
                                res.status(500);
                                res.send(sign(JSON.stringify({
                                    error: err,
                                    yasmscode: 3
                                })));
                            } else {
                                userdata.servercommunicationkey = new NodeRSA(body.keys.communication);
                                userdata.serversigningkey = new NodeRSA(body.keys.signing);
                                const now = (new Date()).getTime();
                                request.post({
                                    url: 'http://' + userdata.address + "/receivechatrequest",
                                    body: {
                                        "from": identitynamefrom,
                                        "message": signAsUser(encryptForFriend(userdata.servercommunicationkey, JSON.stringify({
                                            "command": "requestchat",
                                            "from": identitynamefrom,
                                            "to": identitynameto,
                                            "timestamp": now
                                        })))
                                    },
                                    json: true
                                }, (err, serres, body) => {
                                    if (err || serres.statusCode !== 200) {
                                        res.status(500);
                                        res.send(sign(JSON.stringify({
                                            error: err,
                                            body: body,
                                            yasmscode: 4
                                        })));
                                    } else {
                                        body = userdata.key.decryptPublic(body).toString('utf-8');
                                        if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                                            sqlite.insert("SENTFRIENDREQUESTS", {
                                                sender: identitynamefrom,
                                                receiver: identitynameto,
                                                sentat: now,
                                                status: 0
                                            }, (resp) => {
                                                if (resp.error) {
                                                    res.status(500);
                                                    res.send(sign(JSON.stringify({
                                                        ...resp,
                                                        yasmscode: 300
                                                    })));
                                                } else {
                                                    res.send(sign(encryptForFE(body)));
                                                }
                                            });
                                        } else {
                                            res.status(401);
                                            res.send(sign(JSON.stringify({
                                                error: "Problem communicating with friend's server",
                                                yasmscode: 5
                                            })));
                                        }
                                    }
                                });
                            }
                        });
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 6
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/receivechatrequest', (req, res) => {
    try {
        const from = req.body.from;
        const now = (new Date()).getTime();
        if (myprofile.username) {
            request.post({
                url: centralserver + "/requestchat/" + from,
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        const userdata = JSON.parse(body);
                        userdata.key = new NodeRSA(userdata.key);
                        const decryptedmessage = JSON.parse(decryptFromFE(unsignFriend(userdata.key, req.body.message)));
                        if (
                            decryptedmessage.command === "requestchat" &&
                            from === decryptedmessage.from &&
                            myprofile.identities.indexOf(decryptedmessage.to) > -1 &&
                            decryptedmessage.timestamp >= now - timetolive &&
                            decryptedmessage.timestamp < now
                        ) {
                            sqlite.insert("RECEIVEDFRIENDREQUESTS", {
                                receiver: decryptedmessage.to,
                                sender: decryptedmessage.from,
                                receivedat: decryptedmessage.timestamp,
                                status: 0
                            }, (resp) => {
                                if (resp.error) {
                                    res.status(500);
                                    res.send(sign(JSON.stringify({
                                        ...resp,
                                        yasmscode: 300
                                    })));
                                } else {
                                    res.send(signAsUser((JSON.stringify({
                                        "status": "success"
                                    }))));
                                }
                            });
                        } else {
                            res.status(403);
                            res.send(sign(JSON.stringify({
                                error: "Invalid command"
                            })));
                        }
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 6
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/sendchatrequestresponse', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        const identitynamefrom = decryptedmessage.from;
        const identitynameto = decryptedmessage.to;
        const approved = decryptedmessage.approved;
        if (myprofile.username) {
            if (decryptedmessage.command === "sendchatrequestresponse") {
                const requester = decryptedmessage.from;
                request.post({
                    url: centralserver + "/requestchat/" + requester,
                    json: true
                }, (err, serres, body) => {
                    if (err || serres.statusCode !== 200) {
                        res.status(500);
                        res.send(sign(JSON.stringify({
                            error: err,
                            yasmscode: 2
                        })));
                    } else {
                        body = unsignCS(body);
                        if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                            const userdata = JSON.parse(body);
                            userdata.key = new NodeRSA(userdata.key);
                            request.post({
                                url: 'http://' + userdata.address + "/ping",
                                json: true
                            }, (err, serres, body) => {
                                if (err || serres.statusCode !== 200) {
                                    res.status(500);
                                    res.send(sign(JSON.stringify({
                                        error: err,
                                        yasmscode: 3
                                    })));
                                } else {
                                    userdata.servercommunicationkey = new NodeRSA(body.keys.communication);
                                    userdata.serversigningkey = new NodeRSA(body.keys.signing);
                                    const messagingkey = new NodeRSA().generateKeyPair(1024);
                                    let messagingkeystring = "";
                                    if (approved) {
                                        messagingkeystring = messagingkey.exportKey('public');
                                    }
                                    const now = (new Date()).getTime();
                                    request.post({
                                        url: 'http://' + userdata.address + "/receivechatrequestresponse",
                                        body: {
                                            "from": identitynameto,
                                            "message": signAsUser(encryptForFriend(userdata.servercommunicationkey, JSON.stringify({
                                                "command": "respondtochatrequest",
                                                "receiver": identitynameto,
                                                "sender": identitynamefrom,
                                                "timestamp": now,
                                                "approved": approved,
                                                "key": messagingkeystring
                                            })))
                                        },
                                        json: true
                                    }, (err, serres, body) => {
                                        if (err || serres.statusCode !== 200) {
                                            res.status(500);
                                            res.send(sign(JSON.stringify({
                                                error: err,
                                                body: body,
                                                yasmscode: 4
                                            })));
                                        } else {
                                            body = userdata.key.decryptPublic(body).toString('utf-8');
                                            if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                                                sqlite.runAsync("UPDATE OR REPLACE RECEIVEDFRIENDREQUESTS SET status = ? WHERE sender = ? AND receiver = ? AND status = 0", [approved ? 1 : -1, identitynamefrom, identitynameto], (resp) => {
                                                    if (resp.error) {
                                                        res.status(500);
                                                        res.send(sign(JSON.stringify({
                                                            ...resp,
                                                            yasmscode: 300
                                                        })));
                                                    } else {
                                                        if (approved) {
                                                            sqlite.insert("INCOMINGMESSAGEKEYS", {
                                                                for: identitynamefrom,
                                                                talkingto: identitynameto,
                                                                key: messagingkey.exportKey('private'),
                                                                createdat: now
                                                            }, (resp) => {
                                                                if (resp.error) {
                                                                    res.status(500);
                                                                    res.send({
                                                                        ...resp,
                                                                        yasmscode: 300
                                                                    });
                                                                } else {
                                                                    res.send(sign(encryptForFE(body)));
                                                                }
                                                            });
                                                        } else {
                                                            res.send(sign(encryptForFE(body)));
                                                        }
                                                    }
                                                });
                                            } else {
                                                res.status(401);
                                                res.send(sign(JSON.stringify({
                                                    error: "Problem communicating with friend's server",
                                                    yasmscode: 5
                                                })));
                                            }
                                        }
                                    });
                                }
                            });
                        } else {
                            res.status(401);
                            res.send(sign(JSON.stringify({
                                "error": "Problem with central server"
                            })));
                        }
                    }
                });
            } else {
                res.status(500);
                res.send(sign(JSON.stringify({
                    "error": "Invalid command"
                })));
            }
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/sendmessage', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        const identitynamefrom = decryptedmessage.from;
        const identitynameto = decryptedmessage.to;
        const message = decryptedmessage.message;
        const command = decryptedmessage.command;
        const timestamp = decryptedmessage.time;
        if (myprofile.username) {
            if (command === "sendmessage") {
                request.post({
                    url: centralserver + "/requestchat/" + identitynameto,
                    json: true
                }, (err, serres, body) => {
                    if (err || serres.statusCode !== 200) {
                        res.status(500);
                        res.send(sign(JSON.stringify({
                            error: err,
                            yasmscode: 9
                        })));
                    } else {
                        body = unsignCS(body);
                        if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                            const userdata = JSON.parse(body);
                            userdata.key = new NodeRSA(userdata.key);
                            request.post({
                                url: 'http://' + userdata.address + "/ping",
                                json: true
                            }, (err, serres, body) => {
                                if (err || serres.statusCode !== 200) {
                                    res.status(404);
                                    res.send(sign(JSON.stringify({
                                        error: err,
                                        yasmscode: 3
                                    })));
                                } else {
                                    userdata.servercommunicationkey = new NodeRSA(body.keys.communication);
                                    userdata.serversigningkey = new NodeRSA(body.keys.signing);
                                    sqlite.runAsync("SELECT * FROM OUTGOINGMESSAGEKEYS WHERE for = ? AND talkingto = ?", [identitynameto, identitynamefrom], (rows) => {
                                        if (rows) {
                                            const friendkey = new NodeRSA(rows[0].key);
                                            const now = (new Date()).getTime();
                                            request.post({
                                                url: 'http://' + userdata.address + "/receivemessage",
                                                body: {
                                                    "from": identitynamefrom,
                                                    "to": identitynameto,
                                                    "message": signAsUser(encryptForFriend(friendkey, JSON.stringify({
                                                        "command": "sendmessage",
                                                        "receiver": identitynameto,
                                                        "sender": identitynamefrom,
                                                        "timestamp": now,
                                                        "message": message,
                                                        "messagetime": timestamp
                                                    })))
                                                },
                                                json: true
                                            }, (err, serres, body) => {
                                                if (err) {
                                                    res.status(500);
                                                    res.send(sign(JSON.stringify({
                                                        error: err,
                                                        yasmscode: 4
                                                    })));
                                                } else if (serres.statusCode === 403) {
                                                    body = userdata.serversigningkey.decryptPublic(body).toString('utf-8');
                                                    if (JSON.parse(body).error && JSON.parse(body).error === "key not found") {
                                                        sqlite.run("DELETE FROM OUTGOINGMESSAGEKEYS WHERE for = ? AND talkingto = ?", [identitynameto, identitynamefrom], (resp) => {
                                                            if (resp.error) {
                                                                res.status(500);
                                                                res.send(sign(JSON.stringify({
                                                                    ...resp,
                                                                    yasmscode: 2
                                                                })));
                                                            } else {
                                                                res.status(403);
                                                                res.send(sign(JSON.stringify({
                                                                    "error": identitynameto + " refused message"
                                                                })));
                                                            }
                                                        });
                                                    } else {
                                                        res.status(401);
                                                        res.send(sign(JSON.stringify({
                                                            error: "Problem communicating with friend's server",
                                                            yasmscode: 5
                                                        })));
                                                    }
                                                } else if (serres.statusCode != 200) {
                                                    res.status(500);
                                                    res.send(sign(JSON.stringify({
                                                        error: "Other error",
                                                        yasmscode: 6,
                                                        body: body
                                                    })));
                                                } else {
                                                    body = userdata.key.decryptPublic(body).toString('utf-8');
                                                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                                                        sqlite.insert("MESSAGES", {
                                                            sender: identitynamefrom,
                                                            receiver: identitynameto,
                                                            sentat: timestamp,
                                                            messagetext: message
                                                        }, (resp) => {
                                                            if (resp.error) {
                                                                res.status(500);
                                                                res.send(sign(JSON.stringify({
                                                                    ...resp,
                                                                    yasmscode: 300
                                                                })));
                                                            } else {
                                                                res.send(sign(encryptForFE({
                                                                    "status": "success"
                                                                })));
                                                            }
                                                        });
                                                    } else {
                                                        res.status(401);
                                                        res.send(sign(JSON.stringify({
                                                            error: "Problem communicating with friend's server",
                                                            yasmscode: 7
                                                        })));
                                                    }
                                                }
                                            });
                                        } else {
                                            res.status(403);
                                            res.send(sign(JSON.stringify({
                                                error: "No key found for " + identitynameto,
                                                yasmscode: 8
                                            })));
                                        }
                                    });

                                }
                            });
                        } else {
                            res.status(401);
                            res.send(sign(JSON.stringify({
                                "error": "Problem with central server"
                            })));
                        }
                    }
                });
            } else {
                res.status(500);
                res.send(sign(JSON.stringify({
                    "error": "Invalid command"
                })));
            }
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/receivemessage', (req, res) => {
    try {
        const from = req.body.from;
        const to = req.body.to;
        const now = (new Date()).getTime();
        if (myprofile.username) {
            request.post({
                url: centralserver + "/requestchat/" + from,
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        const userdata = JSON.parse(body);
                        userdata.key = new NodeRSA(userdata.key);
                        sqlite.runAsync("SELECT * FROM INCOMINGMESSAGEKEYS WHERE for = ? AND talkingto = ?", [from, to], (rows) => {
                            if (rows && rows.length > 0) {
                                const friendkey = new NodeRSA(rows[0].key);
                                const decryptedmessage = JSON.parse(decryptFriend(friendkey, (unsignFriend(userdata.key, req.body.message))));
                                if (
                                    decryptedmessage.command === "sendmessage" &&
                                    decryptedmessage.timestamp >= now - timetolive &&
                                    decryptedmessage.timestamp < now &&
                                    decryptedmessage.sender === from &&
                                    decryptedmessage.receiver === to
                                ) {
                                    sqlite.insert("MESSAGES", {
                                        sender: decryptedmessage.sender,
                                        receiver: decryptedmessage.receiver,
                                        sentat: decryptedmessage.messagetime,
                                        messagetext: decryptedmessage.message
                                    }, (resp) => {
                                        if (resp.error) {
                                            res.status(500);
                                            res.send(sign(JSON.stringify({
                                                ...resp,
                                                yasmscode: 300
                                            })));
                                        } else {
                                            res.send(signAsUser({
                                                "status": "success"
                                            }));
                                        }
                                    });
                                } else {
                                    res.status(403);
                                    res.send(sign(JSON.stringify({
                                        error: "Invalid command"
                                    })));
                                }
                            } else {
                                res.status(403);
                                res.send(sign(JSON.stringify({
                                    error: "key not found"
                                })));
                            }
                        });
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 6
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/receivechatrequestresponse', (req, res) => {
    try {
        const from = req.body.from;
        const now = (new Date()).getTime();
        if (myprofile.username) {
            request.post({
                url: centralserver + "/requestchat/" + from,
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        const userdata = JSON.parse(body);
                        userdata.key = new NodeRSA(userdata.key);
                        const decryptedmessage = JSON.parse(decryptFromFE(unsignFriend(userdata.key, req.body.message)));
                        if (
                            decryptedmessage.command === "respondtochatrequest" &&
                            decryptedmessage.timestamp >= now - timetolive &&
                            decryptedmessage.timestamp < now
                        ) {
                            sqlite.runAsync("UPDATE OR REPLACE SENTFRIENDREQUESTS SET status = ? WHERE sender = ? AND receiver = ? AND status = 0", [decryptedmessage.approved ? 1 : -1, decryptedmessage.sender, decryptedmessage.receiver], (resp) => {
                                if (resp.error) {
                                    res.status(500);
                                    res.send(sign(JSON.stringify({
                                        ...resp,
                                        yasmscode: 300
                                    })));
                                } else {
                                    if (decryptedmessage.approved) {
                                        sqlite.insert("OUTGOINGMESSAGEKEYS", {
                                            for: decryptedmessage.receiver,
                                            key: decryptedmessage.key,
                                            createdat: decryptedmessage.timestamp,
                                            talkingto: decryptedmessage.sender
                                        }, (resp) => {
                                            if (resp.error) {
                                                res.status(500);
                                                res.send(sign(JSON.stringify({
                                                    ...resp,
                                                    yasmscode: 300
                                                })));
                                            } else {
                                                res.send(signAsUser((JSON.stringify({
                                                    "status": "success"
                                                }))));
                                            }
                                        });
                                    } else {
                                        res.send(signAsUser((JSON.stringify({
                                            "status": "success"
                                        }))));
                                    }
                                }
                            });
                        } else {
                            res.status(403);
                            res.send(sign(JSON.stringify({
                                error: "Invalid command"
                            })));
                        }
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 6
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.all('/query', (req, res) => {
    sqlite.runAsync(req.body.query, (rows) => {
        res.send({
            rows: rows
        });
    });
});

app.post('/cansend', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "cansend") {
            sqlite.runAsync("SELECT * FROM OUTGOINGMESSAGEKEYS WHERE for = ? AND talkingto = ?", [decryptedmessage.identitynameto, decryptedmessage.identitynamefrom], (rows) => {
                if (rows.length > 0) {
                    res.send(sign(encryptForFE(JSON.stringify({
                        "status": "success"
                    }))));
                } else {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        "error": "can't send"
                    })));
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/block', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "block") {
            sqlite.run("DELETE FROM INCOMINGMESSAGEKEYS WHERE for = ? AND talkingto = ?", [decryptedmessage.identitynamefrom, decryptedmessage.identitynameto], (resp) => {
                if (resp.error) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        ...resp,
                        yasmscode: 2
                    })));
                } else {
                    res.send(sign(encryptForFE(JSON.stringify({
                        "status": "success"
                    }))));
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/getmessages', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "getmessages") {
            sqlite.runAsync("SELECT * FROM MESSAGES WHERE (SENDER = ? AND RECEIVER = ?) OR (SENDER = ? AND RECEIVER = ?) ORDER BY sentat", [decryptedmessage.persona, decryptedmessage.personb, decryptedmessage.personb, decryptedmessage.persona], (rows) => {
                res.send(sign(encryptForFE({
                    status: "success",
                    messages: rows
                })));
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/getsentchatrequests', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "getsentchatrequests") {
            sqlite.runAsync("SELECT * FROM SENTFRIENDREQUESTS WHERE status = 0", [], (rows) => {
                res.send(sign(encryptForFE(rows)));
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/getreceivedchatrequests', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "getreceivedchatrequests") {
            sqlite.runAsync("SELECT * FROM RECEIVEDFRIENDREQUESTS WHERE status = 0", [], (rows) => {
                res.send(sign(encryptForFE(rows)));
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/getcontacts', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "getcontacts") {
            let contacts = [];
            const outgoing = [];
            const incoming = [];
            sqlite.runAsync("SELECT sender, receiver FROM SENTFRIENDREQUESTS WHERE status = 1", [], (rows) => {
                rows.forEach((row) => {
                    outgoing.push([row.receiver, row.sender]);
                });
                sqlite.runAsync("SELECT sender, receiver FROM RECEIVEDFRIENDREQUESTS WHERE status = 1", [], (rows) => {
                    rows.forEach((row) => {
                        incoming.push([row.sender, row.receiver]);
                    });
                    contacts = [
                        ...outgoing
                    ];
                    incoming.forEach((contact) => {
                        let found = false;
                        contacts.forEach((othercontact) => {
                            found = found || (othercontact[0] === contact[0] && othercontact[1] === contact[1]);
                        });
                        if (!found) {
                            contacts.push(contact);
                        }
                    });
                    res.send(sign(encryptForFE(contacts)));
                });
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/getidentities', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username && decryptedmessage.command === "getidentities") {
            res.send(sign(encryptForFE(JSON.stringify(myprofile.identities))));
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in or invalid command"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/login', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(req.body.message));
        const keyfile = decryptedmessage.keyfile;
        if (keyfile.username === decryptedmessage.username) {
            if (fs.existsSync("./db/" + decryptedmessage.username + ".enc")) {
                sqlite.connect("./db/" + decryptedmessage.username + ".enc", keyfile.key);
                sqlite.runAsync("SELECT key FROM MYSIGNINGKEY", [], (keyrows) => {
                    if (keyrows) {
                        sqlite.runAsync("SELECT identityname FROM MYIDENTITIES", [], (identityrows) => {
                            myprofile.identities = [];
                            if (identityrows) {
                                identityrows.forEach((idrow) => {
                                    myprofile.identities.push(idrow.identityname);
                                });
                            }
                        });
                        myprofile.username = decryptedmessage.username;
                        myprofile.signingkey = new NodeRSA(keyrows[0].key);
                        myprofile.appsigningkey = new NodeRSA(decryptedmessage.appsigningkey);
                        myprofile.appcommunicationkey = new NodeRSA(decryptedmessage.appcommunicationkey);
                        request.post({
                            url: centralserver + "/updateaddress",
                            body: {
                                username: myprofile.username,
                                command: signAsUser(JSON.stringify({
                                    command: "updateaddress",
                                    address: getIP() + ":" + app.get('port'),
                                    timestamp: (new Date()).getTime()
                                }))
                            },
                            json: true
                        }, (err, serres, body) => {
                            if (err || serres.statusCode !== 200) {
                                res.status(500);
                                res.send(sign(JSON.stringify({
                                    error: err,
                                    yasmscode: 2
                                })));
                            } else {
                                body = unsignCS(body);
                                if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                                    res.send(sign(encryptForFE(body)));
                                } else {
                                    res.status(401);
                                    res.send(sign(JSON.stringify({
                                        error: "Problem with central server",
                                        yasmscode: 3
                                    })))
                                }
                            }
                        });
                    }
                });
            } else {
                res.status(403);
                res.send(sign(JSON.stringify({
                    message: "This account is not registerd on this device."
                })));
            }
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                message: "Key file does not match provided username"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

app.post('/addidentity', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username) {
            request.post({
                url: centralserver + "/addidentity",
                body: {
                    username: myprofile.username,
                    command: signAsUser(JSON.stringify({
                        command: "addidentity",
                        identityname: decryptedmessage.identityname,
                        timestamp: (new Date()).getTime()
                    }))
                },
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        sqlite.insert("MYIDENTITIES", {
                            identityname: decryptedmessage.identityname
                        }, (resp) => {
                            if (resp.error) {
                                res.status(500);
                                res.send(sign(JSON.stringify({
                                    ...resp,
                                    yasmscode: 300
                                })));
                            } else {
                                myprofile.identities.push(decryptedmessage.identityname);
                                res.send(sign(encryptForFE(JSON.stringify({
                                    "status": "success"
                                }))));
                            }
                        });
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 3
                        })))
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});

/*
app.post('/deleteidentity', (req, res) => {
    try {
        const decryptedmessage = JSON.parse(decryptFromFE(unsignFE(req.body.message)));
        if (myprofile.username) {
            request.post({
                url: centralserver + "/deleteidentity",
                body: {
                    username: myprofile.username,
                    command: myprofile.signingkey.encryptPrivate(JSON.stringify({
                        command: "deleteidentity",
                        identityname: decryptedmessage.identityname,
                        timestamp: (new Date()).getTime()
                    }), 'base64')
                },
                json: true
            }, (err, serres, body) => {
                if (err || serres.statusCode !== 200) {
                    res.status(500);
                    res.send(sign(JSON.stringify({
                        error: err,
                        yasmscode: 2
                    })));
                } else {
                    body = unsignCS(body);
                    if (JSON.parse(body).status && JSON.parse(body).status === "success") {
                        sqlite.run("DELETE FROM MYIDENTITIES WHERE identityname = ?", [decryptedmessage.identityname], (resp) => {
                            if (resp.error) {
                                res.status(500);
                                res.send(sign(JSON.stringify({
                                    ...resp,
                                    yasmscode: 2
                                })));
                            } else {
                                if (myprofile.identities.indexOf(decryptedmessage) > -1) {
                                    myprofile.identities.splice(myprofile.identities.indexOf(req.body.identityname), 1);
                                }
                                res.send(sign(encryptForFE(JSON.stringify({
                                    "status": "success"
                                }))));
                            }
                        });
                    } else {
                        res.status(401);
                        res.send(sign(JSON.stringify({
                            error: "Problem with central server",
                            yasmscode: 3
                        })));
                    }
                }
            });
        } else {
            res.status(403);
            res.send(sign(JSON.stringify({
                "error": "Not logged in"
            })));
        }
    } catch (err) {
        res.status(500);
        res.send(sign(JSON.stringify({
            error: err,
            yasmscode: 1
        })));
    }
});
*/

const server = http.createServer(app);

const getIP = () => {
    let address = "";
    Object.keys(ifaces).forEach(function (ifname) {

        ifaces[ifname].forEach(function (iface) {
            if ('IPv4' !== iface.family || iface.internal !== false) {
                return;
            }
            address = iface.address;
        });
    });
    if (address && address.length > 0) {
        return address;
    } else {
        throw "Address could not be found";
    }
}

server.listen(app.get('port'), () => {
    console.log("Web Server started and listening on port " + app.get('port'));
});