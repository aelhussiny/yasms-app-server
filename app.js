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
                res.send({
                    ...err,
                    yasmscode: 2
                });
            } else {
                if (JSON.parse(unsignCS(body)).status && JSON.parse(unsignCS(body)).status == "success") {
                    sqlite.connect("./db/" + username + ".enc", dbkey.exportKey('private'));
                    sqlite.run("CREATE TABLE MYSIGNINGKEY(key TEXT PRIMARY KEY);", (resp) => {
                        if (resp.error)
                            throw res.error;
                    });
                    sqlite.run("CREATE TABLE MYIDENTITIES(identityname TEXT PRIMARY KEY);", (resp) => {
                        if (resp.error)
                            throw res.error;
                    });
                    sqlite.insert("MYSIGNINGKEY", {
                        key: signingkey.exportKey('private')
                    }, (resp) => {
                        if (resp.error)
                            throw res.error;
                    });
                    sqlite.close();
                    res.send(sign(appcommunicationkey.encrypt(JSON.stringify({
                        username: username,
                        key: dbkey.exportKey('private')
                    }), 'base64')));
                } else {
                    res.status(500);
                    res.send({
                        ...err,
                        yasmscode: 2
                    });
                }
            }
        });
    } catch (err) {
        res.status(500);
        res.send({
            ...err,
            yasmscode: 1
        });
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
                    res.send({
                        ...err,
                        yasmscode: 2
                    });
                } else {
                    res.send(sign(encryptForFE(body)));
                }
            });
        } else {
            res.status(403);
            res.send({
                "error": "Not logged in"
            });
        }
    } catch (err) {
        res.status(500);
        res.send({
            ...err,
            yasmscode: 2
        });
    }
});

app.post('/searchidentities', (req, res) => {
    // SEND REQUEST TO CENTRAL SERVER /SEARCHIDENTITIES WITH IDENTITY PARAM.
});

app.post('/requestchat/:identity', (req, res) => {
    // SEND REQUEST TO CENTRAL SERVER /REQUESTCHAT/:IDENTITY
    // RESPONSE CONTAINS ADDRESS. PING ADDRESS. IF FOUND, GO ON. ELSE RETURN ERROR
    // SEND REQUEST TO ADDRESS/RECEIVECHATREQUEST
    // ADD TO CHATREQUESTS DB TABLE OUTGOING REQUEST
});

app.post('/receivechatrequest', (req, res) => {
    // SEND REQUEST TO CENTRAL SERVER /REQUESTCHAT/:SENDER
    // TAKE PUBLIC KEY AND TRY TO DECRYPT REQUEST. IF WORKS, GO ON. ELSE RETURN ERROR
    // IF CHAT REQUEST IS RECENT, GO ON. ELSE RETURN ERROR
    // ADD TO CHATREQUESTS DB TABLE INCOMING REQUEST
});

app.post('/respondtochatrequest', (req, res) => {
    // SEND REQUEST TO CENTRAL SERVER /REQUESTCHAT/:SENDER
    // IF USER ADDRESS IS RECENTLY UPDATED, GO ON. ELSE RETURN ERROR
    // IF APPROVED
    // DELETE CHAT REQUEST FROM CHATREQUESTS DB TABLE
    // GENERATE KEY THAT SENDER CAN USE TO ENCRYPT MESSAGES
    // ADD KEY TO INCOMINGMESSAGEKEYS
    // SEND REQUEST TO SENDER/RECEIVEREQUESTRESPONSE WITH APPROVAL AND KEY
    // IF DISAPPROVED
    // DELETE CHAT REQUEST FROM CHATREQUESTS DB TABLE
    // SEND REQUEST TO SENDER/RECEIVEREQUESTRESPONSE WITH DISAPPROVAL
});

app.post('/receiverequestresponse', (req, res) => {
    // DELETE FROM DB TABLE CHATREQUESTS OUTGOING REQUEST
    // IF USER APPROVED, STORE KEY IN OUTGOINGMESSAGEKEYS
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
                                res.send({
                                    ...err,
                                    yasmscode: 2
                                });
                            } else {
                                res.send(sign(encryptForFE(body)));
                            }
                        });
                    }
                });
            } else {
                res.status(403);
                res.send({
                    message: "This account is not registerd on this device."
                });
            }
        } else {
            res.status(403);
            res.send({
                message: "Key file does not match provided username"
            });
        }
    } catch (err) {
        res.status(500);
        res.send({
            ...err,
            yasmscode: 1
        });
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
                    res.send({
                        ...err,
                        yasmscode: 2
                    });
                } else {
                    sqlite.insert("MYIDENTITIES", {
                        identityname: decryptedmessage.identityname
                    }, (resp) => {
                        if (resp.error)
                            throw res.error;
                        else {
                            myprofile.identities.push(decryptedmessage.identityname);
                            res.send(sign(encryptForFE(JSON.stringify({
                                "status": "success"
                            }))));
                        }
                    });
                }
            });
        } else {
            res.status(403);
            res.send({
                "error": "Not logged in"
            });
        }
    } catch (err) {
        res.status(500);
        res.send({
            ...err,
            yasmscode: 1
        });
    }
});

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
                    res.send({
                        ...err,
                        yasmscode: 2
                    });
                } else {
                    sqlite.run("DELETE FROM MYIDENTITIES WHERE identityname = ?", [decryptedmessage.identityname], (resp) => {
                        if (res.error) {
                            res.status(500);
                            res.send({
                                ...err,
                                yasmscode: 2
                            });
                        } else {
                            if (myprofile.identities.indexOf(decryptedmessage) > -1) {
                                myprofile.identities.splice(myprofile.identities.indexOf(req.body.identityname), 1);
                            }
                            res.send(sign(encryptForFE(JSON.stringify({
                                "status": "success"
                            }))));
                        }
                    });
                }
            });
        } else {
            res.status(403);
            res.send({
                "error": "Not logged in"
            });
        }
    } catch (err) {
        res.status(500);
        res.send({
            ...err,
            yasmscode: 1
        });
    }
});

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