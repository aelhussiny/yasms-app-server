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

request(process.argv[2] + "/ping", (err, serres, body) => {
    if (err) {
        console.error("Problem connecting to central server " + process.argv[2]);
        process.exit();
    } else {
        centralserver = process.argv[2];
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

app.post('/register', (req, res) => {
    try {
        const dbkey = new NodeRSA().generateKeyPair(1024);
        const signingkey = new NodeRSA().generateKeyPair(1024);
        const username = JSON.parse(servercommunicationkey.decrypt(req.body.message).toString('utf-8')).username;
        request.post({
            url: centralserver + "/register",
            body: {
                username: username,
                key: signingkey.exportKey('public'),
                address: getIP() + ":" + app.get('port')
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
                res.send(JSON.stringify({
                    username: username,
                    key: dbkey.exportKey('private')
                }));
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
                    command: myprofile.signingkey.encryptPrivate(JSON.stringify({
                        command: "updateaddress",
                        address: getIP() + ":" + app.get('port'),
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
                    res.send(body);
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
        const requestcontents = JSON.parse(servercommunicationkey.decrypt(req.body.message).toString('utf-8'));
        const keyfile = requestcontents.keyfile;
        if (keyfile.username === requestcontents.username) {
            if (fs.existsSync("./db/" + requestcontents.username + ".enc")) {
                sqlite.connect("./db/" + requestcontents.username + ".enc", keyfile.key);
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
                        myprofile.username = requestcontents.username;
                        myprofile.signingkey = new NodeRSA(keyrows[0].key);
                        myprofile.appsigningkey = new NodeRSA(requestcontents.appsigningkey);
                        request.post({
                            url: centralserver + "/updateaddress",
                            body: {
                                username: myprofile.username,
                                command: myprofile.signingkey.encryptPrivate(JSON.stringify({
                                    command: "updateaddress",
                                    address: getIP() + ":" + app.get('port'),
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
                                res.send(body);
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
        if (myprofile.username) {
            request.post({
                url: centralserver + "/addidentity",
                body: {
                    username: myprofile.username,
                    command: myprofile.signingkey.encryptPrivate(JSON.stringify({
                        command: "addidentity",
                        identityname: req.body.identityname,
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
                    sqlite.insert("MYIDENTITIES", {
                        identityname: req.body.identityname
                    }, (resp) => {
                        if (resp.error)
                            throw res.error;
                        else
                            res.send({
                                "status": "success"
                            });
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
        if (myprofile.username) {
            request.post({
                url: centralserver + "/deleteidentity",
                body: {
                    username: myprofile.username,
                    command: myprofile.signingkey.encryptPrivate(JSON.stringify({
                        command: "deleteidentity",
                        identityname: req.body.identityname,
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
                    sqlite.run("DELETE FROM MYIDENTITIES WHERE identityname = ?", [req.body.identityname], (resp) => {
                        if (res.error) {
                            console.error(resp.error)
                        } else {
                            if (myprofile.identities.indexOf(req.body.identityname) > -1) {
                                myprofile.identities.splice(myprofile.identities.indexOf(req.body.identityname), 1);
                            }
                            res.send({
                                "status": "success"
                            });
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