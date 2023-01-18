var https = require('https');
var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var saml = require('passport-saml');
var fs = require('fs');

//declare constants
const PORT = 5014;


/** SAML Configurations attributes
 * callbackurl : apps url for IDP to response post authetication
 * signout: apps url for IDP to notify app post signout
 * entrypoint: IDP url to redirect for authentication
 * entityId : Apps Id
 */
const samlConfig = {
    issuer: "w3id-auth-client",
    entityId: "https://sgar.sg.ibm.com:8443/auth/realms/keycloak-w3id-auth",
    callbackUrl: "https://point.sg.ibm.com:5014/login/callback",
    signOut: "https://point.sg.ibm.com:5014/signout/callback",
    entryPoint: "https://9.178.216.221:8443/auth/admin/keycloak-w3id-auth/console/",
};

// For running apps on https mode
// load the public certificate
const sp_pub_cert = fs.readFileSync('sp-pub-cert.pem', 'utf8');

//load the private key
const sp_pvk_key = fs.readFileSync('sp-pvt-key.pem', 'utf8');

//Idp's certificate from metadata
const idp_cert = fs.readFileSync('idp-pub-key.pem', 'utf8');

passport.serializeUser(function (user, done) {
    //Serialize user, console.log if needed
    console.log(user);
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    //Deserialize user, console.log if needed
    console.log(user);
    done(null, user);
});

// configure SAML strategy for SSO
const samlStrategy = new saml.Strategy({
    callbackUrl: samlConfig.callbackUrl,
    entryPoint: samlConfig.entryPoint,
    issuer: samlConfig.issuer,
    identifierFormat: null,
    decryptionPvk: sp_pvk_key,
    cert: [idp_cert, idp_cert],
    privateCert: fs.readFileSync('sp-pvt-key.pem', 'utf8'),
    validateInResponseTo: true,
    disableRequestedAuthnContext: true,
}, (profile, done) => {
    console.log('passport.use() profile: %s \n', JSON.stringify(profile));
    return done(null, profile);
});

//initialize the express middleware
const app = express();
app.use(cookieParser());

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

app.set('view engine', 'ejs');
app.set('views', require('path').join(__dirname, '/view'));

// Configure session management
// Note: Always configure session before passport initialization & passport session, else error will be encounter
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
}));

passport.use('samlStrategy', samlStrategy);
app.use(passport.initialize({}));
app.use(passport.session({}));

/** Configure routes **/
// default route
// app.get('/',
//     (req, res) => {
//         res.send('Weclome to Single Sign-On Application');
//     }
// );
app.get('/', (req, res) => res.redirect('/welcome'));

app.get('/welcome', (req, res, next) => {
    console.log(`${new Date().toISOString()} [KEYCLOAK WELCOME] Welcome page`);
        
    res.render('welcome');
});

// login route
app.get('/login', (req, res, next) => {
        console.log(`${new Date().toISOString()} [KEYCLOAK LOGIN] Login Handler starts..`);
        next();
    },
    passport.authenticate('samlStrategy')
);

// home route
app.get('/home', (req, res, next) => {
        console.log(`${new Date().toISOString()} [KEYCLOAK HOME] Home Handler starts..`);
        next();
    },
    passport.authenticate('samlStrategy'),
    (req, res) => {

        //SSO response payload
        console.log(`${new Date().toISOString()} [KEYCLOAK] SSO login callback response payload: ${req.user.attributes}`);
        res.send(req.user.attributes);
    }
);

// post login callback route
app.post('/login/callback',
    (req, res, next) => {

        //login callback starts
        console.log("login callback starts..");
        next();
    },
    passport.authenticate('samlStrategy'),
    (req, res) => {

        //SSO response payload
        console.log(`${new Date().toISOString()} [KEYCLOAK] SSO login callback response payload: ${req.user.attributes}`);
        res.send(req.user.attributes);
    }
);

//Run the https server
const server = https.createServer({
    'key': sp_pvk_key,
    'cert': sp_pub_cert
}, app).listen(PORT, () => {
    console.log('Listening on https://localhost:%d', server.address().port)
});