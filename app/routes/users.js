'use strict';

// User routes use users controller
var users = require('../controllers/users');

module.exports = function(app, passport) {
    var authCallBack = function(req, res, next, err, user, info){
        if (err) { return next(err); }
        if (!user){
            if(info && info.message){
                req.flash('error', info.message);
            }
            return res.redirect('/signin');
        }
        return req.logIn(user, function(err) {
            if (err) { return next(err); }
            return res.redirect('/');
        });
    };
    app.get('/signin', users.signin);
    app.get('/signup', users.signup);
    app.get('/signout', users.signout);
    app.get('/users/me', users.me);

    // Setting up the users api
    app.post('/users', users.create);

    // Setting up the userId param
    app.param('userId', users.user);

    // Setting the local strategy route
    app.post('/users/session', passport.authenticate('local', {
        failureRedirect: '/signin',
        failureFlash: true
    }), users.session);

    // Setting the facebook oauth routes
    app.get('/auth/facebook', passport.authenticate('facebook', {
        scope: ['email', 'user_about_me'],
        failureRedirect: '/signin'
    }), users.signin);

    app.get('/auth/facebook/callback', function(req, res, next) {
        passport.authenticate('facebook', function(err, user, info) {
            return authCallBack(req, res, next,err, user, info);
        })(req, res, next);
    });

    // Setting the github oauth routes
    app.get('/auth/github', passport.authenticate('github', {
        failureRedirect: '/signin'
    }), users.signin);

    app.get('/auth/github/callback', function(req, res, next) {
        passport.authenticate('github', function(err, user, info) {
            return authCallBack(req, res, next,err, user, info);
        })(req, res, next);
    });

    // Setting the twitter oauth routes
    app.get('/auth/twitter', passport.authenticate('twitter', {
        failureRedirect: '/signin'
    }), users.signin);

    app.get('/auth/twitter/callback', function(req, res, next) {
        passport.authenticate('twitter', function(err, user, info) {
            return authCallBack(req, res, next,err, user, info);
        })(req, res, next);
    });

    // Setting the google oauth routes
    app.get('/auth/google', passport.authenticate('google', {
        failureRedirect: '/signin',
        scope: [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        ]
    }), users.signin);
    app.get('/auth/google/callback', function(req, res, next) {
        passport.authenticate('google', function(err, user, info) {
            return authCallBack(req, res, next,err, user, info);
        })(req, res, next);
    });

    // Setting the linkedin oauth routes
    app.get('/auth/linkedin', passport.authenticate('linkedin', {
        failureRedirect: '/signin',
        scope: [ 'r_emailaddress' ]
    }), users.signin);
    app.get('/auth/linkedin/callback', function(req, res, next) {
        passport.authenticate('linkedin', function(err, user, info) {
            return authCallBack(req, res, next,err, user, info);
        })(req, res, next);
    });

};
