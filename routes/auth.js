const express                                           = require('express');
const passport                                          = require('passport');
const bcrypt                                            = require('bcrypt');
const { isLoggedIn, isNotLoggedIn }                     = require('./middlewares');
const User                                              = require('../models/user');

const router                                            = express.Router();

// 회원가입
router.post('/join', isNotLoggedIn, async (req, res, next) => {
    const { email, nick, password }                     = req.body;

    // 가입처리
    try {
        // 기존 가입유무 체크
        const exUser                                    = await User.findOne({ where: {email} });

        if(exUser) return res.redirect('/join?error=exist');

        const hash                                      = await bcrypt.hash(password, 12);
        await User.create({
            email,
            nick,
            password: hash
        });

        return res.redirect('/');
    } catch (err) {
        console.error(err);
        return next(err);
    }
});

// 로그인 처리
router.post('/login', isNotLoggedIn, (req, res, next) => {
    passport.authenticate('local', (authError, user, info) => {
        if(authError){
            console.error(authError);
            return next(authError);
        }

        if(!user) {
            return res.redirect(`/?loginError=${info.message}`);
        }

        return req.login(user, (loginError) => {
            if(loginError) {
                console.error(loginError);
                return next(loginError);
            }

            return res.redirect('/');
        });
    })(req, res, next); // 미들웨어 내의 미들웨어에는 (req, res, next)를 붙여주도록 한다.
});

// 로그아웃
router.get('/logout', isLoggedIn, (req, res, next) => {
    req.logout();
    req.session.destroy();
    res.redirect('/');
});

// 카카오
router.get('/kakao', passport.authenticate('kakao'));
router.get('/kakao/callback', passport.authenticate('kakao', {
    failureRedirect                                     : '/'
}), (req, res) => {
    res.redirect('/');
});

module.exports                                          = router;