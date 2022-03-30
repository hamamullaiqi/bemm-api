const express = require('express')

const router = express.Router()

const { register, login, loginGoogle } = require("../controllers/auth")


//auth 
router.post("/register", register)
router.post("/login", login)
router.post("/login-google", loginGoogle)

module.exports = router

