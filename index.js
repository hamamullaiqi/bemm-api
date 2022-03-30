require('dotenv').config()
const express = require("express")
const cors = require("cors")


const router = require("./src/routes")


const app = express()

const port = process.env.PORT || 4000


app.use(express.json())
app.use(cors())



//router api
app.use("/api/v1/", router)

//router serving static file
// app.use('/uploads', express.static('uploads'))



app.listen(port, ()=> console.log(`Api Listener on port ${port}! `))