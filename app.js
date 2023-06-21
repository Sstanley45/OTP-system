require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const client = require("twilio")(accountSid, authToken);

const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;

const smsKey = process.env.SMS_SECRET_KEY;

const app = express();
port = process.env.PORT || 5000;

app.use(express.json());

//routes
app.post("/sendOTP", (req, res) => {
  const phone = req.body.phone;
  const otp = Math.floor(100000 + Math.random() * 900000);
  const ttl = 2 * 60 * 1000;
  const expires = Date.now() + ttl;
  const data = `${phone}.${otp}.${expires}`;
  const hash = crypto.createHmac("sha256", smsKey).update(data).digest("hex");
  const fullHash = `${hash}.${expires}`;

  client.messages
    .create({
      body: `your OTP password is ${otp}`,
      from: +14157499280,
      to: phone,
    })
    .then((messages) => console.log(messages))
    .catch((err) => console.log("twilio error",err));
  res.status(200).json({ msg: 'success', phone , hash: fullHash, otp });
});

app.post("/verifyOTP", (req, res) => {
  const phone = req.body.phone;
  const hash = req.body.hash;
  const otp = req.body.otp;
  let [hashValue, expires] = hash.split(".");
  let now = Date.now();
  if (now > parseInt(expires)) {
    return res.status(540).json({ msg: "time out! please try again" });
  }

  const data = `${phone}.${otp}.${expires}`;
  const newCalculatedHash = crypto
    .createHmac("sha256", smsKey)
    .update(data)
    .digest("hex")
  if (newCalculatedHash === hashValue) {
    const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
      expiresIn: "30d",
    });
    return res.status(202).json({ msg: "device verified", token: accessToken });
  } else {
    return res.status(400).json({ verification: false, msg: "incorrect OTP" });
  }
});

//authenticaterMiddleware
const authMiddleware = async (req, res, next) => {
   const authHeader = req.headers.authorization;

   if (!authHeader || !authHeader.startsWith("Bearer ")) {
     console.log("authHeader not present");
     res.status(401).json({ success: false, msg: "not authorized" });
   }
    const token = authHeader.split(" ")[1];
  
    try {
      const decoded = jwt.verify(token, JWT_AUTH_TOKEN);
      const phone = decoded.data
      req.phone = phone
      next()
    } catch (error) {
      console.error(error);
    }
  
};


//protected route
app.get('/dashboard', authMiddleware,(req, res) => {
  console.log(req.phone)
  let luckyNumber = Math.floor(Math.random() * 100)
  res.status(200).send(`hello joe, welcome to the dashboard! your lucky number is ${luckyNumber}`)
})

app.get('/api/v1', (req, res) => {
  res.json({msg : "Welcome"})
})

app.listen(port, () => {
  console.log(`listening on port ${port}...`);
});