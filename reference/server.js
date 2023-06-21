require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const client = require("twilio")(accountSid, authToken);

const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
let refreshTokens = [];

const smsKey = process.env.SMS_SECRET_KEY;

const app = express();

port = process.env.PORT || 4000;

app.use(express.json());
app.use(cookieParser());

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
    .catch((err) => console.log(err));
  res.status(200).send({ phone, hash: fullHash, otp });
});

app.post("/verifyOTP", (req, res) => {
  const phone = req.body.phone;
  const hash = req.body.hash;
  const otp = req.body.otp;
  let [hashValue, expires] = hash.split(".");
  let now = Date.now();
  if (now > parseInt(expires)) {
    return res.status(504).json({ msg: "time out! please try again" });
  }

  const data = `${phone}.${otp}.${expires}`;

  const newCalculatedHash = crypto
    .createHmac("sha256", smsKey)
    .update(data)
    .digest("hex");

  if (newCalculatedHash === hashValue) {
    refreshTokens.push(refreshToken);
    const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
      expiresIn: "30s",
    });
    const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, {
      expiresIn: "1y",
    });
    return res
      .status(202)

      .cookie("accessToken", accessToken, {
        expires: new Date(new Date().getTime() + 30 * 1000),
        sameSite: "strict",
        httpOnly: true,
      })
      .cookie("authSession", true, {
        expires: new Date(new Date().getTime() + 30 * 1000),
      })
      .cookie("refreshToken", refreshToken, {
        expires: new Date(new Date().getTime() + 35576),
        sameSite: "strict",
        httpOnly: true,
      })
      .cookie("refreshTokenID", true, {
        expires: new Date(new Date().getTime() + 35576),
      })

      .json({ msg: "device verified" });
  } else {
    return res.status(400).send({ verification: false, msg: "Incorrect OTP" });
  }
});

//middleware
async function authenticateUser(req, res, next) {
  const accessToken = req.cookies.accessToken;
  jwt.verify(accessToken, JWT_AUTH_TOKEN, async (err, phone) => {
    if (phone) {
      req.phone = phone;
      next();
    } else if (err.message === "TokenExpiredError") {
      return res
        .status(403)
        .json({ success: false, msg: "access token expired!" });
    } else {
      console.error(err);
      res.status(403).json({ err, msg: "user not authenticated" });
    }
  });
}

app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken)
    return res
      .status(404)
      .json({ msg: " refresh token not found, please login again" });
  if (!refreshTokens.includes(refreshToken))
    return res.status(403).json({ msg: "refresh token blocked!" });
  jwt.verify(refreshToken, JWT_REFRESH_TOKEN, (err, phone) => {
    if (!err) {
      const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
        expiresIn: "30S",
      });
      res
        .status(202)

        .cookie("accessToken", accessToken, {
          expires: new Date(new Date().getTime() + 30 * 1000),
          sameSite: "strict",
          httpOnly: true,
        })
        .cookie("authSession", true, {
          expires: new Date(new Date().getTime() + 30 * 1000),
        })
        .json({ previousSessionExpiry: true, success: true });
    } else {
      return res
        .status(403)
        .json({ success: false, msg: "Invalid refresh token" });
    }
  });
});

app.get("/logout", (req, res) => {
  res
    .clearCookie("refreshToken")
    .clearCookie("accessToken")
    .clearCookie("authSession")
    .clearCookie("refreshTokenID")
    .json({ msg: "user logout" });
});

app.listen(port, () => {
  console.log(`listening on port ${port}..`);
});
