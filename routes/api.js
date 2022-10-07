const express = require("express");
const router = express.Router();

// pool 객체와 promisePool 객체를 각각 생성
const mysql = require("../modules/mysql_pool");
const pool = mysql.pool;
const promisePool = mysql.pool.promise();

// JWT 모듈
const { TokenType, makeJWT, isExpiredAccessToken, isExpiredRefreshToken } = require("../modules/jwt");
const res = require("express/lib/response");

// Access 토큰 검증 미들웨어
const auth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const accessToken = authHeader && authHeader.split(" ")[1];

  console.log("accessToken: ", accessToken);

  if (!accessToken) {
    console.log("wrong access token");
    return res.sendStatus(400);
  }

  isExpiredAccessToken(accessToken, (isExpired, userId) => {
    if (isExpired) {
      console.log("access token is expired");
      return res.json({
        isAccessTokenExpired: true,
      });
    }

    next();
  });
};

// 아이디 중복 체크
router.post("/isDuplicateId", async (req, res) => {
  const { userId } = req.body;

  const sql = "SELECT id FROM user WHERE user_id = ?";
  const param = [userId];

  const [result] = await promisePool.query(sql, param);

  let isDuplicateId = true;

  if (result.length) {
    isDuplicateId = true;
  } else {
    isDuplicateId = false;
  }

  res.json({
    isDuplicateId: isDuplicateId,
  });
});

// 회원가입
router.post("/signUp", (req, res) => {
  const { userId, userPw, userName } = req.body;

  const sql = "INSERT INTO user (user_id, user_pw, user_name) VALUES (?, ?, ?);";
  const param = [userId, userPw, userName];

  pool.query(sql, param, (err, result) => {
    if (err) {
      console.log(err);
      res.json({
        isSignUpSuccess: false,
      });
    } else {
      res.json({
        isSignUpSuccess: true,
      });
    }
  });
});

// 로그인
router.post("/login", async (req, res) => {
  const { userId, userPw } = req.body;

  const selectSQL = "SELECT user_id, user_name FROM user WHERE user_id = ? and user_pw = ?";
  const selectParams = [userId, userPw];

  const [result] = await promisePool.query(selectSQL, selectParams);
  const raw = result[0];

  if (!raw) {
    console.log("wrong login info");
    return res.sendStatus(500);
  }

  // JWT 발행
  const accessToken = makeJWT(raw.user_id, TokenType.Access);
  const refreshToken = makeJWT(raw.user_id, TokenType.Refresh);

  // refresh 토큰 db에 저장
  const updateSQL = "UPDATE user SET refresh_token = ? WHERE id = ?";
  const updateParams = [refreshToken, raw.user_id];

  await promisePool.query(updateSQL, updateParams);

  res.json({
    accessToken: accessToken,
    refreshToken: refreshToken,
  });
});

router.post("/refreshAccessToken", async (req, res) => {
  const { refreshToken } = req.body;

  const sql = "SELECT user_id FROM user WHERE refresh_token = ?";
  const params = [refreshToken];
  const [result] = await promisePool.query(sql, params);
  const raw = result[0];

  if (!raw) {
    console.log("wrong refresh toekn");
    return res.sendStatus(400);
  }

  isExpiredRefreshToken(refreshToken, (isRefreshTokenExpired, userId) => {
    if (isRefreshTokenExpired == false) {
      // 새로운 access token 발급
      const newAccessToken = makeJWT(userId, TokenType.Access);
      return res.json({
        isRefreshTokenExpired: isRefreshTokenExpired,
        accessToken: newAccessToken,
      });
    }
    res.json({
      isRefreshTokenExpired: isRefreshTokenExpired,
      accessToken: null,
    });
  });
});

router.post("/chatRooms", auth, async (req, res) => {
  const { userId } = req.body;

  const sql = `SELECT chat_room_member.room_id, chat_room.room_name
  FROM user
	  JOIN chat_room_member ON user.id = chat_room_member.user_id AND user.id = ?
    JOIN chat_room ON user.id = chat_room.creator_id
  `;
  const params = [userId];
  const [result] = await promisePool.query(sql, params);

  if (result.length) {
    res.json({
      chatRooms: result,
    });
  } else {
    res.json({
      chatRooms: [],
    });
  }
});

module.exports = router;
