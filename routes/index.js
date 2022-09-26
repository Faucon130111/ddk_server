const express = require("express");
const router = express.Router();

// pool 객체와 promisePool 객체를 각각 생성
const mysql = require("../modules/mysql_pool");
const pool = mysql.pool;
const promisePool = mysql.pool.promise();

// JWT 모듈
const { TokenType, makeJWT, verify } = require("../modules/jwt");

const { response } = require("express");
const app = express();

router.get("/api/:id", (req, res) => {
  const id = req.params.id;
  console.log("id: ", id);
  res.json(id);
});

// 회원가입
router.post("/signUp", (req, res) => {
  const { id, pw, name } = req.body;

  const sql = "insert into user (id, pw, name) values (?, ?, ?);";
  const param = [id, pw, name];

  pool.query(sql, param, (err, result) => {
    if (err) {
      res.json({
        isSuccess: false,
      });
    } else {
      res.json({
        isSuccess: true,
      });
    }
  });
});

/* 스터디용 promisePool
router.post("/signUp2", async (req, res) => {
  const { id, pw, name } = req.body;

  const sql = "insert into user (id, pw, name) values (?, ?, ?);";
  const param = [id, pw, name];

  // promisePool은 promise 객체로 await 가 들어가야한다,
  // 물론 await 활용하려면 라우터 자체도 async 되어야

  // 굳이굳이 에러를 찍어보고싶다면 catch문으로
  const [result] = await promisePool.query(sql, param).catch((e) => {
    console.log(e);
  });

  // 보통 내 활용법
  const [result2] = await promisePool.query(sql, param);
  if (result2.length) {
    res.json(1);
  }
});
*/

// 로그인
router.post("/login", async (req, res) => {
  const { id, pw } = req.body;

  const selectSQL = "SELECT id, name FROM user WHERE id = ? and pw = ?";
  const selectParams = [id, pw];

  const [result] = await promisePool.query(selectSQL, selectParams);
  const raw = result[0];

  if (!raw) {
    console.log("wrong login info");
    return res.sendStatus(500);
  }

  // JWT 발행
  const accessToken = makeJWT(raw.id, TokenType.Access);
  const refreshToken = makeJWT(raw.id, TokenType.Refresh);

  // refresh 토큰 db에 저장
  const updateSQL = "UPDATE user SET refresh_token = ? WHERE id = ?";
  const updateParams = [refreshToken, raw.id];

  await promisePool.query(updateSQL, updateParams);

  res.json({
    accessToken: accessToken,
    refreshToken: refreshToken,
  });
});

router.post("/refreshAccessToken", async (req, res) => {
  const { refreshToken } = req.body;

  const sql = "SELECT id FROM user WHERE refresh_token = ?";
  const params = [refreshToken];
  const [result] = await promisePool.query(sql, params);
  const raw = result[0];

  if (!raw) {
    console.log("wrong refresh toekn");
    return res.sendStatus(400);
  }

  verify(refreshToken, (isRefreshTokenExpired, id) => {
    if (isRefreshTokenExpired == false) {
      // 새로운 access token 발급
      const newAccessToken = makeJWT(id, TokenType.Access);
      return res.json({
        isRefreshTokenExpired: isRefreshTokenExpired,
        accessToken: newAccessToken,
      });
    }
    res.json({
      isRefreshTokenExpired: isRefreshTokenExpired,
    });
  });
});

// router.post("/test", (req, res) => {
//   const authHeader = req.headers["authorization"];
//   const accessToken = authHeader && authHeader.split(" ")[1];

//   if (!accessToken) {
//     console.log("wrong access token");
//     return res.sendStatus(400);
//   }

//   jwtModule.jwt.verify(accessToken, accessTokenKey, (error, playload) => {
//     if (error) {
//       console.log("access token verify error: ", error);
//       // return res.sendStatus(403);
//       return res.json({
//         isTokenExpired: true,
//       });
//     }

//     res.json(playload);
//   });
// });

module.exports = router;
