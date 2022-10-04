const jwt = require("jsonwebtoken");

const accessTokenKey = "75fe74bb4fa6b66379826a77ab8b5bb3e0f0220c2b578653d33da35d8b832745";
const refreshTokenKey = "629d6fedbce42614ce80139bb6f059ff341bc07f03460b908ee5c4ddfed95740";

const TokenType = Object.freeze({
  Access: Symbol(0),
  Refresh: Symbol(1),
});

const makeJWT = (id, type) => {
  const playload = {
    userId: id,
  };

  let key = "";
  let expiresIn = "";

  switch (type) {
    case TokenType.Access:
      key = accessTokenKey;
      expiresIn = "1m";
      break;

    case TokenType.Refresh:
      key = refreshTokenKey;
      expiresIn = "30 days";
      break;
  }

  return jwt.sign(playload, key, {
    expiresIn: expiresIn,
  });
};

const isExpiredAccessToken = (accessToken, callback) => {
  jwt.verify(accessToken, accessTokenKey, (error, playload) => {
    if (error) {
      console.log("access token verify error: ", error);
      return callback(true);
    }

    callback(false, playload.id);
  });
};

const isExpiredRefreshToken = (refreshToken, callback) => {
  jwt.verify(refreshToken, refreshTokenKey, (error, playload) => {
    if (error) {
      console.log("refresh token verify error: ", error);
      return callback(true);
    }

    callback(false, playload.id);
  });
};

module.exports = {
  TokenType,
  makeJWT,
  isExpiredAccessToken,
  isExpiredRefreshToken,
};
