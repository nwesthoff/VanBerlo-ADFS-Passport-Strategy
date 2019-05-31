import OAuth2 from "passport-oauth2";
import { decode } from "jsonwebtoken";
import md5 from "md5";

class ADFSAuthStrategy extends OAuth2 {
  userProfile = function(accessToken: string, done: Function) {
    const decoded = decode(accessToken);

    return done(null, {
      name: decoded.unique_name,
      email: decoded.email,
      id: md5(decoded.email)
    });
  };

  authorizationParams = function(options) {
    return {
      resource: options.resource
    };
  };
}

export default ADFSAuthStrategy;
