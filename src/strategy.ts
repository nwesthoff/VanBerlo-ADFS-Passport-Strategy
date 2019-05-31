import OAuth2 from "passport-oauth2";
import { decode } from "jsonwebtoken";
import md5 from "md5";

interface ADFSAuthStrategyOptions {
  resource: string;
}

interface Decoded {
  unique_name: string;
  email: string;
}

class ADFSAuthStrategy extends OAuth2 {
  name = "ADFSAuthStrategy";

  userProfile = function(accessToken: string, done: Function) {
    const decoded = decode(accessToken) as Decoded;

    return done(null, {
      name: decoded.unique_name,
      email: decoded.email,
      id: md5(decoded.email)
    });
  };

  authorizationParams = function(options: ADFSAuthStrategyOptions) {
    return {
      resource: options.resource
    };
  };
}

export default ADFSAuthStrategy;
