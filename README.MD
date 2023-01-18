# Getting Started with Keycloak Nodejs w3id Auth
## Keycloak Nodejs w3id Auth
## Single SingleOn (SSO): Service Provide (SP) Client
![version-badge](https://img.shields.io/badge/version-1.0.0-blue.svg)

## Getting Started
## Pre-requsites
Ensure below tools are installed in your environment as those are mandatory to run the client app. 
- Node.js® is an open-source, cross-platform JavaScript runtime environment.
  - [Nodejs Official Page](https://nodejs.org/en/)
- OpenSSL robust, commercial-grade, full-featured toolkit for general-purpose cryptography and secure communication.
  - [OpenSSL Official Page](https://www.openssl.org/)
  - Generate Self-Sign SSL Certificate.
    - ```openssl req -newkey rsa:2048 -nodes -keyout {private_key_name}.key.pem -x509 -days 3650 -out {public_cert_name}.cert.pem```
- Keycloak open source identity and access management.
  - [Keycloak Official Page](https://www.keycloak.org/)
  - Configured keycloak realm.
- Docker container deployment (if needed).
  - [Docker Official Page](https://www.docker.com/get-started/)

## For Local Development:
### Terminal Commands
1. Open a Console Terminal.
3. Navigate to the project folder.
4. Install app denpendency prep: $ ```npm install```
5. Run the app in the development mode: $ ```npm start```
6. Open Chrome web browser with url: [https://localhost:5014/](https://localhost:5014/)
7. App fires up as-is

### Option: Container Deployment
1. Open a Console Terminal
2. Build Docker Image
    - ```docker build -t ImageName:TagName dir```
3. Run in Container
    - ```docker run --name <name-of-container> -p <hostport>:<containerport> -d <image-name>```


### Configurations

Navigate to sp-pub-cert.pem and replace the string from newly generate {public_cert_name}.cert.pem and sp-pvt-key.pem string  with {private_key_name}.key.pem

Navigate to App.js and update the configures as per IDP provider using
```
/** SAML Configurations attributes 
* callbackurl : apps url for IDP to response post authentication 
* signout: apps url for IDP to notify app post sign out 
* entrypoint: IDP url to redirect for authentication 
* entityId : Apps Id 
*/ 
const samlConfig = {
  issuer: "Client-ID", 
  entityId: "realm name/entity name", 
  callbackUrl: "https://{IP-Address}:{PORT}/login/callback", 
  signOut: "https://{IP-Address}:{PORT}/signout/callback", 
  entryPoint: "{saml 2.0 login Url}"
};
```


- Go the browser and navigate to home page : https://localhost:5014/
- Navigate to login page: https://localhost:5014/login app will redirect to IDP for login process and post login it will redirect to call back url with SAML assertion token with claims container user details

## License
[MIT](https://choosealicense.com/licenses/mit/)
