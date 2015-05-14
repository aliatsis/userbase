module.exports = {
    port: process.env.PORT || 8080,
    basePath: '/api',
    userPath: '/user',
    routes: {
        login: '/login',
        logout: '/logout',
        signup: '/signup'
    },
    usernameProperty: 'username',
    passwordProperty: 'password',
    loginAttemptLimit: 5,
    loginAttemptLockDuration: 15, // minutes
    pbkdf2Iterations: 25000,
    pbkdf2KeyLength: 512,
    saltLength: 32,
    encoding: 'hex',
    tokenExpiresInSeconds: 0, // fall through to minutes
    tokenExpiresInMinutes: 30,
    secretOrKey: 'secret'
};