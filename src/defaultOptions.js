module.exports = {
    port: process.env.PORT || 8080,
    basePath: '/api',
    userPath: '/user',
    routes: {
        login: '/login',
        logout: '/logout',
        signup: '/signup',
        profile: '/profile',
        forgotPassword: '/forgotPassword',
        resetPassword: '/resetPassword'
    },
    usernameProperty: 'username',
    passwordProperty: 'password',
    emailProperty: 'email',
    loginAttemptLimit: 5,
    loginAttemptLockDuration: 15, // minutes
    pbkdf2Iterations: 25000,
    pbkdf2KeyLength: 512,
    pbkdf2Algorithm: 'sha512',
    saltLength: 32,
    encoding: 'hex',
    tokenExpiresInSeconds: 0, // fall through to minutes
    tokenExpiresInMinutes: 30,
    resetPasswordTokenLength: 32,
    resetPasswordExpiration: 15, // minutes
    secretOrKey: 'secret'
};