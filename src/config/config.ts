export default () => ({
    jwt: {
        secret: process.env.JWT_SECRET,
    },
    firebase: {
        serviceAccountPath: process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './signly-be33f-firebase-adminsdk-fbsvc-cd21369526.json',
        databaseURL: process.env.FIREBASE_DATABASE_URL,
    },
});
